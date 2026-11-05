//! Pure Teller bank matching laws and canonical source/decision values.
//!
//! The journal and register facade share this layer so native confirmation
//! reproduces the same exact pinned fallback without depending on projections.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{DecodeError, EncodeError, EntryRef, Oid, Reader, Writer, domain_digest};
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb_types::VId;

use crate::{
    BenefitInterval, DecisionCandidate, DecisionCard, DecisionFeature, DecisionReplayError,
    amounts_preserved, decide_bank_match,
};

pub const BANK_LINE_DOC_DOMAIN: &[u8] = b"fa:bank-line-doc:v1";
pub const RECON_MATCH_DOMAIN: &[u8] = b"fa:reconciliation-match:v1";

/// Errors returned by the Teller reconciliation engine and verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconciliationError {
    InvalidField(&'static str),
    /// An exact quantity, amount, or decision feature exceeded `i128`.
    Overflow(&'static str),
    UnitMismatch {
        expected: UnitId,
        actual: UnitId,
    },
    /// A match or decision card attempted to alter a committed amount.
    AmountModified {
        // Keep the uncommon diagnostic from enlarging every matching Result.
        entry_ref: Box<EntryRef>,
        committed: Amount,
        proposed: Amount,
    },
    /// A decision card failed fallback validation or bit-for-bit replay.
    InvalidDecisionCard(DecisionReplayError),
    /// A match has a non-zero difference between bank lines and book entries
    /// that is not explained by a committed residual entry under a named law.
    UnexplainedResidual {
        bank_net_mantissa: i128,
        book_net_mantissa: i128,
        unexplained_delta: i128,
    },
    /// A residual entry was cited without naming a registered residual law.
    MissingResidualLaw,
    /// Posting on or before `reconciled_through` requires `Op::Reconcile`.
    ReconciledPeriodLocked {
        effective_date: DateDay,
        reconciled_through: DateDay,
    },
    /// `verify_reconciliation_register` detected an out-of-balance register or unposted residual.
    VerificationFailed(String),
    Encode(EncodeError),
    Decode(DecodeError),
}

impl core::fmt::Display for ReconciliationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid reconciliation field: {field}"),
            Self::Overflow(operation) => {
                write!(f, "reconciliation arithmetic overflow: {operation}")
            }
            Self::UnitMismatch { expected, actual } => {
                write!(
                    f,
                    "reconciliation unit mismatch: expected unit {}, got {}",
                    expected.0, actual.0
                )
            }
            Self::AmountModified {
                entry_ref,
                committed,
                proposed,
            } => write!(
                f,
                "match attempted to alter committed amount on entry {:032x}: committed {}, proposed {}",
                entry_ref.vid.0, committed.mantissa, proposed.mantissa
            ),
            Self::InvalidDecisionCard(e) => write!(f, "invalid decision card: {e}"),
            Self::UnexplainedResidual {
                bank_net_mantissa,
                book_net_mantissa,
                unexplained_delta,
            } => write!(
                f,
                "unexplained reconciliation residual: bank net {bank_net_mantissa} != book net {book_net_mantissa} (delta {unexplained_delta}); post a fee or FX entry under a named law first"
            ),
            Self::MissingResidualLaw => {
                write!(f, "residual entry must name a registered residual law")
            }
            Self::ReconciledPeriodLocked {
                effective_date,
                reconciled_through,
            } => write!(
                f,
                "effective date {effective_date} is on or before reconciled_through {reconciled_through}; `reconcile` capability is required"
            ),
            Self::VerificationFailed(why) => write!(f, "reconciliation verification failed: {why}"),
            Self::Encode(e) => write!(f, "{e}"),
            Self::Decode(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for ReconciliationError {}

impl From<EncodeError> for ReconciliationError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

impl From<DecodeError> for ReconciliationError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<DecisionReplayError> for ReconciliationError {
    fn from(e: DecisionReplayError) -> Self {
        Self::InvalidDecisionCard(e)
    }
}

/// Content-addressed `BankLine` document derived from an imported bank statement
/// (`DERIVED_FROM` `statement_oid`, plan §9.5, §15.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankStatementLine {
    pub statement_oid: Oid,
    pub statement_seq: u64,
    pub line_ordinal: u32,
    pub booking_date: DateDay,
    pub value_date: DateDay,
    /// On a bank statement: `Side::Credit` (`CRDT`) is a cash deposit/inflow (`+`),
    /// `Side::Debit` (`DBIT`) is a cash withdrawal/outflow (`-`).
    pub side: Side,
    pub amount: Amount,
    pub counterparty: String,
    pub reference: String,
}

impl BankStatementLine {
    /// Signed cash delta from the bank account's perspective (`+` inflow, `-` outflow).
    #[must_use]
    pub const fn signed_cash_delta(&self) -> i128 {
        match self.side {
            Side::Credit => self.amount.mantissa,
            Side::Debit => -self.amount.mantissa,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReconciliationError> {
        if self.amount.mantissa <= 0 {
            return Err(ReconciliationError::InvalidField("amount.mantissa"));
        }
        let mut w = Writer::with_capacity(160);
        w.bytes(BANK_LINE_DOC_DOMAIN)
            .fixed(&self.statement_oid.0)
            .u64(self.statement_seq)
            .u32(self.line_ordinal)
            .i32(self.booking_date.0)
            .i32(self.value_date.0)
            .u8(self.side as u8)
            .u32(self.amount.unit.0)
            .i128(self.amount.mantissa)
            .str(&self.counterparty)
            .str(&self.reference);
        Ok(w.finish()?)
    }

    pub fn oid(&self) -> Result<Oid, ReconciliationError> {
        let bytes = self.canonical_bytes()?;
        Ok(Oid(domain_digest(BANK_LINE_DOC_DOMAIN, &[&bytes])))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ReconciliationError> {
        let mut r = Reader::new(bytes);
        if r.bytes(64, "bank_line.domain")? != BANK_LINE_DOC_DOMAIN {
            return Err(ReconciliationError::Decode(r.invalid("bank_line.domain")));
        }
        let statement_oid = Oid(r.fixed("bank_line.statement_oid")?);
        let statement_seq = r.u64("bank_line.statement_seq")?;
        let line_ordinal = r.u32("bank_line.line_ordinal")?;
        let booking_date = DateDay(r.i32("bank_line.booking_date")?);
        let value_date = DateDay(r.i32("bank_line.value_date")?);
        let side = match r.u8("bank_line.side")? {
            0 => Side::Debit,
            1 => Side::Credit,
            _ => return Err(ReconciliationError::Decode(r.invalid("bank_line.side"))),
        };
        let unit = UnitId(r.u32("bank_line.unit")?);
        let mantissa = r.i128("bank_line.mantissa")?;
        let counterparty = r.str(512, "bank_line.counterparty")?.to_string();
        let reference = r.str(512, "bank_line.reference")?.to_string();
        r.finish()?;
        let line = Self {
            statement_oid,
            statement_seq,
            line_ordinal,
            booking_date,
            value_date,
            side,
            amount: Amount::new(unit, mantissa),
            counterparty,
            reference,
        };
        if line.amount.mantissa <= 0 {
            return Err(ReconciliationError::InvalidField("amount.mantissa"));
        }
        Ok(line)
    }
}

/// Candidate book entry leg on the bank's GL cash account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookCandidateEntry {
    pub entry_ref: EntryRef,
    pub entry_ordinal: u64,
    pub effective_date: DateDay,
    /// On an asset Cash account in the book: `Side::Debit` is a cash inflow (`+`),
    /// `Side::Credit` is a cash outflow (`-`).
    pub side: Side,
    pub amount: Amount,
    pub counterparty: String,
    pub reference: String,
}

impl BookCandidateEntry {
    /// Signed cash delta on the asset Cash account (`+` Debit inflow, `-` Credit outflow).
    #[must_use]
    pub const fn signed_cash_delta(&self) -> i128 {
        match self.side {
            Side::Debit => self.amount.mantissa,
            Side::Credit => -self.amount.mantissa,
        }
    }
}

/// Normalize a counterparty name by lowercasing ASCII, stripping punctuation,
/// and removing common corporate suffixes (`inc`, `llc`, `ltd`, `corp`, `co`).
#[must_use]
pub fn normalize_counterparty(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect();
    let stop_words = ["inc", "llc", "ltd", "corp", "corporation", "co", "the"];
    cleaned
        .split_whitespace()
        .filter(|tok| !stop_words.contains(tok))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Normalize a reference token by trimming and lowercasing ASCII alphanumeric characters.
#[must_use]
pub fn normalize_reference(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// Configuration for the Teller candidate generator and adaptive matcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatcherConfig {
    pub policy_epoch: Option<[u8; 32]>,
    pub enforced_policy_epoch: [u8; 32],
    /// Maximum allowed `|booking_date - effective_date|` in days.
    pub max_date_window_days: i32,
    /// When `true`, disables adaptive heuristics and runs only the pinned
    /// deterministic fallback (`exact_amount_and_date` + reference match).
    pub pinned_fallback_only: bool,
    /// Optional advisory learned similarity scores in basis points (`0..=10_000`)
    /// keyed by `(bank_line_oid, entry_ordinal)`. Marked `advisory = true` on
    /// every [`DecisionCard`] so they can never override analytic rules.
    pub advisory_learned_scores_bps: BTreeMap<(Oid, u64), i128>,
}

/// Committed residual entry (e.g., bank wire fee or FX settlement difference)
/// that explains the exact difference between matched bank lines and book entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidualExplanation {
    pub residual_entry_ref: EntryRef,
    /// Signed cash delta of the residual entry on the cash account.
    pub signed_cash_delta: i128,
    /// Named rounding, fee, or FX law (`fx_laws.toml` or `rounding_laws.toml`).
    pub law_id: String,
}

/// Journaled, immutable [`ReconciliationMatch`] object (`Match` in plan §15.9, bead `fa-2ek`).
///
/// Supports one-to-one, one-to-many (one bank line split across multiple book
/// entries), and many-to-one (multiple bank lines settling one book entry), with
/// an optional [`ResidualExplanation`] when a committed fee or FX entry accounts
/// for the difference. Unmatching or replacing a match records a new object
/// naming `supersedes_match_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationMatch {
    pub bank_line_ids: Vec<Oid>,
    pub book_entry_refs: Vec<EntryRef>,
    pub matched_entry_ordinal: Option<u64>,
    pub residual: Option<ResidualExplanation>,
    pub decision_card: DecisionCard,
    pub principal: VId,
    pub supersedes_match_id: Option<Oid>,
}

impl ReconciliationMatch {
    /// Validate that:
    /// 1. The decision card carries the registered pinned fallback (`validate_fallback`)
    ///    and replays bit-for-bit (`verify_replay`).
    /// 2. Committed amounts are preserved (`amounts_preserved`).
    /// 3. The sum of bank line cash deltas equals the sum of book entry cash
    ///    deltas plus any cited committed residual entry under a named law.
    pub fn validate(
        &self,
        enforced_policy_epoch: [u8; 32],
        bank_lines_by_id: &BTreeMap<Oid, BankStatementLine>,
        book_entries_by_ref: &BTreeMap<EntryRef, BookCandidateEntry>,
    ) -> Result<Oid, ReconciliationError> {
        self.decision_card.validate_fallback()?;
        self.decision_card.verify_replay(enforced_policy_epoch)?;

        if self.bank_line_ids.is_empty() {
            return Err(ReconciliationError::InvalidField("bank_line_ids"));
        }

        let mut bank_net: i128 = 0;
        let mut expected_unit: Option<UnitId> = None;
        for id in &self.bank_line_ids {
            let Some(line) = bank_lines_by_id.get(id) else {
                return Err(ReconciliationError::InvalidField("unknown bank_line_id"));
            };
            if let Some(u) = expected_unit {
                if line.amount.unit != u {
                    return Err(ReconciliationError::UnitMismatch {
                        expected: u,
                        actual: line.amount.unit,
                    });
                }
            } else {
                expected_unit = Some(line.amount.unit);
            }
            bank_net = bank_net
                .checked_add(line.signed_cash_delta())
                .ok_or(ReconciliationError::InvalidField("bank_net overflow"))?;
        }

        let mut book_net: i128 = 0;
        let mut committed_amounts = Vec::with_capacity(self.book_entry_refs.len());
        for eref in &self.book_entry_refs {
            let Some(entry) = book_entries_by_ref.get(eref) else {
                return Err(ReconciliationError::InvalidField("unknown book_entry_ref"));
            };
            if let Some(u) = expected_unit
                && entry.amount.unit != u
            {
                return Err(ReconciliationError::UnitMismatch {
                    expected: u,
                    actual: entry.amount.unit,
                });
            }
            committed_amounts.push(entry.amount);
            book_net = book_net
                .checked_add(entry.signed_cash_delta())
                .ok_or(ReconciliationError::InvalidField("book_net overflow"))?;
        }

        if !amounts_preserved(&committed_amounts, &committed_amounts, &self.decision_card) {
            return Err(ReconciliationError::InvalidField("amounts_preserved"));
        }

        let residual_delta = if let Some(res) = &self.residual {
            if res.law_id.trim().is_empty() {
                return Err(ReconciliationError::MissingResidualLaw);
            }
            res.signed_cash_delta
        } else {
            0
        };

        if !self.book_entry_refs.is_empty() {
            let total_book_with_residual = book_net
                .checked_add(residual_delta)
                .ok_or(ReconciliationError::InvalidField("residual overflow"))?;
            if bank_net != total_book_with_residual {
                return Err(ReconciliationError::UnexplainedResidual {
                    bank_net_mantissa: bank_net,
                    book_net_mantissa: total_book_with_residual,
                    unexplained_delta: bank_net - total_book_with_residual,
                });
            }
        }

        self.oid()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReconciliationError> {
        let card_bytes = self.decision_card.canonical_bytes()?;
        let mut w = Writer::with_capacity(128 + card_bytes.len());
        w.bytes(RECON_MATCH_DOMAIN)
            .list(&self.bank_line_ids, |w, oid| {
                w.fixed(&oid.0);
            })
            .list(&self.book_entry_refs, |w, eref| {
                w.u128(eref.vid.0).fixed(&eref.entry_digest);
            })
            .opt(self.matched_entry_ordinal.as_ref(), |w, ord| {
                w.u64(*ord);
            })
            .opt(self.residual.as_ref(), |w, res| {
                w.u128(res.residual_entry_ref.vid.0)
                    .fixed(&res.residual_entry_ref.entry_digest)
                    .i128(res.signed_cash_delta)
                    .str(&res.law_id);
            })
            .bytes(&card_bytes)
            .u128(self.principal.0)
            .opt(self.supersedes_match_id.as_ref(), |w, oid| {
                w.fixed(&oid.0);
            });
        Ok(w.finish()?)
    }

    pub fn oid(&self) -> Result<Oid, ReconciliationError> {
        let bytes = self.canonical_bytes()?;
        Ok(Oid(domain_digest(RECON_MATCH_DOMAIN, &[&bytes])))
    }
}

/// Verify that a proposed match does not alter any committed [`BookCandidateEntry`] amount.
pub fn verify_match_preserves_committed_amounts(
    entry: &BookCandidateEntry,
    proposed_amount: Amount,
    card: &DecisionCard,
) -> Result<(), ReconciliationError> {
    if !amounts_preserved(&[entry.amount], &[proposed_amount], card) {
        return Err(ReconciliationError::AmountModified {
            entry_ref: Box::new(entry.entry_ref),
            committed: entry.amount,
            proposed: proposed_amount,
        });
    }
    Ok(())
}

/// Exact amount, direction and date law shared by matching and review diagnostics.
fn exact_cash_candidate(
    line: &BankStatementLine,
    entry: &BookCandidateEntry,
    max_date_window_days: i32,
) -> Result<Option<i64>, ReconciliationError> {
    if entry.amount.unit != line.amount.unit {
        return Err(ReconciliationError::UnitMismatch {
            expected: line.amount.unit,
            actual: entry.amount.unit,
        });
    }
    // Bank credits increase cash; book debits increase cash. Compare the
    // original nonnegative magnitudes directly, avoiding sign overflow.
    if entry.amount.mantissa != line.amount.mantissa || entry.side == line.side {
        return Ok(None);
    }
    let days = (i64::from(line.booking_date.0) - i64::from(entry.effective_date.0)).abs();
    Ok((days <= i64::from(max_date_window_days)).then_some(days))
}

/// Whether a cash leg is eligible under the pinned amount/date/reference law,
/// before any other statement line consumes it. This does not choose or
/// confirm a match; callers use it to expose ties and competing bank lines.
pub fn pinned_bank_candidate(
    line: &BankStatementLine,
    entry: &BookCandidateEntry,
    max_date_window_days: i32,
) -> Result<bool, ReconciliationError> {
    if exact_cash_candidate(line, entry, max_date_window_days)?.is_none() {
        return Ok(false);
    }
    let reference = normalize_reference(&line.reference);
    Ok(reference.is_empty() || reference == normalize_reference(&entry.reference))
}

type DatedCandidates = BTreeSet<(i32, usize)>;

#[derive(Default)]
struct CashCandidates {
    all: DatedCandidates,
    references: BTreeMap<String, DatedCandidates>,
    counterparties: BTreeMap<String, DatedCandidates>,
}

/// A request-local index of unconsumed cash legs. The final join is ordered by
/// input position, not by the index keys: candidate/feature order is part of
/// the replayable decision card, including when ordinals repeat.
#[derive(Default)]
struct CashCandidateIndex {
    amounts: BTreeMap<(i128, u8), CashCandidates>,
    units: BTreeMap<UnitId, BTreeSet<usize>>,
    ordinals: BTreeMap<u64, Vec<usize>>,
    references: Vec<String>,
    counterparties: Vec<String>,
    #[cfg(test)]
    range_visits: usize,
}

impl CashCandidateIndex {
    fn new(entries: &[BookCandidateEntry]) -> Self {
        let mut index = Self::default();
        for (position, entry) in entries.iter().enumerate() {
            let reference = normalize_reference(&entry.reference);
            let counterparty = normalize_counterparty(&entry.counterparty);
            let dated = (entry.effective_date.0, position);
            let group = index
                .amounts
                .entry((entry.amount.mantissa, entry.side as u8))
                .or_default();
            group.all.insert(dated);
            group
                .references
                .entry(reference.clone())
                .or_default()
                .insert(dated);
            if !counterparty.is_empty() {
                group
                    .counterparties
                    .entry(counterparty.clone())
                    .or_default()
                    .insert(dated);
            }
            index
                .units
                .entry(entry.amount.unit)
                .or_default()
                .insert(position);
            index
                .ordinals
                .entry(entry.entry_ordinal)
                .or_default()
                .push(position);
            index.references.push(reference);
            index.counterparties.push(counterparty);
        }
        index
    }

    fn select(
        &mut self,
        line: &BankStatementLine,
        reference: &str,
        counterparty: &str,
        window: i32,
    ) -> Result<BTreeSet<usize>, ReconciliationError> {
        // The literal matcher diagnoses the first unconsumed foreign-unit
        // entry even when its amount/direction/date would not match. Preserve
        // that error and its input order before pruning any candidates.
        if let Some((_, actual)) = self
            .units
            .iter()
            .filter(|(unit, _)| **unit != line.amount.unit)
            .filter_map(|(unit, positions)| positions.first().map(|position| (*position, *unit)))
            .min_by_key(|(position, _)| *position)
        {
            return Err(ReconciliationError::UnitMismatch {
                expected: line.amount.unit,
                actual,
            });
        }
        let mut selected = BTreeSet::new();
        if window < 0 {
            return Ok(selected);
        }
        let side = match line.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
        let Some(group) = self.amounts.get(&(line.amount.mantissa, side as u8)) else {
            return Ok(selected);
        };
        let from = line.booking_date.0.saturating_sub(window);
        let through = line.booking_date.0.saturating_add(window);
        let mut extend = |candidates: &DatedCandidates| {
            for (_, position) in candidates.range((from, 0)..=(through, usize::MAX)) {
                #[cfg(test)]
                {
                    self.range_visits += 1;
                }
                selected.insert(*position);
            }
        };
        if reference.is_empty() {
            extend(&group.all);
        } else {
            if let Some(candidates) = group.references.get(reference) {
                extend(candidates);
            }
            if !counterparty.is_empty()
                && let Some(candidates) = group.counterparties.get(counterparty)
            {
                extend(candidates);
            }
        }
        Ok(selected)
    }

    fn consume(&mut self, ordinal: u64, entries: &[BookCandidateEntry]) {
        let Some(positions) = self.ordinals.remove(&ordinal) else {
            return;
        };
        // Consumption is by ordinal in the original law, not by identity or
        // position. Remove every alias so later lines never rescan spent legs.
        for position in positions {
            let entry = &entries[position];
            let dated = (entry.effective_date.0, position);
            if let Some(group) = self
                .amounts
                .get_mut(&(entry.amount.mantissa, entry.side as u8))
            {
                group.all.remove(&dated);
                if let Some(candidates) = group.references.get_mut(&self.references[position]) {
                    candidates.remove(&dated);
                }
                if let Some(candidates) =
                    group.counterparties.get_mut(&self.counterparties[position])
                {
                    candidates.remove(&dated);
                }
            }
            if let Some(positions) = self.units.get_mut(&entry.amount.unit) {
                positions.remove(&position);
                if positions.is_empty() {
                    self.units.remove(&entry.amount.unit);
                }
            }
        }
    }
}

/// Run the Teller candidate generator and adaptive [`DecisionCard`] matcher
/// over `bank_lines` and `book_entries`.
///
/// Under the pinned deterministic fallback (`config.pinned_fallback_only == true`
/// or when the policy epoch / interval forces fallback), matches require:
/// 1. Exact signed cash delta equality (`bank_line.signed_cash_delta() == entry.signed_cash_delta()`).
/// 2. `|booking_date - effective_date| <= config.max_date_window_days`.
/// 3. Exact normalized reference equality (whenever `bank_line.reference` is non-empty).
/// 4. Deterministic tie-break by lowest `entry_ordinal`.
///
/// Candidates are indexed once by amount, direction, normalized reference and
/// counterparty, with ordered date ranges. Only eligible unconsumed candidates
/// enter each line's decision card. Work is O(E log E + B log E + K log E),
/// excluding text normalization and card encoding, for E cash legs, B lines and
/// K emitted candidate occurrences. An ambiguous request can itself require
/// quadratic card output; unrelated ledger entries do not multiply the work.
pub fn match_bank_lines(
    bank_lines: &[BankStatementLine],
    book_entries: &[BookCandidateEntry],
    config: &MatcherConfig,
    principal: VId,
) -> Result<Vec<ReconciliationMatch>, ReconciliationError> {
    if bank_lines.is_empty() {
        return Ok(Vec::new());
    }
    let mut index = CashCandidateIndex::new(book_entries);
    let mut out = Vec::with_capacity(bank_lines.len());
    for line in bank_lines {
        let line_oid = line.oid()?;
        let norm_ref = normalize_reference(&line.reference);
        let norm_cp = normalize_counterparty(&line.counterparty);
        let selected = index.select(line, &norm_ref, &norm_cp, config.max_date_window_days)?;
        let proposal = match_line(
            line,
            line_oid,
            &norm_ref,
            &norm_cp,
            selected.into_iter().map(|position| &book_entries[position]),
            config,
            principal,
        )?;
        if let Some(ordinal) = proposal.matched_entry_ordinal {
            index.consume(ordinal, book_entries);
        }
        out.push(proposal);
    }
    Ok(out)
}

fn match_line<'a>(
    line: &BankStatementLine,
    line_oid: Oid,
    norm_ref: &str,
    norm_cp: &str,
    entries: impl IntoIterator<Item = &'a BookCandidateEntry>,
    config: &MatcherConfig,
    principal: VId,
) -> Result<ReconciliationMatch, ReconciliationError> {
    let mut candidates = Vec::new();
    let mut features = Vec::new();
    let mut fallback_winner: Option<&BookCandidateEntry> = None;
    let mut adaptive_by_ordinal: BTreeMap<i128, &BookCandidateEntry> = BTreeMap::new();

    for entry in entries {
        let Some(day_delta) = exact_cash_candidate(line, entry, config.max_date_window_days)?
        else {
            continue;
        };

        let entry_ref_norm = normalize_reference(&entry.reference);
        let ref_exact = !norm_ref.is_empty() && norm_ref == entry_ref_norm;
        let ref_compatible = norm_ref.is_empty() || ref_exact;
        let cp_exact =
            !norm_cp.is_empty() && norm_cp == normalize_counterparty(&entry.counterparty);

        if ref_compatible {
            match fallback_winner {
                None => fallback_winner = Some(entry),
                Some(prev) if entry.entry_ordinal < prev.entry_ordinal => {
                    fallback_winner = Some(entry);
                }
                _ => {}
            }
        }

        // Analytic score: higher for exact reference + closer date + counterparty match,
        // with deterministic tie-breaking favoring lower entry_ordinal.
        let mut analytic_score: i128 = 1_000 - i128::from(day_delta) * 10;
        if ref_exact {
            analytic_score += 500;
        }
        if cp_exact {
            analytic_score += 200;
        }
        // Subtract entry_ordinal slightly so lower ordinal wins ties deterministically.
        let tie_adjusted_score = analytic_score
            .saturating_mul(1_000_000)
            .saturating_sub(i128::from(entry.entry_ordinal));

        if ref_compatible || cp_exact {
            let ord_param = i128::from(entry.entry_ordinal);
            candidates.push(DecisionCandidate {
                action: "match_entry_ordinal".to_string(),
                parameter: ord_param,
                analytic_score: tie_adjusted_score.max(1),
            });
            adaptive_by_ordinal.insert(ord_param, entry);

            features.push(DecisionFeature {
                name: format!("cand.{}.date_delta_days", entry.entry_ordinal),
                value: i128::from(day_delta),
                advisory: false,
            });
            features.push(DecisionFeature {
                name: format!("cand.{}.ref_exact", entry.entry_ordinal),
                value: i128::from(u8::from(ref_exact)),
                advisory: false,
            });
            features.push(DecisionFeature {
                name: format!("cand.{}.cp_exact", entry.entry_ordinal),
                value: i128::from(u8::from(cp_exact)),
                advisory: false,
            });
            if let Some(&learned_bps) = config
                .advisory_learned_scores_bps
                .get(&(line_oid, entry.entry_ordinal))
            {
                features.push(DecisionFeature {
                    name: format!("cand.{}.learned_similarity_bps", entry.entry_ordinal),
                    value: learned_bps,
                    advisory: true,
                });
            }
        }
    }

    let effective_epoch = if config.pinned_fallback_only {
        None
    } else {
        config.policy_epoch
    };
    let interval = if config.pinned_fallback_only || candidates.is_empty() {
        BenefitInterval {
            lower_bps: 0,
            upper_bps: 2_000,
        }
    } else {
        BenefitInterval {
            lower_bps: 250,
            upper_bps: 750,
        }
    };

    let card = decide_bank_match(
        effective_epoch,
        config.enforced_policy_epoch,
        line_oid.0,
        candidates,
        features,
        interval,
    );
    card.validate_fallback()?;
    card.verify_replay(config.enforced_policy_epoch)?;

    let chosen_entry = if card.used_fallback() {
        fallback_winner
    } else {
        adaptive_by_ordinal
            .get(&card.chosen.parameter)
            .copied()
            .or(fallback_winner)
    };

    let (book_entry_refs, matched_entry_ordinal) = match chosen_entry {
        Some(entry) => (vec![entry.entry_ref], Some(entry.entry_ordinal)),
        None => (Vec::new(), None),
    };

    Ok(ReconciliationMatch {
        bank_line_ids: vec![line_oid],
        book_entry_refs,
        matched_entry_ordinal,
        residual: None,
        decision_card: card,
        principal,
        supersedes_match_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_reference::reconciliation::{RefBankLine, RefBookEntry, naive_fallback_match};

    fn entry(ordinal: u64, amount: i128, day: i32, reference: &str) -> BookCandidateEntry {
        BookCandidateEntry {
            entry_ref: EntryRef {
                vid: VId(u128::from(ordinal) + 1),
                entry_digest: domain_digest(b"test:bank-entry", &[&ordinal.to_le_bytes()]),
            },
            entry_ordinal: ordinal,
            effective_date: DateDay(day),
            side: Side::Debit,
            amount: Amount::new(UnitId(1), amount),
            counterparty: String::new(),
            reference: reference.into(),
        }
    }

    fn line(ordinal: u32, amount: i128, day: i32, reference: &str) -> BankStatementLine {
        BankStatementLine {
            statement_oid: Oid([7; 32]),
            statement_seq: 1,
            line_ordinal: ordinal,
            booking_date: DateDay(day),
            value_date: DateDay(day),
            side: Side::Credit,
            amount: Amount::new(UnitId(1), amount),
            counterparty: String::new(),
            reference: reference.into(),
        }
    }

    fn config(pinned: bool) -> MatcherConfig {
        MatcherConfig {
            policy_epoch: Some([19; 32]),
            enforced_policy_epoch: [19; 32],
            max_date_window_days: 5,
            pinned_fallback_only: pinned,
            advisory_learned_scores_bps: BTreeMap::new(),
        }
    }

    /// The incumbent exhaustive selection, sharing only the unchanged scoring
    /// and card construction. Counts every visited leg, including consumed ones.
    fn literal(
        lines: &[BankStatementLine],
        entries: &[BookCandidateEntry],
        config: &MatcherConfig,
    ) -> Result<(Vec<ReconciliationMatch>, usize), ReconciliationError> {
        let mut consumed = BTreeSet::new();
        let mut visits = 0;
        let mut out = Vec::new();
        for line in lines {
            let oid = line.oid()?;
            let result = match_line(
                line,
                oid,
                &normalize_reference(&line.reference),
                &normalize_counterparty(&line.counterparty),
                entries
                    .iter()
                    .inspect(|_| visits += 1)
                    .filter(|entry| !consumed.contains(&entry.entry_ordinal)),
                config,
                VId(71),
            )?;
            if let Some(ordinal) = result.matched_entry_ordinal {
                consumed.insert(ordinal);
            }
            out.push(result);
        }
        Ok((out, visits))
    }

    fn compare(
        lines: &[BankStatementLine],
        entries: &[BookCandidateEntry],
        config: &MatcherConfig,
    ) {
        let expected = literal(lines, entries, config).map(|(matches, _)| matches);
        let actual = match_bank_lines(lines, entries, config, VId(71));
        assert_eq!(actual, expected);
        if let (Ok(actual), Ok(expected)) = (actual, expected) {
            for (actual, expected) in actual.iter().zip(expected) {
                assert_eq!(actual.canonical_bytes(), expected.canonical_bytes());
                actual
                    .decision_card
                    .verify_replay(config.enforced_policy_epoch)
                    .unwrap();
            }
        }
    }

    #[test]
    fn indexed_bank_match_preserves_complete_cards_and_independent_fallback() {
        let references = ["", " INV-1 ", "inv-1", "inv-2", "other"];
        let parties = ["", "Acme, Inc.", "ACME", "Other LLC"];
        for seed in 0..24u64 {
            let mut state = seed + 1;
            let mut next = || {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                state >> 32
            };
            let entries: Vec<_> = (0..80)
                .map(|i| {
                    let mut e = entry(
                        (i * 17) % 59,
                        1 + i128::from(next() % 5),
                        90 + (next() % 21) as i32,
                        references[(next() % references.len() as u64) as usize],
                    );
                    e.entry_ref.vid = VId(u128::from(i) + 1);
                    e.side = if next().is_multiple_of(2) {
                        Side::Debit
                    } else {
                        Side::Credit
                    };
                    e.counterparty = parties[(next() % parties.len() as u64) as usize].into();
                    e
                })
                .collect();
            let lines: Vec<_> = (0..40)
                .map(|i| {
                    let mut l = line(
                        i,
                        1 + i128::from(next() % 5),
                        90 + (next() % 21) as i32,
                        references[(next() % references.len() as u64) as usize],
                    );
                    l.side = if next().is_multiple_of(2) {
                        Side::Debit
                    } else {
                        Side::Credit
                    };
                    l.counterparty = parties[(next() % parties.len() as u64) as usize].into();
                    l
                })
                .collect();
            for pinned in [false, true] {
                let mut cfg = config(pinned);
                for line in &lines {
                    cfg.advisory_learned_scores_bps
                        .insert((line.oid().unwrap(), seed), 9999);
                }
                compare(&lines, &entries, &cfg);
                cfg.policy_epoch = Some([20; 32]);
                compare(&lines, &entries, &cfg);
            }
            let reference_lines: Vec<_> = lines
                .iter()
                .map(|line| RefBankLine {
                    line_id: line.oid().unwrap().0,
                    booking_date: line.booking_date,
                    signed_mantissa: line.signed_cash_delta(),
                    reference: line.reference.clone(),
                })
                .collect();
            let reference_entries: Vec<_> = entries
                .iter()
                .map(|entry| RefBookEntry {
                    entry_ordinal: entry.entry_ordinal,
                    effective_date: entry.effective_date,
                    signed_mantissa: entry.signed_cash_delta(),
                    reference: entry.reference.clone(),
                })
                .collect();
            let actual = match_bank_lines(&lines, &entries, &config(true), VId(71)).unwrap();
            let selected: Vec<_> = actual
                .iter()
                .map(|m| (m.bank_line_ids[0].0, m.matched_entry_ordinal))
                .collect();
            assert_eq!(
                selected,
                naive_fallback_match(&reference_lines, &reference_entries, 5)
            );
        }
    }

    #[test]
    fn indexed_bank_match_keeps_error_precedence_and_extreme_date_windows() {
        let mut entries = vec![entry(9, 100, 1, "x"), entry(7, 200, 2, "y")];
        entries[1].amount.unit = UnitId(3);
        let mut later = entry(1, 100, 1, "x");
        later.amount.unit = UnitId(2);
        entries.push(later);
        let mut lines = vec![line(1, 100, 1, "x")];
        compare(&lines, &entries, &config(true));
        assert!(matches!(
            match_bank_lines(&lines, &entries, &config(true), VId(71)),
            Err(ReconciliationError::UnitMismatch {
                actual: UnitId(3),
                ..
            })
        ));
        lines[0].amount.mantissa = 0;
        compare(&lines, &entries, &config(true));
        assert!(matches!(
            match_bank_lines(&lines, &entries, &config(true), VId(71)),
            Err(ReconciliationError::InvalidField("amount.mantissa"))
        ));
        compare(&[], &entries, &config(true));

        let entries: Vec<_> = [i32::MIN, -1, 0, 1, i32::MAX]
            .into_iter()
            .enumerate()
            .map(|(i, day)| entry(i as u64, i128::MAX, day, ""))
            .collect();
        for window in [i32::MIN, -1, 0, 1, i32::MAX] {
            let mut cfg = config(true);
            cfg.max_date_window_days = window;
            for day in [i32::MIN, -1, 0, 1, i32::MAX] {
                compare(&[line(1, i128::MAX, day, "")], &entries, &cfg);
            }
        }
    }

    #[test]
    fn indexed_bank_match_consumes_ordinal_aliases_and_preserves_adaptive_ties() {
        let mut entries = vec![
            entry(8, 100, 100, "a"),
            entry(8, 100, 100, "a"),
            entry(2, 100, 100, "b"),
        ];
        entries[1].entry_ref.vid = VId(99);
        for entry in &mut entries {
            entry.counterparty = "Acme Ltd".into();
        }
        let mut lines = vec![
            line(1, 100, 100, "a"),
            line(2, 100, 100, "a"),
            line(3, 100, 100, "b"),
        ];
        for line in &mut lines {
            line.counterparty = "ACME, INC".into();
        }
        for pinned in [true, false] {
            compare(&lines, &entries, &config(pinned));
        }
        let actual = match_bank_lines(&lines, &entries, &config(true), VId(71)).unwrap();
        assert_eq!(
            actual
                .iter()
                .map(|m| m.matched_entry_ordinal)
                .collect::<Vec<_>>(),
            vec![Some(8), None, Some(2)]
        );
        // Once all candidates are consumed, another unit is not an error.
        let entries = vec![entry(1, 100, 100, "a")];
        let mut lines = vec![line(1, 100, 100, "a"), line(2, 100, 100, "a")];
        lines[1].amount.unit = UnitId(2);
        compare(&lines, &entries, &config(true));
    }

    #[test]
    fn indexed_bank_match_visits_only_eligible_candidates_at_one_hundred_thousand() {
        for count in [1_000, 10_000, 100_000] {
            let entries: Vec<_> = (0..count)
                .map(|i| entry(i as u64, 100, 100, &format!("invoice-{i}")))
                .collect();
            let mut index = CashCandidateIndex::new(&entries);
            for i in (0..count).rev() {
                let line = line(i as u32, 100, 100, &format!("invoice-{i}"));
                let selected = index.select(&line, &line.reference, "", 5).unwrap();
                assert_eq!(selected, BTreeSet::from([i]));
                index.consume(entries[i].entry_ordinal, &entries);
            }
            assert_eq!(index.range_visits, count);
            assert!(index.units.is_empty());
            let absent = line(0, 100, 100, "");
            assert!(index.select(&absent, "", "", 5).unwrap().is_empty());
            assert_eq!(index.range_visits, count);
        }
    }

    #[test]
    fn indexed_bank_match_date_ranges_do_not_visit_unrelated_history() {
        let entries: Vec<_> = (0..100_000)
            .map(|i| entry(i as u64, 100, i, "same-reference"))
            .collect();
        let mut index = CashCandidateIndex::new(&entries);
        for day in (0..100_000).step_by(100) {
            let line = line(day as u32, 100, day, "");
            let selected = index.select(&line, "", "", 0).unwrap();
            assert_eq!(selected, BTreeSet::from([day as usize]));
        }
        assert_eq!(index.range_visits, 1_000);
    }

    #[test]
    fn indexed_bank_match_agrees_with_live_exhaustive_incumbent_at_scale() {
        compare_exhaustive_at_scale(1_000);
    }

    #[test]
    #[ignore = "explicit 100-million-visit incumbent benchmark; run with --ignored --nocapture"]
    fn indexed_bank_match_ten_thousand_lines_agree_with_live_exhaustive_incumbent() {
        compare_exhaustive_at_scale(10_000);
    }

    fn compare_exhaustive_at_scale(count: u32) {
        let entries: Vec<_> = (0..count)
            .map(|i| entry(i as u64, i128::from(i) + 1, 100, ""))
            .collect();
        let lines: Vec<_> = (0..count)
            .map(|i| line(i, i128::from(i) + 1, 100, ""))
            .collect();
        let cfg = config(true);
        let start = std::time::Instant::now();
        let actual = match_bank_lines(&lines, &entries, &cfg, VId(71)).unwrap();
        let indexed = start.elapsed();
        let start = std::time::Instant::now();
        let (expected, visits) = literal(&lines, &entries, &cfg).unwrap();
        let exhaustive = start.elapsed();
        assert_eq!(actual, expected);
        assert_eq!(visits, (count as usize) * (count as usize));
        assert_eq!(actual.len(), count as usize);
        assert!(actual.iter().all(|m| m.matched_entry_ordinal.is_some()));
        eprintln!(
            "bank matcher: {count} lines, {count} cash legs; indexed={indexed:?}, exhaustive={exhaustive:?}, exhaustive_visits={visits}; outputs identical"
        );
    }
}
