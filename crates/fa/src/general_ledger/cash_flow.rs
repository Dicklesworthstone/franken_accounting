//! Classified cash movements over the native, immutable general ledger.
//!
//! Cash scope and activity classifications are explicit accounting inputs, not
//! facts inferred from account names or generated text. Every selected cash leg
//! must be classified exactly once. Internal transfers must cancel within ONE
//! entry and native unit, across distinct selected cash accounts. Opening and
//! closing stocks come from the independent native folds, never a balancing plug.
//!
//! This is a cash-movement workpaper, not a GAAP/IFRS opinion or a claim that the
//! declared scope contains every cash equivalent in the book. Non-cash activity
//! is outside that scope. Exchange effects are explicit classifications; no FX
//! conversion or cross-unit total is computed. Canonical bytes retain the source
//! transcript and classifications, but are not a standalone replay certificate.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::{Refusal, exit};
use fa_model::AccountType;
use fa_money::wide::U256;
use fgdb_types::QueryCx;

use super::{Bytes, GeneralLedger, MAX_GENERAL_LEDGER_LINES};
use crate::{BookError, Outcome};

pub const CASH_FLOW_FORMAT: &str = "fa:cash-flow:v1";

/// Classification of an original cash leg, not a synthetic netted transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CashFlowActivity {
    Operating = 0,
    Investing = 1,
    Financing = 2,
    ExchangeEffect = 3,
    InternalTransfer = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowAssignment {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub activity: CashFlowActivity,
}

/// The account set must EXACTLY match the native general-ledger selection.
/// Asset leaves may represent cash/equivalents; liability leaves may represent
/// qualifying overdrafts. These designations remain the caller's assertion.
/// `name` identifies the retained classification policy/workpaper version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowDefinition {
    pub name: String,
    pub cash_accounts: Vec<u128>,
    pub assignments: Vec<CashFlowAssignment>,
}

/// Inflows/outflows are nonnegative gross magnitudes; net may be negative.
/// Within a single journal entry, native unit, and activity section, opposing
/// cash legs are netted before accumulating gross `inflows` and `outflows` so
/// intra-entry cash movement does not inflate direct-method gross turnover.
/// Refunds and reversals in separate entries retain their actual cash direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CashFlowSection {
    pub inflows: i128,
    pub outflows: i128,
    pub net: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowUnit {
    pub unit_id: u32,
    pub opening: i128,
    pub operating: CashFlowSection,
    pub investing: CashFlowSection,
    pub financing: CashFlowSection,
    pub exchange_effects: CashFlowSection,
    pub net_change: i128,
    pub closing: i128,
}

/// Constructed only from a native read. No caller-supplied balance totals or
/// mutable report fields can replace the source after reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlow {
    source: GeneralLedger,
    definition: CashFlowDefinition,
    units: Vec<CashFlowUnit>,
}

impl CashFlow {
    #[must_use]
    pub fn source(&self) -> &GeneralLedger {
        &self.source
    }

    #[must_use]
    pub fn definition(&self) -> &CashFlowDefinition {
        &self.definition
    }

    /// Ascending native unit id, including explicitly selected zero units.
    #[must_use]
    pub fn units(&self) -> &[CashFlowUnit] {
        &self.units
    }

    /// Bounded, deterministic output including the exact native source scope,
    /// coordinates, leg citations and classifications. This does not grant
    /// authority or substitute for source-certificate verification.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut out = Bytes::default();
        out.string(CASH_FLOW_FORMAT)?;
        let source = self.source.canonical_bytes()?;
        out.count(source.len())?;
        out.add(&source)?;
        out.string(&self.definition.name)?;
        out.count(self.definition.cash_accounts.len())?;
        for account in &self.definition.cash_accounts {
            out.add(&account.to_le_bytes())?;
        }
        out.count(self.definition.assignments.len())?;
        for assignment in &self.definition.assignments {
            out.add(&assignment.entry_digest)?;
            out.add(&assignment.leg_index.to_le_bytes())?;
            out.add(&[assignment.activity as u8])?;
        }
        out.count(self.units.len())?;
        for unit in &self.units {
            out.add(&unit.unit_id.to_le_bytes())?;
            out.add(&unit.opening.to_le_bytes())?;
            for section in [
                unit.operating,
                unit.investing,
                unit.financing,
                unit.exchange_effects,
            ] {
                for amount in [section.inflows, section.outflows, section.net] {
                    out.add(&amount.to_le_bytes())?;
                }
            }
            out.add(&unit.net_change.to_le_bytes())?;
            out.add(&unit.closing.to_le_bytes())?;
        }
        Ok(out.0)
    }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §12.1 / §15.3 (classified cash movements must tie to native stock)",
        "declare the exact cash scope and classify every selected posted leg once; transfers must cancel within one entry and unit; never add a balancing plug",
    )
}

/// Separate wide magnitudes prevent order-dependent intermediate overflow.
/// Bounded native inputs fit well inside 256 bits; only final public amounts
/// are narrowed to the repository's exact i128 monetary range.
#[derive(Clone, Copy)]
struct Exact {
    positive: U256,
    negative: U256,
}

impl Exact {
    const ZERO: Self = Self {
        positive: U256::ZERO,
        negative: U256::ZERO,
    };

    fn signed(&mut self, value: i128) -> Result<(), Refusal> {
        let part = if value < 0 {
            &mut self.negative
        } else {
            &mut self.positive
        };
        *part = part
            .checked_add(U256::from_u128(value.unsigned_abs()))
            .ok_or_else(|| invalid("cash-flow accumulation exceeds its wide bound"))?;
        Ok(())
    }

    fn sides(&mut self, debits: i128, credits: i128) -> Result<(), Refusal> {
        if debits < 0 || credits < 0 || (debits > 0) == (credits > 0) {
            return Err(invalid(
                "cash movement must be exactly one positive debit or credit",
            ));
        }
        self.signed(debits)?;
        self.signed(-credits)
    }

    fn combine(&mut self, other: Self, subtract: bool) -> Result<(), Refusal> {
        let (positive, negative) = if subtract {
            (other.negative, other.positive)
        } else {
            (other.positive, other.negative)
        };
        self.positive = self
            .positive
            .checked_add(positive)
            .ok_or_else(|| invalid("cash-flow accumulation exceeds its wide bound"))?;
        self.negative = self
            .negative
            .checked_add(negative)
            .ok_or_else(|| invalid("cash-flow accumulation exceeds its wide bound"))?;
        Ok(())
    }

    fn net_into(self, section: &mut Self) -> Result<(), Refusal> {
        if self.positive >= self.negative {
            let net_inflow = self
                .positive
                .checked_sub(self.negative)
                .ok_or_else(|| invalid("cash-flow accumulation underflow"))?;
            section.positive = section
                .positive
                .checked_add(net_inflow)
                .ok_or_else(|| invalid("cash-flow accumulation exceeds its wide bound"))?;
        } else {
            let net_outflow = self
                .negative
                .checked_sub(self.positive)
                .ok_or_else(|| invalid("cash-flow accumulation underflow"))?;
            section.negative = section
                .negative
                .checked_add(net_outflow)
                .ok_or_else(|| invalid("cash-flow accumulation exceeds its wide bound"))?;
        }
        Ok(())
    }

    fn value(self) -> Result<i128, Refusal> {
        let value = if self.positive >= self.negative {
            self.positive
                .checked_sub(self.negative)
                .and_then(U256::to_u128)
                .and_then(|n| i128::try_from(n).ok())
        } else {
            self.negative
                .checked_sub(self.positive)
                .and_then(U256::to_u128)
                .and_then(|n| {
                    if n == i128::MIN.unsigned_abs() {
                        Some(i128::MIN)
                    } else {
                        i128::try_from(n).ok().and_then(i128::checked_neg)
                    }
                })
        };
        value.ok_or_else(|| invalid("cash-flow amount exceeds the exact i128 output range"))
    }

    fn section(self) -> Result<CashFlowSection, Refusal> {
        let magnitude = |value: U256| {
            value
                .to_u128()
                .and_then(|n| i128::try_from(n).ok())
                .ok_or_else(|| {
                    invalid("cash-flow gross turnover exceeds the exact i128 output range")
                })
        };
        Ok(CashFlowSection {
            inflows: magnitude(self.positive)?,
            outflows: magnitude(self.negative)?,
            net: self.value()?,
        })
    }
}

struct Totals {
    opening: Exact,
    closing: Exact,
    sections: [Exact; 4],
}

impl Totals {
    fn new() -> Self {
        Self {
            opening: Exact::ZERO,
            closing: Exact::ZERO,
            sections: [Exact::ZERO; 4],
        }
    }
}

#[derive(Debug)]
enum ProjectionError {
    Refusal(Refusal),
    Book(BookError),
}
impl From<Refusal> for ProjectionError {
    fn from(error: Refusal) -> Self {
        Self::Refusal(error)
    }
}
impl From<BookError> for ProjectionError {
    fn from(error: BookError) -> Self {
        Self::Book(error)
    }
}

fn build(
    source: GeneralLedger,
    definition: &CashFlowDefinition,
    mut checkpoint: impl FnMut() -> Result<(), BookError>,
) -> Result<CashFlow, ProjectionError> {
    checkpoint()?;
    if definition.name.trim().is_empty()
        || definition.name.len() > 256
        || definition.cash_accounts.is_empty()
        || definition.cash_accounts.len() != source.accounts().len()
        || definition.assignments.len() > MAX_GENERAL_LEDGER_LINES
        || definition.assignments.len() != source.lines().len()
    {
        return Err(invalid("cash-flow definition needs a bounded name, exact cash scope and one assignment per posted cash leg").into());
    }
    let cash: BTreeSet<_> = definition.cash_accounts.iter().copied().collect();
    if cash.len() != definition.cash_accounts.len() {
        return Err(invalid("cash-flow account designations repeat an account").into());
    }
    for (index, account) in source.accounts().iter().enumerate() {
        if index % 256 == 0 {
            checkpoint()?;
        }
        if !cash.contains(&account.id)
            || !account.is_leaf
            || ![AccountType::ASSET.0, AccountType::LIABILITY.0].contains(&account.account_type)
        {
            return Err(invalid(
                "declared cash accounts must exactly cover the selected asset/overdraft leaves",
            )
            .into());
        }
    }
    let mut assignments = BTreeMap::new();
    for (index, assignment) in definition.assignments.iter().enumerate() {
        if index % 256 == 0 {
            checkpoint()?;
        }
        if assignments
            .insert(
                (assignment.entry_digest, assignment.leg_index),
                assignment.activity,
            )
            .is_some()
        {
            return Err(invalid("cash-flow classification repeats a journal leg").into());
        }
    }
    let mut totals: BTreeMap<_, _> = source
        .units()
        .iter()
        .map(|id| (*id, Totals::new()))
        .collect();
    for (index, cell) in source.cells().iter().enumerate() {
        if index % 256 == 0 {
            checkpoint()?;
        }
        let total = totals
            .get_mut(&cell.unit_id)
            .ok_or_else(|| invalid("cash-flow stock names an undeclared native unit"))?;
        total.opening.signed(cell.opening)?;
        total.closing.signed(cell.closing)?;
    }
    let mut transfers: BTreeMap<([u8; 32], u32), (Exact, BTreeSet<u128>)> = BTreeMap::new();
    let mut entry_sections: BTreeMap<([u8; 32], u32, usize), Exact> = BTreeMap::new();
    for (index, line) in source.lines().iter().enumerate() {
        if index % 256 == 0 {
            checkpoint()?;
        }
        let cell = source
            .cells()
            .get(line.cell_index as usize)
            .ok_or_else(|| invalid("cash-flow leg names an absent source cell"))?;
        let activity = assignments
            .remove(&(line.entry_digest, line.leg_index))
            .ok_or_else(|| invalid("a posted cash leg has no unique classification"))?;
        if activity == CashFlowActivity::InternalTransfer {
            let (sum, accounts) = transfers
                .entry((line.entry_digest, cell.unit_id))
                .or_insert_with(|| (Exact::ZERO, BTreeSet::new()));
            sum.sides(line.debits, line.credits)?;
            accounts.insert(cell.account_id);
        } else {
            if !totals.contains_key(&cell.unit_id) {
                return Err(invalid("cash-flow leg names an undeclared native unit").into());
            }
            entry_sections
                .entry((line.entry_digest, cell.unit_id, activity as usize))
                .or_insert(Exact::ZERO)
                .sides(line.debits, line.credits)?;
        }
    }
    for (index, ((_, unit_id, section_idx), entry_net)) in entry_sections.into_iter().enumerate() {
        if index % 256 == 0 {
            checkpoint()?;
        }
        let total = totals
            .get_mut(&unit_id)
            .ok_or_else(|| invalid("cash-flow leg names an undeclared native unit"))?;
        entry_net.net_into(&mut total.sections[section_idx])?;
    }
    if !assignments.is_empty() {
        return Err(
            invalid("cash-flow classifications name legs outside the native selection").into(),
        );
    }
    for (index, (sum, accounts)) in transfers.values().enumerate() {
        if index % 256 == 0 {
            checkpoint()?;
        }
        if accounts.len() < 2 || sum.value()? != 0 {
            return Err(invalid("internal cash transfers must cancel within one entry and unit across distinct cash accounts").into());
        }
    }
    let mut units = Vec::with_capacity(totals.len());
    for (index, (unit_id, total)) in totals.into_iter().enumerate() {
        if index % 256 == 0 {
            checkpoint()?;
        }
        let mut change = Exact::ZERO;
        for section in total.sections {
            change.combine(section, false)?;
        }
        let mut residual = total.opening;
        residual.combine(change, false)?;
        residual.combine(total.closing, true)?;
        if residual.value()? != 0 {
            return Err(invalid("classified cash activity does not reconcile opening to closing stock in a native unit").into());
        }
        units.push(CashFlowUnit {
            unit_id,
            opening: total.opening.value()?,
            operating: total.sections[0].section()?,
            investing: total.sections[1].section()?,
            financing: total.sections[2].section()?,
            exchange_effects: total.sections[3].section()?,
            net_change: change.value()?,
            closing: total.closing.value()?,
        });
    }
    checkpoint()?;
    let mut definition = definition.clone();
    definition.cash_accounts.sort_unstable();
    definition
        .assignments
        .sort_unstable_by_key(|a| (a.entry_digest, a.leg_index));
    checkpoint()?;
    Ok(CashFlow {
        source,
        definition,
        units,
    })
}

pub(super) fn project(
    source: GeneralLedger,
    definition: &CashFlowDefinition,
    query: &QueryCx,
) -> Outcome<CashFlow> {
    match build(source, definition, || {
        query.checkpoint().map_err(BookError::Context)
    }) {
        Ok(report) => Ok(Ok(report)),
        Err(ProjectionError::Refusal(error)) => Ok(Err(error)),
        Err(ProjectionError::Book(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::general_ledger::{GeneralLedgerCell, GeneralLedgerLine};
    use fa_model::{EntryClass, Id128};
    use fa_statements::Account;
    use fa_statements::roll_forward::Bucket;
    use fa_time::DateDay;
    use fgdb_types::CommitSeq;

    fn fixture() -> (GeneralLedger, CashFlowDefinition) {
        let accounts = [1_u128, 2]
            .into_iter()
            .map(|id| Account {
                id,
                code: format!("100{id}"),
                name: format!("Cash {id}"),
                account_type: AccountType::ASSET.0,
                is_leaf: true,
            })
            .collect();
        let cell = |account_id, opening, debits, credits, closing, line_start, line_end| {
            GeneralLedgerCell {
                account_id,
                unit_id: 1,
                opening,
                debits,
                credits,
                net_change: closing - opening,
                closing,
                line_start,
                line_end,
            }
        };
        let line = |cell_index, entry: u8, leg_index, debits, credits, running_balance| {
            GeneralLedgerLine {
                cell_index,
                entry_digest: [entry; 32],
                leg_index,
                recorded_seq: u64::from(entry),
                effective_day: DateDay(10),
                bucket_index: 0,
                debits,
                credits,
                running_balance,
            }
        };
        let source = GeneralLedger {
            book_id: Id128([1; 16]),
            branch_id: Id128::TRUNK,
            known_at: CommitSeq(5),
            label: "January cash".into(),
            effective_from: DateDay(1),
            effective_through: DateDay(31),
            accounts,
            units: vec![1],
            buckets: vec![Bucket {
                class: EntryClass::ORIGINAL,
                reason_code: String::new(),
                rule_digest: None,
            }],
            cells: vec![
                cell(1, 1000, 500, 350, 1150, 0, 4),
                cell(2, 0, 500, 0, 500, 4, 6),
            ],
            lines: vec![
                line(0, 1, 0, 500, 0, 1500),
                line(0, 2, 0, 0, 200, 1300),
                line(0, 4, 0, 0, 100, 1200),
                line(0, 5, 0, 0, 50, 1150),
                line(1, 3, 0, 400, 0, 400),
                line(1, 4, 1, 100, 0, 500),
            ],
        };
        let assignments = source
            .lines()
            .iter()
            .map(|line| CashFlowAssignment {
                entry_digest: line.entry_digest,
                leg_index: line.leg_index,
                activity: match line.entry_digest[0] {
                    2 => CashFlowActivity::Investing,
                    3 => CashFlowActivity::Financing,
                    4 => CashFlowActivity::InternalTransfer,
                    _ => CashFlowActivity::Operating,
                },
            })
            .collect();
        (
            source,
            CashFlowDefinition {
                name: "cash-policy-v1".into(),
                cash_accounts: vec![1, 2],
                assignments,
            },
        )
    }

    fn read(
        source: GeneralLedger,
        definition: &CashFlowDefinition,
    ) -> Result<CashFlow, ProjectionError> {
        build(source, definition, || Ok(()))
    }

    #[test]
    fn receipts_refunds_investment_financing_and_transfers_reconcile() {
        let (source, definition) = fixture();
        let original = source.canonical_bytes().unwrap();
        let report = read(source, &definition).unwrap();
        let unit = &report.units()[0];
        assert_eq!(
            (unit.opening, unit.net_change, unit.closing),
            (1000, 650, 1650)
        );
        assert_eq!(
            unit.operating,
            CashFlowSection {
                inflows: 500,
                outflows: 50,
                net: 450
            }
        );
        assert_eq!(unit.investing.net, -200);
        assert_eq!(unit.financing.net, 400);
        assert_eq!(unit.exchange_effects.net, 0);
        assert_eq!(report.source().canonical_bytes().unwrap(), original);
        assert_eq!(report.definition().assignments.len(), 6);
    }

    #[test]
    fn classifications_and_cash_scope_have_canonical_order() {
        let (source, mut definition) = fixture();
        let expected = read(source.clone(), &definition)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        definition.cash_accounts.reverse();
        definition.assignments.reverse();
        assert_eq!(
            read(source, &definition)
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            expected
        );
    }

    #[test]
    fn unclassified_even_net_zero_activity_is_not_ignored() {
        let (source, mut definition) = fixture();
        definition
            .assignments
            .retain(|a| a.activity != CashFlowActivity::InternalTransfer);
        assert!(read(source, &definition).is_err());
    }

    #[test]
    fn duplicate_and_foreign_citations_are_rejected() {
        let (source, definition) = fixture();
        let mut duplicate = definition.clone();
        duplicate.assignments[1] = duplicate.assignments[0].clone();
        assert!(read(source.clone(), &duplicate).is_err());
        let mut foreign = definition;
        foreign.assignments[0].entry_digest = [99; 32];
        assert!(read(source, &foreign).is_err());
    }

    #[test]
    fn cash_scope_must_match_and_cannot_include_income_or_equity() {
        let (source, definition) = fixture();
        for cash_accounts in [vec![], vec![1], vec![1, 1], vec![1, 99]] {
            let mut bad = definition.clone();
            bad.cash_accounts = cash_accounts;
            assert!(read(source.clone(), &bad).is_err());
        }
        let mut bad_source = source;
        bad_source.accounts[0].account_type = AccountType::EQUITY.0;
        assert!(read(bad_source, &definition).is_err());
    }

    #[test]
    fn transfers_cannot_hide_one_sided_cash_movements() {
        let (source, mut definition) = fixture();
        definition.assignments[0].activity = CashFlowActivity::InternalTransfer;
        assert!(read(source, &definition).is_err());
    }

    #[test]
    fn transfers_cannot_net_across_native_units() {
        let (mut source, definition) = fixture();
        source.units.push(2);
        source.cells[1].unit_id = 2;
        assert!(read(source, &definition).is_err());
    }

    #[test]
    fn transfers_cannot_net_across_entries() {
        let (mut source, mut definition) = fixture();
        source.lines[5].entry_digest = [5; 32];
        definition.assignments[5].entry_digest = [5; 32];
        assert!(read(source, &definition).is_err());
    }

    #[test]
    fn declared_zero_units_are_retained_without_cross_unit_totals() {
        let (mut source, definition) = fixture();
        source.units.push(2);
        let report = read(source, &definition).unwrap();
        assert_eq!(report.units().len(), 2);
        let zero = &report.units()[1];
        assert_eq!(
            (zero.unit_id, zero.opening, zero.net_change, zero.closing),
            (2, 0, 0, 0)
        );
    }

    #[test]
    fn independent_closing_stock_cannot_be_replaced_by_a_plug() {
        let (mut source, definition) = fixture();
        source.cells[0].closing += 1;
        assert!(read(source, &definition).is_err());
    }

    #[test]
    fn empty_period_retains_opening_cash_and_overdrafts() {
        let (mut source, mut definition) = fixture();
        source.lines.clear();
        definition.assignments.clear();
        for cell in &mut source.cells {
            cell.debits = 0;
            cell.credits = 0;
            cell.net_change = 0;
            cell.closing = cell.opening;
            cell.line_start = 0;
            cell.line_end = 0;
        }
        source.accounts[1].account_type = AccountType::LIABILITY.0;
        source.cells[1].opening = -200;
        source.cells[1].closing = -200;
        let report = read(source, &definition).unwrap();
        assert_eq!(
            (report.units()[0].opening, report.units()[0].closing),
            (800, 800)
        );
    }

    #[test]
    fn exchange_effects_are_explicit_and_do_not_rewrite_the_cash_change() {
        let (source, mut definition) = fixture();
        definition.assignments[0].activity = CashFlowActivity::ExchangeEffect;
        let report = read(source, &definition).unwrap();
        assert_eq!(report.units()[0].exchange_effects.net, 500);
        assert_eq!(report.units()[0].operating.net, -50);
        assert_eq!(report.units()[0].net_change, 650);
    }

    #[test]
    fn large_cancelling_sums_are_exact_and_order_independent() {
        for values in [
            [i128::MAX, i128::MAX, -i128::MAX],
            [-i128::MAX, i128::MAX, i128::MAX],
        ] {
            let mut sum = Exact::ZERO;
            for value in values {
                sum.signed(value).unwrap();
            }
            assert_eq!(sum.value().unwrap(), i128::MAX);
        }
        let mut minimum = Exact::ZERO;
        minimum.signed(i128::MIN).unwrap();
        assert_eq!(minimum.value().unwrap(), i128::MIN);
    }

    #[test]
    fn output_overflow_and_negative_magnitudes_fail_closed() {
        let mut sum = Exact::ZERO;
        sum.signed(i128::MAX).unwrap();
        sum.signed(1).unwrap();
        assert!(sum.value().is_err());
        assert!(sum.section().is_err());
        let mut neg = Exact::ZERO;
        assert!(neg.sides(0, -1).is_err());
        let mut both = Exact::ZERO;
        assert!(both.sides(1, 1).is_err());
    }

    #[test]
    fn empty_or_unbounded_policy_identity_is_rejected() {
        let (source, mut definition) = fixture();
        for name in [String::new(), " ".into(), "x".repeat(257)] {
            definition.name = name;
            assert!(read(source.clone(), &definition).is_err());
        }
    }

    #[test]
    fn long_projection_participates_in_query_checkpoints() {
        let (source, definition) = fixture();
        let mut checks = 0;
        build(source, &definition, || {
            checks += 1;
            Ok(())
        })
        .unwrap();
        assert!(checks >= 8);
    }
}
