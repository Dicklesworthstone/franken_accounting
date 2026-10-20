//! Concordat: multi-book adjustment layers, book-to-book reconciliation bridges,
//! intercompany pair matching, deterministic elimination derivation, and
//! consolidated equity reconciliation (plan §12.2, §12.3, FA-INV-13).
//!
//! All arithmetic is exact (`i128` with checked 256-bit `U256` intermediates and
//! registered `RoundingLaw` rules for non-controlling interest allocation).
//! No floating-point type enters any amount or ownership path.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fa_model::{DecodeError, EncodeError, Id128, Oid, Reader, Writer, domain_digest};
use fa_money::rounding::RoundingLaw;
use fa_money::wide::U256;

use crate::{
    Account, AccountBalance, ColumnInput, Statement, StatementDefinition, StatementError,
    StatementInput, evaluate,
};

pub const BOOK_TO_BOOK_BRIDGE_FORMAT: &[u8] = b"fa:book-to-book-bridge:v1";
pub const CONSOLIDATION_RUN_FORMAT: &[u8] = b"fa:consolidation-run:v1";

const MAX_BRIDGE_ENTRIES: usize = 65_536;
const MAX_ENTITIES: usize = 1024;
const MAX_IC_PAIRS: usize = 4096;
const BPS_DENOMINATOR: i128 = 10_000;

/// Relationship of a book to its accounting universe (plan §12.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BookKind {
    /// Standalone primary book of record (e.g. GAAP book).
    Primary,
    /// Layered book (tax, statutory, or management) anchored to a parent book
    /// at an explicit `parent_known_at` commit sequence.
    AdjustmentLayer {
        parent_book_id: Id128,
        parent_known_at: u64,
    },
}

/// Schedule M-1 / M-3 and statutory/management adjustment reason codes (plan §12.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BookToBookReasonCode {
    /// Permanent tax difference: meals & entertainment disallowance.
    M1PermanentMealsEntertainment,
    /// Permanent tax difference: tax-exempt interest/income.
    M1PermanentTaxExemptIncome,
    /// Permanent tax difference: non-deductible penalties or fines.
    M1PermanentPenaltiesFines,
    /// Temporary timing difference: MACRS / tax vs book depreciation.
    M1TemporaryDepreciation,
    /// Temporary timing difference: allowance for doubtful accounts vs direct write-off.
    M1TemporaryBadDebtAllowance,
    /// Temporary timing difference: prepaid / unearned revenue inclusion.
    M1TemporaryUnearnedRevenue,
    /// Schedule M-3 temporary difference: stock-based compensation.
    M3TemporaryStockCompensation,
    /// Statutory chart/presentation reclassification.
    StatutoryReclassification,
    /// Management reporting allocation.
    ManagementCostAllocation,
}

impl BookToBookReasonCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::M1PermanentMealsEntertainment => "M1-PERM-MEALS",
            Self::M1PermanentTaxExemptIncome => "M1-PERM-TAX-EXEMPT",
            Self::M1PermanentPenaltiesFines => "M1-PERM-PENALTIES",
            Self::M1TemporaryDepreciation => "M1-TEMP-DEPRECIATION",
            Self::M1TemporaryBadDebtAllowance => "M1-TEMP-BAD-DEBT",
            Self::M1TemporaryUnearnedRevenue => "M1-TEMP-UNEARNED-REV",
            Self::M3TemporaryStockCompensation => "M3-TEMP-STOCK-COMP",
            Self::StatutoryReclassification => "STAT-RECLASS",
            Self::ManagementCostAllocation => "MGMT-ALLOC",
        }
    }

    #[must_use]
    pub const fn is_permanent(self) -> bool {
        matches!(
            self,
            Self::M1PermanentMealsEntertainment
                | Self::M1PermanentTaxExemptIncome
                | Self::M1PermanentPenaltiesFines
        )
    }

    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::M1PermanentMealsEntertainment => 1,
            Self::M1PermanentTaxExemptIncome => 2,
            Self::M1PermanentPenaltiesFines => 3,
            Self::M1TemporaryDepreciation => 4,
            Self::M1TemporaryBadDebtAllowance => 5,
            Self::M1TemporaryUnearnedRevenue => 6,
            Self::M3TemporaryStockCompensation => 7,
            Self::StatutoryReclassification => 8,
            Self::ManagementCostAllocation => 9,
        }
    }

    pub(crate) fn from_tag(tag: u8, r: &Reader<'_>) -> Result<Self, DecodeError> {
        match tag {
            1 => Ok(Self::M1PermanentMealsEntertainment),
            2 => Ok(Self::M1PermanentTaxExemptIncome),
            3 => Ok(Self::M1PermanentPenaltiesFines),
            4 => Ok(Self::M1TemporaryDepreciation),
            5 => Ok(Self::M1TemporaryBadDebtAllowance),
            6 => Ok(Self::M1TemporaryUnearnedRevenue),
            7 => Ok(Self::M3TemporaryStockCompensation),
            8 => Ok(Self::StatutoryReclassification),
            9 => Ok(Self::ManagementCostAllocation),
            _ => Err(r.bad_tag("book_to_book_reason_code", tag)),
        }
    }
}

/// One adjustment leg in an `AdjustmentLayer` book, citing the rule version and
/// Schedule M-1/M-3 or statutory reason code that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdjustmentLayerLeg {
    pub entry_id: u128,
    pub rule_version_oid: Oid,
    pub reason_code: BookToBookReasonCode,
    pub account_id: u128,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
}

/// Input to `reconcile_book_to_book` (`recon.book_to_book`, plan §12.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookToBookInput {
    pub parent_book_id: Id128,
    pub parent_known_at: u64,
    pub layered_book_id: Id128,
    pub layered_kind: BookKind,
    pub layered_known_at: u64,
    pub accounts: Vec<Account>,
    pub units: Vec<u32>,
    pub parent_balances: Vec<AccountBalance>,
    pub layered_balances: Vec<AccountBalance>,
    pub adjustments: Vec<AdjustmentLayerLeg>,
}

/// One rule-version and reason-code delta explaining part of a book-to-book difference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeExplanation {
    pub entry_id: u128,
    pub rule_version_oid: Oid,
    pub reason_code: BookToBookReasonCode,
    /// Exact signed movement `debits - credits`.
    pub net_delta: i128,
}

/// One reconciled `(account, unit)` row in a book-to-book bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookToBookBridgeRow {
    pub account_id: u128,
    pub account_code: String,
    pub unit_id: u32,
    /// `debits - credits` in the parent book.
    pub parent_net: i128,
    /// Sum of `net_delta` across all adjustment legs for `(account_id, unit_id)`.
    pub adjustments_net: i128,
    /// `debits - credits` in the layered book (`parent_net + adjustments_net`).
    pub layered_net: i128,
    pub explanations: Vec<BridgeExplanation>,
}

/// Certified-ready book-to-book reconciliation bridge (`recon.book_to_book`, plan §12.2, FA-INV-13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookToBookBridge {
    pub parent_book_id: Id128,
    pub parent_known_at: u64,
    pub layered_book_id: Id128,
    pub layered_known_at: u64,
    pub rows: Vec<BookToBookBridgeRow>,
}

impl BookToBookBridge {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(BOOK_TO_BOOK_BRIDGE_FORMAT)
            .fixed(&self.parent_book_id.0)
            .u64(self.parent_known_at)
            .fixed(&self.layered_book_id.0)
            .u64(self.layered_known_at)
            .list(&self.rows, |w, row| {
                w.u128(row.account_id)
                    .str(&row.account_code)
                    .u32(row.unit_id)
                    .i128(row.parent_net)
                    .i128(row.adjustments_net)
                    .i128(row.layered_net)
                    .list(&row.explanations, |w, exp| {
                        w.u128(exp.entry_id)
                            .fixed(&exp.rule_version_oid.0)
                            .u8(exp.reason_code.tag())
                            .i128(exp.net_delta);
                    });
            });
        w.finish()
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            BOOK_TO_BOOK_BRIDGE_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let magic = r.fixed::<{ BOOK_TO_BOOK_BRIDGE_FORMAT.len() }>("book_to_book.magic")?;
        if magic != BOOK_TO_BOOK_BRIDGE_FORMAT {
            return Err(r.invalid("book-to-book bridge format header"));
        }
        let parent_book_id = Id128(r.fixed::<16>("parent_book_id")?);
        let parent_known_at = r.u64("parent_known_at")?;
        let layered_book_id = Id128(r.fixed::<16>("layered_book_id")?);
        let layered_known_at = r.u64("layered_known_at")?;
        let row_count = r.count(MAX_BRIDGE_ENTRIES, "bridge.rows")?;
        let mut rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            let account_id = r.u128("row.account_id")?;
            let account_code = r.str(64, "row.account_code")?.to_string();
            let unit_id = r.u32("row.unit_id")?;
            let parent_net = r.i128("row.parent_net")?;
            let adjustments_net = r.i128("row.adjustments_net")?;
            let layered_net = r.i128("row.layered_net")?;
            let exp_count = r.count(MAX_BRIDGE_ENTRIES, "row.explanations")?;
            let mut explanations = Vec::with_capacity(exp_count);
            for _ in 0..exp_count {
                let entry_id = r.u128("exp.entry_id")?;
                let rule_version_oid = Oid(r.fixed::<32>("exp.rule_version_oid")?);
                let reason_tag = r.u8("exp.reason_code")?;
                let reason_code = BookToBookReasonCode::from_tag(reason_tag, &r)?;
                let net_delta = r.i128("exp.net_delta")?;
                explanations.push(BridgeExplanation {
                    entry_id,
                    rule_version_oid,
                    reason_code,
                    net_delta,
                });
            }
            rows.push(BookToBookBridgeRow {
                account_id,
                account_code,
                unit_id,
                parent_net,
                adjustments_net,
                layered_net,
                explanations,
            });
        }
        r.finish()?;
        Ok(Self {
            parent_book_id,
            parent_known_at,
            layered_book_id,
            layered_known_at,
            rows,
        })
    }
}

/// Kind of reciprocal intercompany pair (plan §12.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntercompanyPairKind {
    /// Balance-sheet reciprocal pair (e.g., Intercompany Due From vs Due To).
    ReciprocalReceivablePayable,
    /// Income-statement reciprocal pair (e.g., Intercompany Revenue vs Expense).
    ReciprocalRevenueExpense,
}

impl IntercompanyPairKind {
    const fn tag(self) -> u8 {
        match self {
            Self::ReciprocalReceivablePayable => 1,
            Self::ReciprocalRevenueExpense => 2,
        }
    }
}

/// Declared reciprocal intercompany relationship between two legal entities/books.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntercompanyPairSpec {
    pub pair_code: String,
    pub kind: IntercompanyPairKind,
    pub entity_a: Id128,
    pub account_a: u128,
    pub entity_b: Id128,
    pub account_b: u128,
    /// Optional explicit FX / in-transit difference account (`FA-INV-13`).
    pub difference_account: Option<u128>,
    /// Maximum allowed absolute FX translation residual in the reporting unit (`0` when same unit).
    pub max_fx_residual: i128,
}

/// Result of matching one declared intercompany pair in one unit (`FA-INV-13`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchedIntercompanyPair {
    pub pair_code: String,
    pub kind: IntercompanyPairKind,
    pub unit_id: u32,
    pub entity_a: Id128,
    pub account_a: u128,
    /// Signed `debits - credits` on `account_a` for `entity_a`.
    pub entity_a_net: i128,
    pub entity_b: Id128,
    pub account_b: u128,
    /// Signed `debits - credits` on `account_b` for `entity_b`.
    pub entity_b_net: i128,
    /// Explicit difference account and signed leg (`debits - credits`) required to close the pair.
    pub difference_leg: Option<(u128, i128)>,
}

/// Ownership link from a parent entity to a consolidated subsidiary (plan §12.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnershipSpec {
    pub parent_entity: Id128,
    pub subsidiary_entity: Id128,
    /// Ownership percentage in basis points (`1..=10_000`, where `10_000` = 100%).
    pub ownership_bps: u16,
    /// Parent's "Investment in Subsidiary" asset account ID.
    pub investment_account_id: u128,
    /// Subsidiary's contributed/pre-acquisition equity account IDs eliminated against the investment.
    pub subsidiary_equity_account_ids: Vec<u128>,
    /// Consolidated Non-Controlling Interest (NCI) equity account ID (required if `ownership_bps < 10_000`).
    pub nci_equity_account_id: Option<u128>,
    /// Registered rounding law used when splitting subsidiary equity/earnings into controlling vs NCI.
    pub rounding_law: RoundingLaw,
}

/// One member entity/book fold participating in a consolidation run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityMemberInput {
    pub entity_id: Id128,
    pub book_id: Id128,
    pub known_at: u64,
    pub balances: Vec<AccountBalance>,
}

/// One leg of a deterministically derived elimination entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EliminationLeg {
    pub entity_id: Id128,
    pub account_id: u128,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
}

/// Deterministically derived elimination entry proposal (`FA-INV-13`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EliminationEntry {
    pub code: String,
    pub description: String,
    pub unit_id: u32,
    pub legs: Vec<EliminationLeg>,
}

impl EliminationEntry {
    /// Verify `FA-INV-01` balance conservation on the derived elimination entry.
    #[must_use]
    pub fn is_balanced(&self) -> bool {
        let mut debits = U256::ZERO;
        let mut credits = U256::ZERO;
        for leg in &self.legs {
            if leg.debits < 0 || leg.credits < 0 || leg.unit_id != self.unit_id {
                return false;
            }
            let Some(next_d) = debits.checked_add(U256::from_u128(leg.debits.unsigned_abs()))
            else {
                return false;
            };
            let Some(next_c) = credits.checked_add(U256::from_u128(leg.credits.unsigned_abs()))
            else {
                return false;
            };
            debits = next_d;
            credits = next_c;
        }
        debits == credits
    }
}

/// Proof of consolidated equity conservation per unit (`FA-INV-13.core`).
///
/// Credit-normal equity sign convention:
/// `parent_total_equity + subsidiaries_total_equity + equity_eliminations == consolidated_total_equity`
/// and `consolidated_total_equity == controlling_interest_equity + non_controlling_interest_equity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolidatedEquityReconciliation {
    pub unit_id: u32,
    /// Parent's standalone total equity (credit - debit, including unclosed earnings).
    pub parent_total_equity: i128,
    /// Sum of subsidiaries' standalone total equity (credit - debit, including unclosed earnings).
    pub subsidiaries_total_equity: i128,
    /// Net equity change from investment-vs-equity eliminations and intercompany P&L eliminations.
    pub equity_eliminations: i128,
    /// Non-controlling interest (NCI) equity recognized on consolidation.
    pub non_controlling_interest_equity: i128,
    /// Controlling interest equity (`consolidated_total_equity - non_controlling_interest_equity`).
    pub controlling_interest_equity: i128,
    /// Total equity on the consolidated balance sheet (`total_equity` line).
    pub consolidated_total_equity: i128,
}

/// Input to a deterministic multi-book / multi-entity consolidation run (`consolidate`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolidationInput {
    pub consolidation_book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub period: String,
    pub effective_through: fa_time::DateDay,
    pub accounts: Vec<Account>,
    pub units: Vec<u32>,
    pub members: Vec<EntityMemberInput>,
    pub intercompany_pairs: Vec<IntercompanyPairSpec>,
    pub ownership: Vec<OwnershipSpec>,
}

/// Output of a deterministic consolidation run (`FA-INV-13.core`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolidationRun {
    pub consolidation_book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub period: String,
    pub matched_pairs: Vec<MatchedIntercompanyPair>,
    pub eliminations: Vec<EliminationEntry>,
    pub equity_reconciliations: Vec<ConsolidatedEquityReconciliation>,
    pub balance_sheet: Statement,
    pub income_statement: Statement,
}

impl ConsolidationRun {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(CONSOLIDATION_RUN_FORMAT)
            .fixed(&self.consolidation_book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.known_at)
            .str(&self.period)
            .list(&self.matched_pairs, |w, pair| {
                w.str(&pair.pair_code)
                    .u8(pair.kind.tag())
                    .u32(pair.unit_id)
                    .fixed(&pair.entity_a.0)
                    .u128(pair.account_a)
                    .i128(pair.entity_a_net)
                    .fixed(&pair.entity_b.0)
                    .u128(pair.account_b)
                    .i128(pair.entity_b_net)
                    .opt(pair.difference_leg.as_ref(), |w, (acct, delta)| {
                        w.u128(*acct).i128(*delta);
                    });
            })
            .list(&self.eliminations, |w, elim| {
                w.str(&elim.code)
                    .str(&elim.description)
                    .u32(elim.unit_id)
                    .list(&elim.legs, |w, leg| {
                        w.fixed(&leg.entity_id.0)
                            .u128(leg.account_id)
                            .u32(leg.unit_id)
                            .i128(leg.debits)
                            .i128(leg.credits);
                    });
            })
            .list(&self.equity_reconciliations, |w, eq| {
                w.u32(eq.unit_id)
                    .i128(eq.parent_total_equity)
                    .i128(eq.subsidiaries_total_equity)
                    .i128(eq.equity_eliminations)
                    .i128(eq.non_controlling_interest_equity)
                    .i128(eq.controlling_interest_equity)
                    .i128(eq.consolidated_total_equity);
            });
        let bs_bytes = self.balance_sheet.canonical_bytes()?;
        let is_bytes = self.income_statement.canonical_bytes()?;
        w.bytes(&bs_bytes).bytes(&is_bytes);
        w.finish()
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            CONSOLIDATION_RUN_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConcordatError {
    Input(String),
    Statement(StatementError),
    /// The layered book is not an `AdjustmentLayer` anchored to `parent_book_id`.
    ParentBookMismatch {
        expected_parent: Id128,
        layered_book: Id128,
    },
    /// The parent book moved past `layer_parent_known_at` (e.g. a restatement occurred)
    /// and the layered book has not yet propagated the parent restatement.
    ParentBookRestated {
        parent_book_id: Id128,
        layer_parent_known_at: u64,
        current_parent_known_at: u64,
    },
    /// An adjustment entry in an `AdjustmentLayer` book is not balanced per unit.
    UnbalancedAdjustment {
        entry_id: u128,
        unit_id: u32,
        debits: i128,
        credits: i128,
    },
    /// A cell difference between parent and layered book is not explained by any rule-versioned adjustment.
    UnexplainedBookDifference {
        account_code: String,
        unit_id: u32,
        parent_net: i128,
        adjustments_net: i128,
        layered_net: i128,
        residual: i128,
    },
    /// An intercompany pair failed to net to zero within the FX law's bound (`FA-INV-13`).
    UnmatchedIntercompanyPair {
        pair_code: String,
        unit_id: u32,
        entity_a: Id128,
        entity_b: Id128,
        entity_a_net: i128,
        entity_b_net: i128,
        residual: i128,
    },
    /// Parent's investment account balance disagrees with the controlling share of subsidiary equity.
    InvestmentEquityMismatch {
        subsidiary_entity: Id128,
        unit_id: u32,
        investment_balance: i128,
        expected_controlling_equity: i128,
    },
    /// Consolidated equity failed to reconcile to member equities + eliminations + NCI (`FA-INV-13`).
    EquityReconciliationFailure {
        unit_id: u32,
        expected_consolidated_equity: i128,
        actual_consolidated_equity: i128,
    },
    Overflow(&'static str),
}

impl fmt::Display for ConcordatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(msg) => write!(f, "concordat input error: {msg}"),
            Self::Statement(e) => write!(f, "{e}"),
            Self::ParentBookMismatch {
                expected_parent,
                layered_book,
            } => write!(
                f,
                "layered book {} is not an AdjustmentLayer anchored to parent book {}",
                layered_book.to_hex(),
                expected_parent.to_hex()
            ),
            Self::ParentBookRestated {
                parent_book_id,
                layer_parent_known_at,
                current_parent_known_at,
            } => write!(
                f,
                "parent book {} is at known-at {current_parent_known_at}, which supersedes layer anchor {layer_parent_known_at}; propagate parent restatement first",
                parent_book_id.to_hex()
            ),
            Self::UnbalancedAdjustment {
                entry_id,
                unit_id,
                debits,
                credits,
            } => write!(
                f,
                "adjustment entry {:032x} in unit {unit_id} is unbalanced: debits {debits} != credits {credits}",
                entry_id
            ),
            Self::UnexplainedBookDifference {
                account_code,
                unit_id,
                parent_net,
                adjustments_net,
                layered_net,
                residual,
            } => write!(
                f,
                "unexplained book-to-book difference on account `{account_code}` in unit {unit_id}: parent ({parent_net}) + adjustments ({adjustments_net}) != layered ({layered_net}), residual = {residual}"
            ),
            Self::UnmatchedIntercompanyPair {
                pair_code,
                unit_id,
                entity_a,
                entity_b,
                entity_a_net,
                entity_b_net,
                residual,
            } => write!(
                f,
                "unmatched intercompany pair `{pair_code}` between {} ({entity_a_net}) and {} ({entity_b_net}) in unit {unit_id}: residual {residual} exceeds admissible difference bound",
                entity_a.to_hex(),
                entity_b.to_hex()
            ),
            Self::InvestmentEquityMismatch {
                subsidiary_entity,
                unit_id,
                investment_balance,
                expected_controlling_equity,
            } => write!(
                f,
                "parent investment in subsidiary {} in unit {unit_id} is {investment_balance}, but controlling share of subsidiary equity is {expected_controlling_equity}",
                subsidiary_entity.to_hex()
            ),
            Self::EquityReconciliationFailure {
                unit_id,
                expected_consolidated_equity,
                actual_consolidated_equity,
            } => write!(
                f,
                "consolidated equity reconciliation failed in unit {unit_id}: expected {expected_consolidated_equity}, got {actual_consolidated_equity}"
            ),
            Self::Overflow(what) => write!(f, "concordat arithmetic overflow: {what}"),
        }
    }
}

impl core::error::Error for ConcordatError {}

impl From<StatementError> for ConcordatError {
    fn from(e: StatementError) -> Self {
        Self::Statement(e)
    }
}

fn checked_net(debits: i128, credits: i128) -> Result<i128, ConcordatError> {
    if debits < 0 || credits < 0 {
        return Err(ConcordatError::Input(
            "balance debits and credits must be non-negative".into(),
        ));
    }
    debits
        .checked_sub(credits)
        .ok_or(ConcordatError::Overflow("debit minus credit net"))
}

fn round_bps_share(
    amount: i128,
    ownership_bps: u16,
    law: RoundingLaw,
) -> Result<i128, ConcordatError> {
    let mag = U256::from_u128(amount.unsigned_abs())
        .checked_mul_u128(u128::from(ownership_bps))
        .ok_or(ConcordatError::Overflow("controlling share numerator"))?;
    let denom = BPS_DENOMINATOR.unsigned_abs();
    let (q_wide, r_wide) = mag
        .checked_div_rem(U256::from_u128(denom))
        .ok_or(ConcordatError::Overflow("controlling share division"))?;
    let q = q_wide
        .to_u128()
        .ok_or(ConcordatError::Overflow("controlling share quotient"))?;
    let r = r_wide
        .to_u128()
        .ok_or(ConcordatError::Overflow("controlling share remainder"))?;
    let rounded_mag = law
        .apply_magnitude(q, r, denom, amount < 0)
        .ok_or(ConcordatError::Overflow("controlling share rounding"))?;
    if amount < 0 {
        if rounded_mag == i128::MIN.unsigned_abs() {
            Ok(i128::MIN)
        } else {
            i128::try_from(rounded_mag)
                .ok()
                .and_then(i128::checked_neg)
                .ok_or(ConcordatError::Overflow("controlling share sign"))
        }
    } else {
        i128::try_from(rounded_mag).map_err(|_| ConcordatError::Overflow("controlling share sign"))
    }
}

/// Reconcile a parent book and an `AdjustmentLayer` book (`recon.book_to_book`, plan §12.2, FA-INV-13).
///
/// Verifies that:
/// 1. `layered_kind` is `BookKind::AdjustmentLayer` anchored to `parent_book_id` at `parent_known_at`
///    (refusing if the parent book has moved/restated without propagation).
/// 2. Every `AdjustmentLayerLeg` entry balances per `(entry_id, unit_id)`.
/// 3. Every difference between `parent_balances` and `layered_balances` is 100% explained
///    by rule-versioned adjustment legs with registered M-1/M-3 or statutory reason codes.
pub fn reconcile_book_to_book(input: &BookToBookInput) -> Result<BookToBookBridge, ConcordatError> {
    match input.layered_kind {
        BookKind::AdjustmentLayer {
            parent_book_id,
            parent_known_at,
        } => {
            if parent_book_id != input.parent_book_id
                || input.parent_book_id == input.layered_book_id
            {
                return Err(ConcordatError::ParentBookMismatch {
                    expected_parent: input.parent_book_id,
                    layered_book: input.layered_book_id,
                });
            }
            if parent_known_at != input.parent_known_at {
                return Err(ConcordatError::ParentBookRestated {
                    parent_book_id: input.parent_book_id,
                    layer_parent_known_at: parent_known_at,
                    current_parent_known_at: input.parent_known_at,
                });
            }
        }
        BookKind::Primary => {
            return Err(ConcordatError::ParentBookMismatch {
                expected_parent: input.parent_book_id,
                layered_book: input.layered_book_id,
            });
        }
    }

    if input.units.is_empty() {
        return Err(ConcordatError::Input(
            "book-to-book reconciliation requires at least one unit".into(),
        ));
    }
    let units: BTreeSet<u32> = input.units.iter().copied().collect();
    if units.len() != input.units.len() {
        return Err(ConcordatError::Input(
            "duplicate unit in book-to-book input".into(),
        ));
    }

    let accounts: BTreeMap<u128, &Account> = input.accounts.iter().map(|a| (a.id, a)).collect();
    if accounts.len() != input.accounts.len() {
        return Err(ConcordatError::Input(
            "duplicate account ID in book-to-book input".into(),
        ));
    }

    // Verify each adjustment entry balances per (entry_id, unit_id).
    let mut entry_totals: BTreeMap<(u128, u32), (i128, i128)> = BTreeMap::new();
    for leg in &input.adjustments {
        if leg.debits < 0 || leg.credits < 0 {
            return Err(ConcordatError::Input(
                "adjustment leg debits and credits must be non-negative".into(),
            ));
        }
        if !units.contains(&leg.unit_id) {
            return Err(ConcordatError::Input(format!(
                "adjustment leg uses undeclared unit {}",
                leg.unit_id
            )));
        }
        let account = accounts.get(&leg.account_id).ok_or_else(|| {
            ConcordatError::Input(format!(
                "adjustment leg names unknown account {:032x}",
                leg.account_id
            ))
        })?;
        if !account.is_leaf {
            return Err(ConcordatError::Input(format!(
                "adjustment leg posts to summary account `{}`",
                account.code
            )));
        }
        let totals = entry_totals
            .entry((leg.entry_id, leg.unit_id))
            .or_insert((0, 0));
        totals.0 = totals
            .0
            .checked_add(leg.debits)
            .ok_or(ConcordatError::Overflow("adjustment entry debits"))?;
        totals.1 = totals
            .1
            .checked_add(leg.credits)
            .ok_or(ConcordatError::Overflow("adjustment entry credits"))?;
    }
    for ((entry_id, unit_id), (debits, credits)) in entry_totals {
        if debits != credits {
            return Err(ConcordatError::UnbalancedAdjustment {
                entry_id,
                unit_id,
                debits,
                credits,
            });
        }
    }

    let fold_side = |balances: &[AccountBalance],
                     label: &str|
     -> Result<BTreeMap<(u128, u32), i128>, ConcordatError> {
        let mut out = BTreeMap::new();
        for b in balances {
            let account = accounts.get(&b.account_id).ok_or_else(|| {
                ConcordatError::Input(format!(
                    "{label} balance names unknown account {:032x}",
                    b.account_id
                ))
            })?;
            if !account.is_leaf {
                return Err(ConcordatError::Input(format!(
                    "{label} balance names summary account `{}`",
                    account.code
                )));
            }
            if !units.contains(&b.unit_id) {
                return Err(ConcordatError::Input(format!(
                    "{label} balance uses undeclared unit {}",
                    b.unit_id
                )));
            }
            let net = checked_net(b.debits, b.credits)?;
            if out.insert((b.account_id, b.unit_id), net).is_some() {
                return Err(ConcordatError::Input(format!(
                    "duplicate {label} balance for account `{}` unit {}",
                    account.code, b.unit_id
                )));
            }
        }
        Ok(out)
    };

    let parent_map = fold_side(&input.parent_balances, "parent")?;
    let layered_map = fold_side(&input.layered_balances, "layered")?;

    let mut explanations_by_cell: BTreeMap<(u128, u32), Vec<BridgeExplanation>> = BTreeMap::new();
    for leg in &input.adjustments {
        let net_delta = checked_net(leg.debits, leg.credits)?;
        if net_delta == 0 {
            continue;
        }
        explanations_by_cell
            .entry((leg.account_id, leg.unit_id))
            .or_default()
            .push(BridgeExplanation {
                entry_id: leg.entry_id,
                rule_version_oid: leg.rule_version_oid,
                reason_code: leg.reason_code,
                net_delta,
            });
    }

    let mut all_keys: BTreeSet<(u128, u32)> = BTreeSet::new();
    all_keys.extend(parent_map.keys().copied());
    all_keys.extend(layered_map.keys().copied());
    all_keys.extend(explanations_by_cell.keys().copied());

    let mut rows = Vec::with_capacity(all_keys.len());
    for (account_id, unit_id) in all_keys {
        let account = accounts[&account_id];
        let parent_net = parent_map.get(&(account_id, unit_id)).copied().unwrap_or(0);
        let layered_net = layered_map
            .get(&(account_id, unit_id))
            .copied()
            .unwrap_or(0);
        let mut explanations = explanations_by_cell
            .remove(&(account_id, unit_id))
            .unwrap_or_default();
        explanations.sort_by(|a, b| {
            a.entry_id
                .cmp(&b.entry_id)
                .then(a.rule_version_oid.0.cmp(&b.rule_version_oid.0))
                .then(a.reason_code.cmp(&b.reason_code))
                .then(a.net_delta.cmp(&b.net_delta))
        });
        let mut adjustments_net = 0i128;
        for exp in &explanations {
            adjustments_net = adjustments_net
                .checked_add(exp.net_delta)
                .ok_or(ConcordatError::Overflow("adjustments_net sum"))?;
        }
        let expected_layered = parent_net
            .checked_add(adjustments_net)
            .ok_or(ConcordatError::Overflow("parent_net + adjustments_net"))?;
        let residual = layered_net
            .checked_sub(expected_layered)
            .ok_or(ConcordatError::Overflow("book-to-book residual"))?;
        if residual != 0 {
            return Err(ConcordatError::UnexplainedBookDifference {
                account_code: account.code.clone(),
                unit_id,
                parent_net,
                adjustments_net,
                layered_net,
                residual,
            });
        }
        rows.push(BookToBookBridgeRow {
            account_id,
            account_code: account.code.clone(),
            unit_id,
            parent_net,
            adjustments_net,
            layered_net,
            explanations,
        });
    }

    rows.sort_by(|a, b| {
        a.account_code
            .cmp(&b.account_code)
            .then(a.account_id.cmp(&b.account_id))
            .then(a.unit_id.cmp(&b.unit_id))
    });

    Ok(BookToBookBridge {
        parent_book_id: input.parent_book_id,
        parent_known_at: input.parent_known_at,
        layered_book_id: input.layered_book_id,
        layered_known_at: input.layered_known_at,
        rows,
    })
}

/// Match declared reciprocal intercompany pairs across member entities (`FA-INV-13`).
///
/// Every reciprocal pair must either net to zero (`entity_a_net + entity_b_net == 0`) or
/// carry an explicit difference leg on its declared `difference_account` within `max_fx_residual`.
pub fn match_intercompany_pairs(
    members: &[EntityMemberInput],
    pairs: &[IntercompanyPairSpec],
    units: &[u32],
) -> Result<Vec<MatchedIntercompanyPair>, ConcordatError> {
    if pairs.len() > MAX_IC_PAIRS {
        return Err(ConcordatError::Input(
            "intercompany pairs exceed bound".into(),
        ));
    }
    let mut member_nets: BTreeMap<(Id128, u128, u32), i128> = BTreeMap::new();
    let mut known_entities = BTreeSet::new();
    for member in members {
        if !known_entities.insert(member.entity_id) {
            return Err(ConcordatError::Input(format!(
                "duplicate member entity {}",
                member.entity_id.to_hex()
            )));
        }
        for b in &member.balances {
            let net = checked_net(b.debits, b.credits)?;
            if member_nets
                .insert((member.entity_id, b.account_id, b.unit_id), net)
                .is_some()
            {
                return Err(ConcordatError::Input(format!(
                    "duplicate balance for entity {} account {:032x} unit {}",
                    member.entity_id.to_hex(),
                    b.account_id,
                    b.unit_id
                )));
            }
        }
    }

    let mut sorted_pairs: Vec<&IntercompanyPairSpec> = pairs.iter().collect();
    sorted_pairs.sort_by(|a, b| a.pair_code.cmp(&b.pair_code));
    for w in sorted_pairs.windows(2) {
        if w[0].pair_code == w[1].pair_code {
            return Err(ConcordatError::Input(format!(
                "duplicate intercompany pair code `{}`",
                w[0].pair_code
            )));
        }
    }

    let mut sorted_units = units.to_vec();
    sorted_units.sort_unstable();
    sorted_units.dedup();

    let mut matched = Vec::new();
    for spec in sorted_pairs {
        if spec.pair_code.trim().is_empty() {
            return Err(ConcordatError::Input(
                "intercompany pair_code must be non-empty".into(),
            ));
        }
        if spec.entity_a == spec.entity_b {
            return Err(ConcordatError::Input(format!(
                "intercompany pair `{}` must connect two distinct entities",
                spec.pair_code
            )));
        }
        if !known_entities.contains(&spec.entity_a) || !known_entities.contains(&spec.entity_b) {
            return Err(ConcordatError::Input(format!(
                "intercompany pair `{}` references an entity outside the consolidation group",
                spec.pair_code
            )));
        }
        if spec.max_fx_residual < 0 {
            return Err(ConcordatError::Input(format!(
                "intercompany pair `{}` has negative max_fx_residual",
                spec.pair_code
            )));
        }
        for &unit_id in &sorted_units {
            let a_net = member_nets
                .get(&(spec.entity_a, spec.account_a, unit_id))
                .copied()
                .unwrap_or(0);
            let b_net = member_nets
                .get(&(spec.entity_b, spec.account_b, unit_id))
                .copied()
                .unwrap_or(0);
            let raw_residual = a_net
                .checked_add(b_net)
                .ok_or(ConcordatError::Overflow("intercompany pair sum"))?;
            let difference_leg = if raw_residual == 0 {
                None
            } else {
                let Some(diff_acct) = spec.difference_account else {
                    return Err(ConcordatError::UnmatchedIntercompanyPair {
                        pair_code: spec.pair_code.clone(),
                        unit_id,
                        entity_a: spec.entity_a,
                        entity_b: spec.entity_b,
                        entity_a_net: a_net,
                        entity_b_net: b_net,
                        residual: raw_residual,
                    });
                };
                if raw_residual.unsigned_abs() > spec.max_fx_residual.unsigned_abs() {
                    return Err(ConcordatError::UnmatchedIntercompanyPair {
                        pair_code: spec.pair_code.clone(),
                        unit_id,
                        entity_a: spec.entity_a,
                        entity_b: spec.entity_b,
                        entity_a_net: a_net,
                        entity_b_net: b_net,
                        residual: raw_residual,
                    });
                }
                // To eliminate a_net and b_net cleanly, the difference leg takes `raw_residual`
                // (debit if raw_residual > 0, credit if raw_residual < 0).
                Some((diff_acct, raw_residual))
            };
            if a_net != 0 || b_net != 0 || difference_leg.is_some() {
                matched.push(MatchedIntercompanyPair {
                    pair_code: spec.pair_code.clone(),
                    kind: spec.kind,
                    unit_id,
                    entity_a: spec.entity_a,
                    account_a: spec.account_a,
                    entity_a_net: a_net,
                    entity_b: spec.entity_b,
                    account_b: spec.account_b,
                    entity_b_net: b_net,
                    difference_leg,
                });
            }
        }
    }
    Ok(matched)
}

fn push_reversing_leg(
    legs: &mut Vec<EliminationLeg>,
    entity_id: Id128,
    account_id: u128,
    unit_id: u32,
    net_to_eliminate: i128,
) {
    if net_to_eliminate > 0 {
        // Account has a net debit balance; credit it to eliminate.
        legs.push(EliminationLeg {
            entity_id,
            account_id,
            unit_id,
            debits: 0,
            credits: net_to_eliminate,
        });
    } else if net_to_eliminate < 0 {
        // Account has a net credit balance; debit it to eliminate.
        legs.push(EliminationLeg {
            entity_id,
            account_id,
            unit_id,
            debits: net_to_eliminate
                .checked_neg()
                .expect("checked_net cannot produce i128::MIN from non-negative debits/credits"),
            credits: 0,
        });
    }
}

/// Execute a deterministic consolidation run over member entity folds (`plan §12.3`, `FA-INV-13.core`).
///
/// Steps:
/// 1. Validates member inputs, accounts, units, and the ownership graph.
/// 2. Matches all declared `intercompany_pairs` (`match_intercompany_pairs`), refusing any
///    unmatched pair or FX residual outside the law's bound.
/// 3. Derives balanced `EliminationEntry` records for each matched intercompany pair and for
///    each parent-subsidiary ownership link (eliminating subsidiary equity against the parent's
///    investment account and recognizing Non-Controlling Interest under the registered `RoundingLaw`).
/// 4. Aggregates member balances + elimination legs, evaluates the consolidated Balance Sheet
///    and Income Statement via `evaluate`, and proves consolidated equity conservation (`FA-INV-13.core`).
pub fn consolidate(input: &ConsolidationInput) -> Result<ConsolidationRun, ConcordatError> {
    if input.members.is_empty() || input.members.len() > MAX_ENTITIES {
        return Err(ConcordatError::Input(
            "consolidation requires 1..=1024 member entities".into(),
        ));
    }
    if input.units.is_empty() {
        return Err(ConcordatError::Input(
            "consolidation requires at least one unit".into(),
        ));
    }
    let mut units = input.units.clone();
    units.sort_unstable();
    if units.windows(2).any(|w| w[0] == w[1]) {
        return Err(ConcordatError::Input(
            "duplicate unit in consolidation input".into(),
        ));
    }

    let accounts: BTreeMap<u128, &Account> = input.accounts.iter().map(|a| (a.id, a)).collect();
    if accounts.len() != input.accounts.len() {
        return Err(ConcordatError::Input(
            "duplicate account in consolidation input".into(),
        ));
    }

    let matched_pairs =
        match_intercompany_pairs(&input.members, &input.intercompany_pairs, &units)?;

    // Index member net balances (debits - credits) per (entity_id, account_id, unit_id).
    let mut member_nets: BTreeMap<(Id128, u128, u32), i128> = BTreeMap::new();
    let mut known_entities = BTreeSet::new();
    for member in &input.members {
        known_entities.insert(member.entity_id);
        for b in &member.balances {
            let account = accounts.get(&b.account_id).ok_or_else(|| {
                ConcordatError::Input(format!(
                    "member {} balance names unknown account {:032x}",
                    member.entity_id.to_hex(),
                    b.account_id
                ))
            })?;
            if !account.is_leaf {
                return Err(ConcordatError::Input(format!(
                    "member {} balance names summary account `{}`",
                    member.entity_id.to_hex(),
                    account.code
                )));
            }
            if !units.contains(&b.unit_id) {
                return Err(ConcordatError::Input(format!(
                    "member {} balance uses undeclared unit {}",
                    member.entity_id.to_hex(),
                    b.unit_id
                )));
            }
            let net = checked_net(b.debits, b.credits)?;
            member_nets.insert((member.entity_id, b.account_id, b.unit_id), net);
        }
    }

    let mut eliminations = Vec::new();
    // 1. Derive intercompany pair eliminations.
    for pair in &matched_pairs {
        let mut legs = Vec::new();
        push_reversing_leg(
            &mut legs,
            pair.entity_a,
            pair.account_a,
            pair.unit_id,
            pair.entity_a_net,
        );
        push_reversing_leg(
            &mut legs,
            pair.entity_b,
            pair.account_b,
            pair.unit_id,
            pair.entity_b_net,
        );
        if let Some((diff_acct, diff_delta)) = pair.difference_leg {
            let account = accounts.get(&diff_acct).ok_or_else(|| {
                ConcordatError::Input(format!(
                    "intercompany pair `{}` difference account {:032x} is unknown",
                    pair.pair_code, diff_acct
                ))
            })?;
            if !account.is_leaf {
                return Err(ConcordatError::Input(format!(
                    "intercompany pair `{}` difference account `{}` is a summary account",
                    pair.pair_code, account.code
                )));
            }
            if diff_delta > 0 {
                legs.push(EliminationLeg {
                    entity_id: pair.entity_a,
                    account_id: diff_acct,
                    unit_id: pair.unit_id,
                    debits: diff_delta,
                    credits: 0,
                });
            } else if diff_delta < 0 {
                legs.push(EliminationLeg {
                    entity_id: pair.entity_a,
                    account_id: diff_acct,
                    unit_id: pair.unit_id,
                    debits: 0,
                    credits: diff_delta.checked_neg().ok_or(ConcordatError::Overflow(
                        "intercompany difference leg negation",
                    ))?,
                });
            }
        }
        let entry = EliminationEntry {
            code: format!("ELIM-IC-{}-U{}", pair.pair_code, pair.unit_id),
            description: format!(
                "Eliminate intercompany pair `{}` between {} and {}",
                pair.pair_code,
                pair.entity_a.to_hex(),
                pair.entity_b.to_hex()
            ),
            unit_id: pair.unit_id,
            legs,
        };
        if !entry.is_balanced() {
            return Err(ConcordatError::Input(format!(
                "derived intercompany elimination `{}` is not balanced",
                entry.code
            )));
        }
        eliminations.push(entry);
    }

    // 2. Validate ownership graph and derive investment-vs-subsidiary-equity eliminations.
    let mut sorted_ownership: Vec<&OwnershipSpec> = input.ownership.iter().collect();
    sorted_ownership.sort_by(|a, b| {
        a.parent_entity
            .0
            .cmp(&b.parent_entity.0)
            .then(a.subsidiary_entity.0.cmp(&b.subsidiary_entity.0))
    });
    let mut seen_subsidiaries = BTreeSet::new();
    let mut nci_recognized_by_unit: BTreeMap<u32, i128> = BTreeMap::new();
    let mut eliminated_sub_equity_by_unit: BTreeMap<u32, i128> = BTreeMap::new();

    for spec in &sorted_ownership {
        if spec.parent_entity == spec.subsidiary_entity {
            return Err(ConcordatError::Input(
                "an entity cannot own itself in consolidation".into(),
            ));
        }
        if !seen_subsidiaries.insert(spec.subsidiary_entity) {
            return Err(ConcordatError::Input(format!(
                "duplicate ownership specification for subsidiary {}",
                spec.subsidiary_entity.to_hex()
            )));
        }
        if !known_entities.contains(&spec.parent_entity)
            || !known_entities.contains(&spec.subsidiary_entity)
        {
            return Err(ConcordatError::Input(
                "ownership specification references an entity outside members".into(),
            ));
        }
        if spec.ownership_bps == 0 || i128::from(spec.ownership_bps) > BPS_DENOMINATOR {
            return Err(ConcordatError::Input(format!(
                "ownership_bps {} must be in 1..=10000",
                spec.ownership_bps
            )));
        }
        if spec.subsidiary_equity_account_ids.is_empty() {
            return Err(ConcordatError::Input(
                "ownership specification requires at least one subsidiary equity account".into(),
            ));
        }
        for &unit_id in &units {
            let inv_net = member_nets
                .get(&(spec.parent_entity, spec.investment_account_id, unit_id))
                .copied()
                .unwrap_or(0);
            let mut sub_equity_credit = 0i128;
            let mut legs = Vec::new();
            for &eq_acct in &spec.subsidiary_equity_account_ids {
                let net = member_nets
                    .get(&(spec.subsidiary_entity, eq_acct, unit_id))
                    .copied()
                    .unwrap_or(0);
                // Equity is credit-normal: credit balance is `-net`.
                let credit_bal = net
                    .checked_neg()
                    .ok_or(ConcordatError::Overflow("subsidiary equity negation"))?;
                sub_equity_credit = sub_equity_credit
                    .checked_add(credit_bal)
                    .ok_or(ConcordatError::Overflow("subsidiary equity sum"))?;
                // Eliminate subsidiary equity account (debit if credit_bal > 0).
                push_reversing_leg(&mut legs, spec.subsidiary_entity, eq_acct, unit_id, net);
            }
            if inv_net == 0 && sub_equity_credit == 0 {
                continue;
            }
            let controlling_share =
                round_bps_share(sub_equity_credit, spec.ownership_bps, spec.rounding_law)?;
            let nci_share = sub_equity_credit
                .checked_sub(controlling_share)
                .ok_or(ConcordatError::Overflow("nci share subtraction"))?;
            if inv_net != controlling_share {
                return Err(ConcordatError::InvestmentEquityMismatch {
                    subsidiary_entity: spec.subsidiary_entity,
                    unit_id,
                    investment_balance: inv_net,
                    expected_controlling_equity: controlling_share,
                });
            }
            // Credit parent's investment account by `controlling_share`.
            push_reversing_leg(
                &mut legs,
                spec.parent_entity,
                spec.investment_account_id,
                unit_id,
                inv_net,
            );
            if nci_share != 0 {
                let nci_acct = spec.nci_equity_account_id.ok_or_else(|| {
                    ConcordatError::Input(format!(
                        "subsidiary {} has ownership {} bps (< 10000) and non-zero NCI {nci_share}, so nci_equity_account_id is required",
                        spec.subsidiary_entity.to_hex(),
                        spec.ownership_bps
                    ))
                })?;
                if nci_share > 0 {
                    legs.push(EliminationLeg {
                        entity_id: spec.subsidiary_entity,
                        account_id: nci_acct,
                        unit_id,
                        debits: 0,
                        credits: nci_share,
                    });
                } else {
                    legs.push(EliminationLeg {
                        entity_id: spec.subsidiary_entity,
                        account_id: nci_acct,
                        unit_id,
                        debits: nci_share
                            .checked_neg()
                            .ok_or(ConcordatError::Overflow("nci debit negation"))?,
                        credits: 0,
                    });
                }
                let entry_nci = nci_recognized_by_unit.entry(unit_id).or_insert(0);
                *entry_nci = entry_nci
                    .checked_add(nci_share)
                    .ok_or(ConcordatError::Overflow("nci total"))?;
            }
            let entry_elim = eliminated_sub_equity_by_unit.entry(unit_id).or_insert(0);
            *entry_elim = entry_elim
                .checked_sub(sub_equity_credit)
                .ok_or(ConcordatError::Overflow("eliminated sub equity total"))?;

            let entry = EliminationEntry {
                code: format!("ELIM-EQ-{}-U{}", spec.subsidiary_entity.to_hex(), unit_id),
                description: format!(
                    "Eliminate investment in subsidiary {} ({} bps) against subsidiary equity",
                    spec.subsidiary_entity.to_hex(),
                    spec.ownership_bps
                ),
                unit_id,
                legs,
            };
            if !entry.is_balanced() {
                return Err(ConcordatError::Input(format!(
                    "derived equity elimination `{}` is not balanced",
                    entry.code
                )));
            }
            eliminations.push(entry);
        }
    }

    // Aggregate member debits/credits + elimination legs per (account_id, unit_id).
    let mut consolidated_totals: BTreeMap<(u128, u32), (i128, i128)> = BTreeMap::new();
    for member in &input.members {
        for b in &member.balances {
            let slot = consolidated_totals
                .entry((b.account_id, b.unit_id))
                .or_insert((0, 0));
            slot.0 = slot
                .0
                .checked_add(b.debits)
                .ok_or(ConcordatError::Overflow("consolidated debits"))?;
            slot.1 = slot
                .1
                .checked_add(b.credits)
                .ok_or(ConcordatError::Overflow("consolidated credits"))?;
        }
    }
    for elim in &eliminations {
        for leg in &elim.legs {
            let slot = consolidated_totals
                .entry((leg.account_id, leg.unit_id))
                .or_insert((0, 0));
            slot.0 = slot
                .0
                .checked_add(leg.debits)
                .ok_or(ConcordatError::Overflow("consolidated elimination debits"))?;
            slot.1 = slot
                .1
                .checked_add(leg.credits)
                .ok_or(ConcordatError::Overflow("consolidated elimination credits"))?;
        }
    }

    // Verify that every matched intercompany account nets to zero in the consolidated totals.
    for pair in &matched_pairs {
        for acct in [pair.account_a, pair.account_b] {
            let (d, c) = consolidated_totals
                .get(&(acct, pair.unit_id))
                .copied()
                .unwrap_or((0, 0));
            if d != c {
                return Err(ConcordatError::Input(format!(
                    "intercompany account {:032x} in pair `{}` did not eliminate to zero ({d} != {c})",
                    acct, pair.pair_code
                )));
            }
        }
    }

    let consolidated_balances: Vec<AccountBalance> = consolidated_totals
        .into_iter()
        .map(
            |((account_id, unit_id), (debits, credits))| AccountBalance {
                account_id,
                unit_id,
                debits,
                credits,
            },
        )
        .collect();

    let bs_def = StatementDefinition::embedded("balance-sheet")?;
    let is_def = StatementDefinition::embedded("income-statement")?;

    let bs_input = StatementInput {
        book_id: input.consolidation_book_id,
        branch_id: input.branch_id,
        known_at: input.known_at,
        accounts: input.accounts.clone(),
        units: units.clone(),
        columns: vec![ColumnInput {
            label: input.period.clone(),
            periods: vec![input.period.clone()],
            effective_from: None,
            effective_through: input.effective_through,
            balances: consolidated_balances.clone(),
        }],
    };
    let is_input = StatementInput {
        book_id: input.consolidation_book_id,
        branch_id: input.branch_id,
        known_at: input.known_at,
        accounts: input.accounts.clone(),
        units: units.clone(),
        columns: vec![ColumnInput {
            label: input.period.clone(),
            periods: vec![input.period.clone()],
            effective_from: Some(input.effective_through),
            effective_through: input.effective_through,
            balances: consolidated_balances,
        }],
    };

    let balance_sheet = evaluate(&bs_def, &bs_input)?;
    let income_statement = evaluate(&is_def, &is_input)?;

    // Compute per-entity standalone total equity (Equity + Revenue - Expense, credit-normal)
    // and verify the FA-INV-13 consolidated equity conservation law per unit.
    let subsidiary_ids: BTreeSet<Id128> = sorted_ownership
        .iter()
        .map(|s| s.subsidiary_entity)
        .collect();

    let entity_total_equity = |entity_id: Id128, unit_id: u32| -> Result<i128, ConcordatError> {
        let mut total = 0i128;
        for (&(ent, acct_id, u), &net) in &member_nets {
            if ent != entity_id || u != unit_id {
                continue;
            }
            let acct_type = accounts[&acct_id].account_type;
            // Equity (3), Revenue (4), Expense (5) all contribute to total equity (credit - debit = -net).
            if matches!(acct_type, 3..=5) {
                let credit_contribution = net
                    .checked_neg()
                    .ok_or(ConcordatError::Overflow("entity equity contribution"))?;
                total = total
                    .checked_add(credit_contribution)
                    .ok_or(ConcordatError::Overflow("entity equity sum"))?;
            }
        }
        Ok(total)
    };

    // Net P&L / difference impact of intercompany eliminations per unit.
    let ic_equity_impact = |unit_id: u32| -> Result<i128, ConcordatError> {
        let mut total = 0i128;
        for elim in &eliminations {
            if elim.unit_id != unit_id || !elim.code.starts_with("ELIM-IC-") {
                continue;
            }
            for leg in &elim.legs {
                let acct_type = accounts[&leg.account_id].account_type;
                if matches!(acct_type, 3..=5) {
                    let net = checked_net(leg.debits, leg.credits)?;
                    let credit_contribution = net
                        .checked_neg()
                        .ok_or(ConcordatError::Overflow("ic equity impact"))?;
                    total = total
                        .checked_add(credit_contribution)
                        .ok_or(ConcordatError::Overflow("ic equity impact sum"))?;
                }
            }
        }
        Ok(total)
    };

    let mut equity_reconciliations = Vec::with_capacity(units.len());
    for &unit_id in &units {
        let mut parent_total_equity = 0i128;
        let mut subsidiaries_total_equity = 0i128;
        for member in &input.members {
            let eq = entity_total_equity(member.entity_id, unit_id)?;
            if subsidiary_ids.contains(&member.entity_id) {
                subsidiaries_total_equity = subsidiaries_total_equity
                    .checked_add(eq)
                    .ok_or(ConcordatError::Overflow("subsidiaries_total_equity"))?;
            } else {
                parent_total_equity = parent_total_equity
                    .checked_add(eq)
                    .ok_or(ConcordatError::Overflow("parent_total_equity"))?;
            }
        }
        let nci_eq = nci_recognized_by_unit.get(&unit_id).copied().unwrap_or(0);
        let sub_eq_elim = eliminated_sub_equity_by_unit
            .get(&unit_id)
            .copied()
            .unwrap_or(0);
        let ic_eq_elim = ic_equity_impact(unit_id)?;
        let equity_eliminations = sub_eq_elim
            .checked_add(ic_eq_elim)
            .ok_or(ConcordatError::Overflow("equity_eliminations"))?;

        let expected_consolidated_equity = parent_total_equity
            .checked_add(subsidiaries_total_equity)
            .and_then(|v| v.checked_add(equity_eliminations))
            .and_then(|v| v.checked_add(nci_eq))
            .ok_or(ConcordatError::Overflow("expected_consolidated_equity"))?;

        let actual_consolidated_equity = balance_sheet
            .lines
            .iter()
            .find(|l| l.code == "total_equity" && l.unit_id == unit_id)
            .map(|l| l.amounts[0])
            .ok_or_else(|| {
                ConcordatError::Input("consolidated balance sheet missing total_equity line".into())
            })?;

        if expected_consolidated_equity != actual_consolidated_equity {
            return Err(ConcordatError::EquityReconciliationFailure {
                unit_id,
                expected_consolidated_equity,
                actual_consolidated_equity,
            });
        }

        let controlling_interest_equity = actual_consolidated_equity
            .checked_sub(nci_eq)
            .ok_or(ConcordatError::Overflow("controlling_interest_equity"))?;

        equity_reconciliations.push(ConsolidatedEquityReconciliation {
            unit_id,
            parent_total_equity,
            subsidiaries_total_equity,
            equity_eliminations,
            non_controlling_interest_equity: nci_eq,
            controlling_interest_equity,
            consolidated_total_equity: actual_consolidated_equity,
        });
    }

    Ok(ConsolidationRun {
        consolidation_book_id: input.consolidation_book_id,
        branch_id: input.branch_id,
        known_at: input.known_at,
        period: input.period.clone(),
        matched_pairs,
        eliminations,
        equity_reconciliations,
        balance_sheet,
        income_statement,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_time::DateDay;

    fn account(id: u128, code: &str, name: &str, account_type: u8) -> Account {
        Account {
            id,
            code: code.into(),
            name: name.into(),
            account_type,
            is_leaf: true,
        }
    }

    fn bal(account_id: u128, unit_id: u32, debits: i128, credits: i128) -> AccountBalance {
        AccountBalance {
            account_id,
            unit_id,
            debits,
            credits,
        }
    }

    fn consolidation_chart() -> Vec<Account> {
        vec![
            account(1000, "1000", "Cash", 1),
            account(1300, "1300", "Intercompany Due From Sub", 1),
            account(1500, "1500", "Investment in Subsidiary", 1),
            account(2000, "2000", "Accounts Payable", 2),
            account(2300, "2300", "Intercompany Due To Parent", 2),
            account(3000, "3000", "Common Stock", 3),
            account(3100, "3100", "Subsidiary Common Stock", 3),
            account(3200, "3200", "Non-Controlling Interest", 3),
            account(4000, "4000", "External Revenue", 4),
            account(4300, "4300", "Intercompany Revenue", 4),
            account(5000, "5000", "Operating Expense", 5),
            account(5300, "5300", "Intercompany Expense", 5),
            account(5400, "5400", "Intercompany FX Difference", 5),
        ]
    }

    #[test]
    fn intercompany_pairs_eliminations_and_consolidated_equity_reconcile_exactly() {
        let parent = Id128([0x01; 16]);
        let sub = Id128([0x02; 16]);
        let group_book = Id128([0x10; 16]);

        // Parent (80% owner of Sub, Sub stock = 500 -> Parent investment = 400, NCI = 100):
        // Assets: Cash 1100 (Dr), IC Due From Sub 150 (Dr), Investment in Sub 400 (Dr) = 1650
        // Liabilities: AP 200 (Cr)
        // Equity: Common Stock 1000 (Cr)
        // Revenue: External 500 (Cr), IC Revenue 120 (Cr)
        // Expense: Operating 170 (Dr)
        // Check: Dr = 1100 + 150 + 400 + 170 = 1820; Cr = 200 + 1000 + 500 + 120 = 1820.
        let parent_member = EntityMemberInput {
            entity_id: parent,
            book_id: Id128([0x0a; 16]),
            known_at: 42,
            balances: vec![
                bal(1000, 1, 1_100, 0),
                bal(1300, 1, 150, 0),
                bal(1500, 1, 400, 0),
                bal(2000, 1, 0, 200),
                bal(3000, 1, 0, 1_000),
                bal(4000, 1, 0, 500),
                bal(4300, 1, 0, 120),
                bal(5000, 1, 170, 0),
            ],
        };

        // Subsidiary:
        // Assets: Cash 750 (Dr)
        // Liabilities: AP 50 (Cr), IC Due To Parent 150 (Cr)
        // Equity: Sub Common Stock 500 (Cr)
        // Revenue: External 250 (Cr)
        // Expense: Operating 80 (Dr), IC Expense 118 (Dr) [2 USD FX difference within bound 5]
        // Check: Dr = 750 + 80 + 118 = 948; Cr = 50 + 150 + 500 + 248 (let's make External Rev 248 so Dr==Cr).
        let sub_member = EntityMemberInput {
            entity_id: sub,
            book_id: Id128([0x0b; 16]),
            known_at: 42,
            balances: vec![
                bal(1000, 1, 750, 0),
                bal(2000, 1, 0, 50),
                bal(2300, 1, 0, 150),
                bal(3100, 1, 0, 500),
                bal(4000, 1, 0, 248),
                bal(5000, 1, 80, 0),
                bal(5300, 1, 118, 0),
            ],
        };

        let input = ConsolidationInput {
            consolidation_book_id: group_book,
            branch_id: Id128::TRUNK,
            known_at: 42,
            period: "FY2026-P03".into(),
            effective_through: DateDay(90),
            accounts: consolidation_chart(),
            units: vec![1],
            members: vec![parent_member, sub_member],
            intercompany_pairs: vec![
                IntercompanyPairSpec {
                    pair_code: "IC-AR-AP".into(),
                    kind: IntercompanyPairKind::ReciprocalReceivablePayable,
                    entity_a: parent,
                    account_a: 1300,
                    entity_b: sub,
                    account_b: 2300,
                    difference_account: None,
                    max_fx_residual: 0,
                },
                IntercompanyPairSpec {
                    pair_code: "IC-REV-EXP".into(),
                    kind: IntercompanyPairKind::ReciprocalRevenueExpense,
                    entity_a: parent,
                    account_a: 4300,
                    entity_b: sub,
                    account_b: 5300,
                    difference_account: Some(5400),
                    max_fx_residual: 5,
                },
            ],
            ownership: vec![OwnershipSpec {
                parent_entity: parent,
                subsidiary_entity: sub,
                ownership_bps: 8_000,
                investment_account_id: 1500,
                subsidiary_equity_account_ids: vec![3100],
                nci_equity_account_id: Some(3200),
                rounding_law: RoundingLaw::HalfEven,
            }],
        };

        let run = consolidate(&input).expect("consolidation succeeds");
        assert_eq!(run.matched_pairs.len(), 2);
        assert_eq!(run.eliminations.len(), 3);
        assert!(run.eliminations.iter().all(EliminationEntry::is_balanced));

        // Consolidated Cash = 1100 + 750 = 1850; IC Due From & Investment in Sub eliminated to 0!
        let bs_line = |code: &str| -> i128 {
            run.balance_sheet
                .lines
                .iter()
                .find(|l| l.code == code && l.unit_id == 1)
                .unwrap()
                .amounts[0]
        };
        let is_line = |code: &str| -> i128 {
            run.income_statement
                .lines
                .iter()
                .find(|l| l.code == code && l.unit_id == 1)
                .unwrap()
                .amounts[0]
        };
        assert_eq!(bs_line("assets"), 1_850);
        assert_eq!(bs_line("liabilities"), 250);
        // Equity = Parent Common Stock (1000) + NCI (100) = 1100
        assert_eq!(bs_line("equity"), 1_100);
        // Consolidated Net Income = External Rev (500 + 248 = 748) - Operating Exp (170 + 80 = 250) + IC FX Gain (2) = 500
        assert_eq!(is_line("revenue"), 748);
        assert_eq!(is_line("expense"), 248);
        assert_eq!(is_line("net_income"), 500);
        assert_eq!(bs_line("unclosed_earnings"), 500);
        assert_eq!(bs_line("total_equity"), 1_600);
        assert_eq!(bs_line("balance_check"), 0);

        let eq = &run.equity_reconciliations[0];
        assert_eq!(eq.parent_total_equity, 1_450); // 1000 stock + (620 rev - 170 exp)
        assert_eq!(eq.subsidiaries_total_equity, 550); // 500 stock + (248 rev - 198 exp)
        assert_eq!(eq.equity_eliminations, -500); // -500 sub stock + 0 net P&L impact (IC rev 120 Dr, IC exp 118 Cr, FX diff 2 Cr)
        assert_eq!(eq.non_controlling_interest_equity, 100);
        assert_eq!(eq.controlling_interest_equity, 1_500);
        assert_eq!(eq.consolidated_total_equity, 1_600);

        // Determinism: permuting member and balance order yields identical canonical bytes and digest.
        let digest_a = run.digest().unwrap();
        let mut permuted = input.clone();
        permuted.members.reverse();
        permuted.members[0].balances.reverse();
        permuted.intercompany_pairs.reverse();
        let run_b = consolidate(&permuted).unwrap();
        assert_eq!(
            run.canonical_bytes().unwrap(),
            run_b.canonical_bytes().unwrap()
        );
        assert_eq!(digest_a, run_b.digest().unwrap());
    }

    #[test]
    fn book_to_book_bridge_explains_every_difference_by_rule_version_and_m1_m3_reason() {
        let parent_book = Id128([0x21; 16]);
        let tax_book = Id128([0x22; 16]);
        let depreciation_rule = Oid([0xa1; 32]);
        let meals_rule = Oid([0xb2; 32]);
        let accounts = vec![
            account(1000, "1000", "Cash", 1),
            account(1600, "1600", "Accumulated Depreciation", 1),
            account(3000, "3000", "Retained Earnings", 3),
            account(5100, "5100", "Meals and Entertainment", 5),
            account(5200, "5200", "Depreciation Expense", 5),
        ];

        let input = BookToBookInput {
            parent_book_id: parent_book,
            parent_known_at: 15,
            layered_book_id: tax_book,
            layered_kind: BookKind::AdjustmentLayer {
                parent_book_id: parent_book,
                parent_known_at: 15,
            },
            layered_known_at: 19,
            accounts,
            units: vec![1],
            parent_balances: vec![
                bal(1000, 1, 1_000, 0),
                bal(1600, 1, 0, 100),
                bal(3000, 1, 0, 1_060),
                bal(5100, 1, 60, 0),
                bal(5200, 1, 100, 0),
            ],
            // Tax adjustments:
            // 1. 50% of Meals (30) disallowed permanently -> Cr 5100 (30), Dr 3000 (30)
            // 2. Bonus MACRS depreciation (+80) -> Dr 5200 (80), Cr 1600 (80)
            layered_balances: vec![
                bal(1000, 1, 1_000, 0),
                bal(1600, 1, 0, 180),
                bal(3000, 1, 0, 1_030),
                bal(5100, 1, 30, 0),
                bal(5200, 1, 180, 0),
            ],
            adjustments: vec![
                AdjustmentLayerLeg {
                    entry_id: 1,
                    rule_version_oid: meals_rule,
                    reason_code: BookToBookReasonCode::M1PermanentMealsEntertainment,
                    account_id: 3000,
                    unit_id: 1,
                    debits: 30,
                    credits: 0,
                },
                AdjustmentLayerLeg {
                    entry_id: 1,
                    rule_version_oid: meals_rule,
                    reason_code: BookToBookReasonCode::M1PermanentMealsEntertainment,
                    account_id: 5100,
                    unit_id: 1,
                    debits: 0,
                    credits: 30,
                },
                AdjustmentLayerLeg {
                    entry_id: 2,
                    rule_version_oid: depreciation_rule,
                    reason_code: BookToBookReasonCode::M1TemporaryDepreciation,
                    account_id: 5200,
                    unit_id: 1,
                    debits: 80,
                    credits: 0,
                },
                AdjustmentLayerLeg {
                    entry_id: 2,
                    rule_version_oid: depreciation_rule,
                    reason_code: BookToBookReasonCode::M1TemporaryDepreciation,
                    account_id: 1600,
                    unit_id: 1,
                    debits: 0,
                    credits: 80,
                },
            ],
        };

        let bridge = reconcile_book_to_book(&input).expect("bridge reconciles");
        assert_eq!(bridge.rows.len(), 5);
        let meals_row = bridge
            .rows
            .iter()
            .find(|r| r.account_code == "5100")
            .unwrap();
        assert_eq!(meals_row.parent_net, 60);
        assert_eq!(meals_row.adjustments_net, -30);
        assert_eq!(meals_row.layered_net, 30);
        assert_eq!(meals_row.explanations.len(), 1);
        assert!(meals_row.explanations[0].reason_code.is_permanent());

        let encoded = bridge.canonical_bytes().unwrap();
        let decoded = BookToBookBridge::decode(&encoded).unwrap();
        assert_eq!(bridge, decoded);
        assert_eq!(bridge.digest().unwrap(), decoded.digest().unwrap());
    }

    #[test]
    fn unmatched_intercompany_pair_and_unexplained_bridge_or_restated_parent_are_refused() {
        let parent = Id128([0x01; 16]);
        let sub = Id128([0x02; 16]);
        let members = vec![
            EntityMemberInput {
                entity_id: parent,
                book_id: Id128([0x0a; 16]),
                known_at: 10,
                balances: vec![bal(1300, 1, 200, 0), bal(3000, 1, 0, 200)],
            },
            EntityMemberInput {
                entity_id: sub,
                book_id: Id128([0x0b; 16]),
                known_at: 10,
                balances: vec![bal(1000, 1, 140, 0), bal(2300, 1, 0, 140)],
            },
        ];

        // 1. Unmatched intercompany pair without difference account -> refused naming pair and residual 60.
        let unmatched = match_intercompany_pairs(
            &members,
            &[IntercompanyPairSpec {
                pair_code: "IC-AR-AP".into(),
                kind: IntercompanyPairKind::ReciprocalReceivablePayable,
                entity_a: parent,
                account_a: 1300,
                entity_b: sub,
                account_b: 2300,
                difference_account: None,
                max_fx_residual: 0,
            }],
            &[1],
        )
        .unwrap_err();
        assert!(matches!(
            unmatched,
            ConcordatError::UnmatchedIntercompanyPair {
                ref pair_code,
                residual: 60,
                ..
            } if pair_code == "IC-AR-AP"
        ));

        // 2. Difference exceeds max_fx_residual -> refused even when difference_account is supplied.
        let over_bound = match_intercompany_pairs(
            &members,
            &[IntercompanyPairSpec {
                pair_code: "IC-AR-AP".into(),
                kind: IntercompanyPairKind::ReciprocalReceivablePayable,
                entity_a: parent,
                account_a: 1300,
                entity_b: sub,
                account_b: 2300,
                difference_account: Some(5400),
                max_fx_residual: 10,
            }],
            &[1],
        )
        .unwrap_err();
        assert!(matches!(
            over_bound,
            ConcordatError::UnmatchedIntercompanyPair { residual: 60, .. }
        ));

        // 3. Parent restatement invalidates AdjustmentLayer until propagated.
        let bridge_input = BookToBookInput {
            parent_book_id: parent,
            parent_known_at: 25, // Parent restated at seq 25!
            layered_book_id: sub,
            layered_kind: BookKind::AdjustmentLayer {
                parent_book_id: parent,
                parent_known_at: 15, // Layer still anchored to seq 15
            },
            layered_known_at: 19,
            accounts: vec![account(1000, "1000", "Cash", 1)],
            units: vec![1],
            parent_balances: vec![bal(1000, 1, 100, 0)],
            layered_balances: vec![bal(1000, 1, 100, 0)],
            adjustments: vec![],
        };
        assert!(matches!(
            reconcile_book_to_book(&bridge_input),
            Err(ConcordatError::ParentBookRestated {
                layer_parent_known_at: 15,
                current_parent_known_at: 25,
                ..
            })
        ));

        // 4. Unexplained difference between parent and layered book -> refused with exact residual.
        let mut unexplained = bridge_input;
        unexplained.parent_known_at = 15;
        unexplained.layered_balances = vec![bal(1000, 1, 175, 0)];
        assert!(matches!(
            reconcile_book_to_book(&unexplained),
            Err(ConcordatError::UnexplainedBookDifference {
                ref account_code,
                residual: 75,
                ..
            }) if account_code == "1000"
        ));
    }
}
