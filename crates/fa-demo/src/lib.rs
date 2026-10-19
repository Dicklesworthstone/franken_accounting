//! Seeded, deterministic demo books (`fa demo init --scenario <name> --seed <u64>`,
//! plan §15.3, convergence gate `G3-02`, bead `fa-v6j`).
//!
//! Creates a complete, self-contained book directory with:
//! - Deterministic `BookKeys` (`<dir>/book.keys`, mode `0600`) and `BookSpec`
//!   seeded from `("fa:demo:v1", scenario, seed)`.
//! - Embedded chart of accounts (`us-gaap-smb` or `us-bank-call-report`).
//! - Full 12-month fiscal calendar for `FY2026` (`FY2026-OPEN`, `FY2026-P01`..`P12`,
//!   `FY2026-A1`, `FY2026-CLOSE`) with period lifecycle transitions (`FY2026-P01`
//!   `Closed`, `FY2026-P02` `Locked` with independent SoD approval, `FY2026-P03`..`P12`
//!   `Open`).
//! - Content-addressed `Document` evidence (`HumanUpload` and an `AgentUpload`
//!   with an independent `Reviewed` attestation).
//! - A finalized `MigrationRun` (`go-live-2026`, `OpeningOnly`, 2-principal SoD
//!   approvals on both chunk staging and finalization).
//! - Customer invoices and open-item settlement receipts, vendor bills and
//!   settlements, a two-phase `Pending` hold and its `Resolution`, and an
//!   auto-reversing `Adjusting` accrual with a verified `ReversalSchedule`.
//! - Scenario-specific planted forensic facts (`retail`, `bank`, `ponzi`,
//!   `shell-network`, `worldcom`, `channel-stuffing`, `ghost-payroll`).
//! - Materialized period registers (`advance_registers`) and a signed Notary
//!   transparency checkpoint (`checkpoint`).
//! - A generated `<dir>/README.md` cataloging the book identity, checkpoint
//!   digest, period states, migration run, planted facts with exact entry VIds,
//!   and ready-to-run `fa` CLI commands.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};

use fa::book::{Book, BookError, BookKeys, Entropy};
use fa_journal::{
    AccountSpec, Approved, BookSpec, Capability, Document, PostRequest, Refusal, RunBody,
    RunControlRequest, RunMode, TimeZonePolicy, TrialBalanceLine, UnitPolicy, with_auto_reverse,
};
use fa_model::{
    AccountType, Disposition, EntryClass, EntryOrigin, EntryPayload, EntryRef, ExternalId, Id128,
    LegPayload, Oid, Pending, PeriodRef, Settlement, account_vid, domain_digest, principal_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::{CommitSeq, VId};

const US_GAAP_SMB_TEXT: &str = include_str!("../../../templates/charts/us-gaap-smb.json");
const US_BANK_CALL_REPORT_TEXT: &str =
    include_str!("../../../templates/charts/us-bank-call-report.json");

/// Supported demo scenarios (`fa demo init --scenario <name>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scenario {
    /// Multi-period retail SMB book (`us-gaap-smb`) with migration, settlements,
    /// two-phase hold/resolution, auto-reversing accrual, closed/locked periods,
    /// and a planted duplicate vendor payment.
    Retail,
    /// Bank book (`us-bank-call-report`) with a planted 3-account kiting float loop.
    Bank,
    /// Investment book (`us-gaap-smb`) with investor inflow recycling and
    /// below-threshold structuring splits.
    Ponzi,
    /// Multi-counterparty book (`us-gaap-smb`) with a circular round-trip transfer chain.
    ShellNetwork,
    /// Telecom-style book (`us-gaap-smb`) with a weekend round-dollar line-cost
    /// capitalization into fixed assets.
    WorldCom,
    /// Distribution book (`us-gaap-smb`) with quarter-end revenue cutoff stuffing.
    ChannelStuffing,
    /// Payroll book (`us-gaap-smb`) with repeated duplicate ghost-employee disbursements.
    GhostPayroll,
}

/// Canonical CLI names of all supported demo scenarios.
pub const SCENARIO_NAMES: &[&str] = &[
    "retail",
    "bank",
    "ponzi",
    "shell-network",
    "worldcom",
    "channel-stuffing",
    "ghost-payroll",
];

impl Scenario {
    pub const ALL: [Self; 7] = [
        Self::Retail,
        Self::Bank,
        Self::Ponzi,
        Self::ShellNetwork,
        Self::WorldCom,
        Self::ChannelStuffing,
        Self::GhostPayroll,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retail => "retail",
            Self::Bank => "bank",
            Self::Ponzi => "ponzi",
            Self::ShellNetwork => "shell-network",
            Self::WorldCom => "worldcom",
            Self::ChannelStuffing => "channel-stuffing",
            Self::GhostPayroll => "ghost-payroll",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "retail" | "clean-retailer" => Some(Self::Retail),
            "bank" | "kiting" | "kiting-loop" => Some(Self::Bank),
            "ponzi" | "ponzi-funnel" => Some(Self::Ponzi),
            "shell-network" | "shell_network" => Some(Self::ShellNetwork),
            "worldcom" | "worldcom-capex" => Some(Self::WorldCom),
            "channel-stuffing" | "channel_stuffing" => Some(Self::ChannelStuffing),
            "ghost-payroll" | "ghost_payroll" => Some(Self::GhostPayroll),
            _ => None,
        }
    }

    #[must_use]
    pub const fn book_name(self) -> &'static str {
        match self {
            Self::Retail => "Northwind Retail Demo Co.",
            Self::Bank => "First Charter Demo Bank N.A.",
            Self::Ponzi => "Meridian Yield Demo Fund LLC",
            Self::ShellNetwork => "Atlas Conduit Holdings Demo Ltd.",
            Self::WorldCom => "WorldTel Line Systems Demo Corp.",
            Self::ChannelStuffing => "Apex Distribution Demo Inc.",
            Self::GhostPayroll => "Harbor Logistics Payroll Demo Co.",
        }
    }

    #[must_use]
    pub const fn chart_template(self) -> &'static str {
        match self {
            Self::Bank => "us-bank-call-report",
            _ => "us-gaap-smb",
        }
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One planted accounting or forensic fact documented in the demo book's README
/// and returned in the `demo_initialized` robot event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlantedFact {
    pub id: String,
    pub kind: String,
    pub period: String,
    pub entry_vids: Vec<VId>,
    pub summary: String,
}

/// Summary of a newly initialized demo book (`fa demo init`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DemoInitialized {
    pub book_id: Id128,
    pub dir: PathBuf,
    pub keys: PathBuf,
    pub readme: PathBuf,
    pub scenario: Scenario,
    pub seed: u64,
    pub name: String,
    pub base_unit: String,
    pub calendar: String,
    pub chart_template: String,
    pub accounts: usize,
    pub periods: usize,
    pub documents: usize,
    pub entries: usize,
    pub migration_run_vid: VId,
    pub checkpoint_oid: Oid,
    pub journal_digest: [u8; 32],
    pub head_seq: CommitSeq,
    pub planted_facts: Vec<PlantedFact>,
}

/// Errors returned while constructing a demo book.
#[derive(Debug)]
pub enum DemoError {
    Book(BookError),
    Refusal(Refusal),
    Verification(String),
}

impl fmt::Display for DemoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Book(e) => write!(f, "{e}"),
            Self::Refusal(r) => write!(f, "{}: {}", r.code, r.message),
            Self::Verification(m) => write!(f, "demo self-verification failed: {m}"),
        }
    }
}

impl core::error::Error for DemoError {}

impl From<BookError> for DemoError {
    fn from(e: BookError) -> Self {
        Self::Book(e)
    }
}

impl From<fa_journal::KernelError> for DemoError {
    fn from(e: fa_journal::KernelError) -> Self {
        Self::Book(BookError::Kernel(e))
    }
}

impl From<Refusal> for DemoError {
    fn from(r: Refusal) -> Self {
        Self::Refusal(r)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn chart_key(template_text: &str) -> Vec<u8> {
    format!(
        "chart:{}",
        hex(&domain_digest(b"fa:chart:v1", &[template_text.as_bytes()])[..16])
    )
    .into_bytes()
}

fn derive_seeds(scenario: Scenario, seed: u64) -> (u64, u64, Id128) {
    let seed_le = seed.to_le_bytes();
    let d_keys = domain_digest(
        b"fa:demo:keys:v1",
        &[scenario.as_str().as_bytes(), &seed_le],
    );
    let d_book = domain_digest(
        b"fa:demo:book:v1",
        &[scenario.as_str().as_bytes(), &seed_le],
    );
    let d_id = domain_digest(b"fa:demo:id:v1", &[scenario.as_str().as_bytes(), &seed_le]);
    let mut k_bytes = [0u8; 8];
    k_bytes.copy_from_slice(&d_keys[..8]);
    let mut b_bytes = [0u8; 8];
    b_bytes.copy_from_slice(&d_book[..8]);
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&d_id[..16]);
    (
        u64::from_le_bytes(k_bytes),
        u64::from_le_bytes(b_bytes),
        Id128(id_bytes),
    )
}

fn spec_row(
    code: &str,
    name: &str,
    account_type: AccountType,
    is_leaf: bool,
    unit_policy: UnitPolicy,
    parent_code: Option<&str>,
) -> AccountSpec {
    let normal_balance = account_type.normal_balance().unwrap_or(0);
    AccountSpec {
        code: code.to_string(),
        name: name.to_string(),
        account_type: account_type.0,
        normal_balance,
        is_leaf,
        unit_policy,
        parent_code: parent_code.map(str::to_string),
        limit: None,
    }
}

/// The `us-gaap-smb` chart of accounts matching `templates/charts/us-gaap-smb.json`.
#[must_use]
pub fn us_gaap_smb_accounts(base_unit: UnitId) -> Vec<AccountSpec> {
    let any = UnitPolicy::AnyUnit;
    let base = UnitPolicy::Single(base_unit);
    use AccountType as T;
    vec![
        spec_row("1", "Assets", T::ASSET, false, any, None),
        spec_row(
            "1000",
            "Cash and cash equivalents",
            T::ASSET,
            false,
            any,
            Some("1"),
        ),
        spec_row(
            "1010",
            "Operating checking",
            T::ASSET,
            true,
            base,
            Some("1000"),
        ),
        spec_row("1020", "Savings", T::ASSET, true, base, Some("1000")),
        spec_row("1030", "Petty cash", T::ASSET, true, base, Some("1000")),
        spec_row(
            "1200",
            "Accounts receivable",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1250",
            "Allowance for credit losses (contra-asset)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row("1300", "Inventory", T::ASSET, true, base, Some("1")),
        spec_row("1400", "Prepaid expenses", T::ASSET, true, base, Some("1")),
        spec_row(
            "1500",
            "Property and equipment",
            T::ASSET,
            false,
            any,
            Some("1"),
        ),
        spec_row("1510", "Equipment", T::ASSET, true, base, Some("1500")),
        spec_row(
            "1520",
            "Furniture and fixtures",
            T::ASSET,
            true,
            base,
            Some("1500"),
        ),
        spec_row("1530", "Vehicles", T::ASSET, true, base, Some("1500")),
        spec_row(
            "1590",
            "Accumulated depreciation (contra-asset)",
            T::ASSET,
            true,
            base,
            Some("1500"),
        ),
        spec_row("1900", "Other assets", T::ASSET, true, base, Some("1")),
        spec_row("2", "Liabilities", T::LIABILITY, false, any, None),
        spec_row(
            "2000",
            "Accounts payable",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2100",
            "Credit cards payable",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2200",
            "Accrued liabilities",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2300",
            "Sales tax payable",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2400",
            "Payroll liabilities",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2500",
            "Deferred revenue",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2600",
            "Income taxes payable",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row("2700", "Notes payable", T::LIABILITY, true, base, Some("2")),
        spec_row("3", "Equity", T::EQUITY, false, any, None),
        spec_row(
            "3000",
            "Owner's capital or common stock",
            T::EQUITY,
            true,
            base,
            Some("3"),
        ),
        spec_row(
            "3100",
            "Additional paid-in capital",
            T::EQUITY,
            true,
            base,
            Some("3"),
        ),
        spec_row(
            "3200",
            "Retained earnings",
            T::EQUITY,
            true,
            base,
            Some("3"),
        ),
        spec_row(
            "3300",
            "Owner's draws or dividends",
            T::EQUITY,
            true,
            base,
            Some("3"),
        ),
        spec_row("4", "Revenue", T::REVENUE, false, any, None),
        spec_row("4000", "Sales revenue", T::REVENUE, true, base, Some("4")),
        spec_row("4100", "Service revenue", T::REVENUE, true, base, Some("4")),
        spec_row(
            "4500",
            "Sales returns and discounts (contra-revenue)",
            T::REVENUE,
            true,
            base,
            Some("4"),
        ),
        spec_row("4900", "Other income", T::REVENUE, true, base, Some("4")),
        spec_row("5", "Cost of goods sold", T::EXPENSE, false, any, None),
        spec_row(
            "5000",
            "Cost of goods sold",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row(
            "5100",
            "Freight and delivery in",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row("6", "Operating expenses", T::EXPENSE, false, any, None),
        spec_row("6000", "Rent", T::EXPENSE, true, base, Some("6")),
        spec_row(
            "6100",
            "Salaries and wages",
            T::EXPENSE,
            true,
            base,
            Some("6"),
        ),
        spec_row("6150", "Payroll taxes", T::EXPENSE, true, base, Some("6")),
        spec_row("6200", "Utilities", T::EXPENSE, true, base, Some("6")),
        spec_row("6300", "Insurance", T::EXPENSE, true, base, Some("6")),
        spec_row("6400", "Office supplies", T::EXPENSE, true, base, Some("6")),
        spec_row(
            "6500",
            "Professional fees",
            T::EXPENSE,
            true,
            base,
            Some("6"),
        ),
        spec_row(
            "6600",
            "Advertising and marketing",
            T::EXPENSE,
            true,
            base,
            Some("6"),
        ),
        spec_row(
            "6700",
            "Depreciation expense",
            T::EXPENSE,
            true,
            base,
            Some("6"),
        ),
        spec_row(
            "6800",
            "Bank and merchant fees",
            T::EXPENSE,
            true,
            base,
            Some("6"),
        ),
        spec_row(
            "6900",
            "Travel and meals",
            T::EXPENSE,
            true,
            base,
            Some("6"),
        ),
        spec_row("7", "Other expenses", T::EXPENSE, false, any, None),
        spec_row(
            "7000",
            "Interest expense",
            T::EXPENSE,
            true,
            base,
            Some("7"),
        ),
        spec_row(
            "7100",
            "Income tax expense",
            T::EXPENSE,
            true,
            base,
            Some("7"),
        ),
    ]
}

/// The `us-bank-call-report` chart of accounts matching `templates/charts/us-bank-call-report.json`.
#[must_use]
pub fn us_bank_call_report_accounts(base_unit: UnitId) -> Vec<AccountSpec> {
    let any = UnitPolicy::AnyUnit;
    let base = UnitPolicy::Single(base_unit);
    use AccountType as T;
    vec![
        spec_row("1", "Assets (Schedule RC)", T::ASSET, false, any, None),
        spec_row(
            "1110",
            "Noninterest-bearing balances and currency and coin (RC 1.a)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1120",
            "Interest-bearing balances (RC 1.b)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1210",
            "Held-to-maturity securities (RC 2.a)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1220",
            "Available-for-sale debt securities (RC 2.b)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1230",
            "Equity securities with readily determinable fair values not held for trading (RC 2.c)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1310",
            "Federal funds sold (RC 3.a)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1320",
            "Securities purchased under agreements to resell (RC 3.b)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1410",
            "Loans and leases held for sale (RC 4.a)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1420",
            "Loans and leases held for investment (RC 4.b)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1430",
            "Allowance for credit losses on loans and leases (RC 4.c, contra-asset)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1500",
            "Trading assets (RC 5)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1600",
            "Premises and fixed assets (RC 6)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1700",
            "Other real estate owned (RC 7)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1800",
            "Investments in unconsolidated subsidiaries and associated companies (RC 8)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1850",
            "Direct and indirect investments in real estate ventures (RC 9)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1900",
            "Intangible assets (RC 10)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "1950",
            "Other assets (RC 11)",
            T::ASSET,
            true,
            base,
            Some("1"),
        ),
        spec_row(
            "2",
            "Liabilities (Schedule RC)",
            T::LIABILITY,
            false,
            any,
            None,
        ),
        spec_row(
            "2110",
            "Deposits in domestic offices: noninterest-bearing (RC 13.a.1)",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2120",
            "Deposits in domestic offices: interest-bearing (RC 13.a.2)",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2210",
            "Federal funds purchased (RC 14.a)",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2220",
            "Securities sold under agreements to repurchase (RC 14.b)",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2300",
            "Trading liabilities (RC 15)",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2400",
            "Other borrowed money (RC 16)",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2500",
            "Subordinated notes and debentures (RC 19)",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "2600",
            "Other liabilities (RC 20)",
            T::LIABILITY,
            true,
            base,
            Some("2"),
        ),
        spec_row(
            "3",
            "Equity capital (Schedule RC)",
            T::EQUITY,
            false,
            any,
            None,
        ),
        spec_row(
            "3100",
            "Perpetual preferred stock and related surplus (RC 23)",
            T::EQUITY,
            true,
            base,
            Some("3"),
        ),
        spec_row(
            "3200",
            "Common stock (RC 24)",
            T::EQUITY,
            true,
            base,
            Some("3"),
        ),
        spec_row("3300", "Surplus (RC 25)", T::EQUITY, true, base, Some("3")),
        spec_row(
            "3400",
            "Retained earnings (RC 26.a)",
            T::EQUITY,
            true,
            base,
            Some("3"),
        ),
        spec_row(
            "3500",
            "Accumulated other comprehensive income (RC 26.b)",
            T::EQUITY,
            true,
            base,
            Some("3"),
        ),
        spec_row(
            "3600",
            "Other equity capital components (RC 26.c)",
            T::EQUITY,
            true,
            base,
            Some("3"),
        ),
        spec_row(
            "3700",
            "Noncontrolling interests in consolidated subsidiaries (RC 27.b)",
            T::EQUITY,
            true,
            base,
            Some("3"),
        ),
        spec_row(
            "4",
            "Interest and noninterest income (Schedule RI)",
            T::REVENUE,
            false,
            any,
            None,
        ),
        spec_row(
            "4110",
            "Interest and fee income on loans (RI 1.a)",
            T::REVENUE,
            true,
            base,
            Some("4"),
        ),
        spec_row(
            "4140",
            "Interest income on balances due from depository institutions (RI 1.d)",
            T::REVENUE,
            true,
            base,
            Some("4"),
        ),
        spec_row(
            "4150",
            "Interest and dividend income on securities (RI 1.e)",
            T::REVENUE,
            true,
            base,
            Some("4"),
        ),
        spec_row(
            "4170",
            "Interest income on federal funds sold and securities purchased under agreements to resell (RI 1.g)",
            T::REVENUE,
            true,
            base,
            Some("4"),
        ),
        spec_row(
            "4510",
            "Income from fiduciary activities (RI 5.a)",
            T::REVENUE,
            true,
            base,
            Some("4"),
        ),
        spec_row(
            "4520",
            "Service charges on deposit accounts (RI 5.b)",
            T::REVENUE,
            true,
            base,
            Some("4"),
        ),
        spec_row(
            "4530",
            "Trading revenue (RI 5.c)",
            T::REVENUE,
            true,
            base,
            Some("4"),
        ),
        spec_row(
            "4590",
            "Other noninterest income (RI 5.l)",
            T::REVENUE,
            true,
            base,
            Some("4"),
        ),
        spec_row(
            "4610",
            "Realized gains (losses) on held-to-maturity securities (RI 6.a)",
            T::REVENUE,
            true,
            base,
            Some("4"),
        ),
        spec_row(
            "4620",
            "Realized gains (losses) on available-for-sale debt securities (RI 6.b)",
            T::REVENUE,
            true,
            base,
            Some("4"),
        ),
        spec_row(
            "5",
            "Interest and noninterest expense (Schedule RI)",
            T::EXPENSE,
            false,
            any,
            None,
        ),
        spec_row(
            "5210",
            "Interest on deposits (RI 2.a)",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row(
            "5220",
            "Expense of federal funds purchased and securities sold under agreements to repurchase (RI 2.b)",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row(
            "5230",
            "Interest on trading liabilities and other borrowed money (RI 2.c)",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row(
            "5240",
            "Interest on subordinated notes and debentures (RI 2.d)",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row(
            "5400",
            "Provision for credit losses (RI 4)",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row(
            "5710",
            "Salaries and employee benefits (RI 7.a)",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row(
            "5720",
            "Expenses of premises and fixed assets (RI 7.b)",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row(
            "5730",
            "Goodwill impairment losses (RI 7.c.1)",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row(
            "5740",
            "Amortization expense and impairment losses for other intangible assets (RI 7.c.2)",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row(
            "5790",
            "Other noninterest expense (RI 7.d)",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
        spec_row(
            "5900",
            "Applicable income taxes (RI 9)",
            T::EXPENSE,
            true,
            base,
            Some("5"),
        ),
    ]
}

fn add_doc(
    book: &mut Book,
    kind: u8,
    mime: &str,
    grade: u8,
    retrieved_by: VId,
    text: String,
) -> Result<Document, DemoError> {
    let doc = Document {
        book_id: book.context().book_id,
        kind,
        mime: mime.to_string(),
        grade,
        retrieved_by,
        bytes: text.into_bytes(),
    };
    book.add_document(&doc)??;
    Ok(doc)
}

#[allow(clippy::too_many_arguments)]
fn build_proposal(
    book: &Book,
    class: EntryClass,
    effective_date: DateDay,
    document_date: Option<DateDay>,
    key: &str,
    description: &str,
    principal: VId,
    legs: Vec<LegPayload>,
    evidence: Vec<fa_model::EvidenceRef>,
    pending: Option<Pending>,
    external_ids: &[(&str, &str)],
    _tags: &[(&str, &str)],
) -> Result<EntryPayload, DemoError> {
    let mut ext = Vec::with_capacity(external_ids.len());
    for (sys, id) in external_ids {
        ext.push(ExternalId {
            system: (*sys).to_string(),
            id: book.seal_text(id)?,
        });
    }
    ext.sort_by(|a, b| {
        a.system
            .cmp(&b.system)
            .then_with(|| a.id.field_digest().cmp(&b.id.field_digest()))
    });

    let intent_oid = Oid(domain_digest(b"fa:demo:intent:v1", &[key.as_bytes()]));
    let unit_totals =
        EntryPayload::fold_unit_totals(&legs).map_err(fa_journal::KernelError::from)?;
    Ok(EntryPayload {
        schema_minor: 0,
        book_id: book.context().book_id,
        branch_id: Id128::TRUNK,
        class,
        effective_date,
        document_date,
        description: book.seal_text(description)?,
        effective_period: None,
        legs,
        control: None,
        unit_totals,
        base_totals: None,
        idempotency_key: key.as_bytes().to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid,
            intent_kind: 1,
        },
        principal_ref: principal,
        session_ref: None,
        evidence,
        supersession: Vec::new(),
        pending,
        external_ids: ext,
        extensions: Vec::new(),
        tags: Vec::new(),
    })
}

fn post_proposal(
    book: &mut Book,
    proposal: EntryPayload,
    principal: VId,
    ops: &[&str],
    approvals: Vec<fa_model::ApprovalRef>,
) -> Result<EntryRef, DemoError> {
    let capability =
        Capability::embedded(principal, ops).map_err(|e| BookError::KeyFile(e.to_string()))?;
    let posted = book.post(PostRequest {
        proposal,
        approvals,
        plan_certificate: None,
        capability,
    })??;
    Ok(posted.entry_ref())
}

fn two_principal_approvals(
    book: &mut Book,
    proposal: &EntryPayload,
    approver_1: VId,
    approver_2: VId,
) -> Result<Vec<fa_model::ApprovalRef>, DemoError> {
    let digest = proposal
        .proposal_digest()
        .map_err(fa_journal::KernelError::Model)?;
    let mut out = Vec::with_capacity(2);
    for p in [approver_1, approver_2] {
        let cap =
            Capability::embedded(p, &["approve"]).map_err(|e| BookError::KeyFile(e.to_string()))?;
        let approved: Approved = book.approve(cap, digest)??;
        out.push(approved.approval());
    }
    Ok(out)
}

/// Initialize a deterministic demo book at `dir` (and its key file at `keys_file`)
/// for `(scenario, seed)`, returning the full [`DemoInitialized`] summary and
/// writing `<dir>/README.md`.
pub fn init_dir(
    dir: &Path,
    keys_file: &Path,
    scenario: Scenario,
    seed: u64,
) -> Result<DemoInitialized, DemoError> {
    let (key_seed, book_seed, book_id) = derive_seeds(scenario, seed);
    let key_entropy = Entropy::deterministic(key_seed);
    let book_entropy = Entropy::deterministic(book_seed);

    let units = UnitRegistry::embedded().map_err(BookError::Registry)?;
    let usd = units
        .lookup("USD")
        .ok_or_else(|| BookError::KeyFile("USD unit missing from registry".into()))?;
    let calendar = FiscalCalendar::monthly("US-FY", 1, 1).map_err(fa_journal::KernelError::from)?;
    let opening_date =
        DateDay::from_ymd(2026, 1, 1).map_err(|e| BookError::KeyFile(format!("{e:?}")))?;

    let spec = BookSpec {
        book_id,
        name: scenario.book_name().to_string(),
        base_unit: usd,
        calendar,
        time_zone_policy: Some(TimeZonePolicy::Utc),
        entities: Vec::new(),
        opening_date: Some(opening_date),
    };

    std::fs::create_dir_all(dir).map_err(|e| BookError::Io(dir.to_path_buf(), e))?;
    if let Some(parent) = keys_file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BookError::Io(parent.to_path_buf(), e))?;
    }
    let keys = BookKeys::generate(&key_entropy)?;
    keys.save(keys_file)?;
    let mut book = Book::create_dir(dir, keys, spec, book_entropy)?;

    let operator = principal_vid("operator");
    let controller = principal_vid("controller");
    let auditor = principal_vid("auditor");
    let agent = principal_vid("agent");

    // 1. Install chart of accounts from the scenario's template.
    let (template_text, chart_accounts) = match scenario {
        Scenario::Bank => (US_BANK_CALL_REPORT_TEXT, us_bank_call_report_accounts(usd)),
        _ => (US_GAAP_SMB_TEXT, us_gaap_smb_accounts(usd)),
    };
    let schema_cap = Capability::embedded(operator, &["schema_change"])
        .map_err(|e| BookError::KeyFile(e.to_string()))?;
    let installed = book.install_chart(
        &chart_accounts,
        operator,
        opening_date,
        &chart_key(template_text),
        &schema_cap,
    )??;

    // 2. Create FY2026 periods, lock `FY2026-OPEN` for Migration, and open `FY2026-P01`..`FY2026-P12`.
    let (_, period_defs) = book.create_periods(2026, operator, &schema_cap)??;
    let close_cap = Capability::embedded(controller, &["close"])
        .map_err(|e| BookError::KeyFile(e.to_string()))?;
    for (idx, transition) in [
        PeriodTransition::Open,
        PeriodTransition::SoftClose,
        PeriodTransition::Close,
    ]
    .into_iter()
    .enumerate()
    {
        book.transition_period(
            "FY2026-OPEN",
            transition,
            controller,
            1,
            opening_date,
            format!("demo:opening-{idx}:FY2026-OPEN:s{seed}").as_bytes(),
            &close_cap,
        )??;
    }
    let lock_plan = book.plan_transition(
        "FY2026-OPEN",
        PeriodTransition::Lock,
        controller,
        1,
        opening_date,
        format!("demo:lock:FY2026-OPEN:s{seed}").as_bytes(),
    )??;
    let lock_digest = book.plan_digest(&lock_plan)?;
    let lock_approval = book
        .approve(
            Capability::embedded(operator, &["approve"])
                .map_err(|e| BookError::KeyFile(e.to_string()))?,
            lock_digest,
        )??
        .approval();
    book.transition_planned(
        &lock_plan,
        PeriodTransition::Lock,
        &close_cap,
        &[lock_approval],
    )??;
    for m in 1..=12 {
        let code = format!("FY2026-P{m:02}");
        let start = DateDay::from_ymd(2026, m, 1)
            .map_err(|e| BookError::KeyFile(format!("period start: {e:?}")))?;
        book.transition_period(
            &code,
            PeriodTransition::Open,
            controller,
            1,
            start,
            format!("demo:open:{code}:s{seed}").as_bytes(),
            &close_cap,
        )??;
    }

    // 3. Record evidence documents (HumanUpload + AgentUpload with independent Review).
    let mut doc_count = 0usize;
    let tb_doc = add_doc(
        &mut book,
        18, // Spreadsheet
        "text/csv",
        3, // HumanUpload
        operator,
        format!(
            "scenario,seed,opening_date,unit\n{},{} ,2026-01-01,USD\n",
            scenario.as_str(),
            seed
        ),
    )?;
    doc_count += 1;

    let sales_doc = add_doc(
        &mut book,
        1, // Invoice
        "text/plain",
        3, // HumanUpload
        operator,
        format!(
            "Customer invoice schedule · scenario={} · seed={seed}\nINV-2026-101..104\n",
            scenario.as_str()
        ),
    )?;
    doc_count += 1;

    let rcpt_doc = add_doc(
        &mut book,
        8, // Remittance
        "text/plain",
        3, // HumanUpload
        operator,
        format!(
            "Customer remittance advice · scenario={} · seed={seed}\n",
            scenario.as_str()
        ),
    )?;
    doc_count += 1;

    let vendor_doc = add_doc(
        &mut book,
        2, // Bill
        "text/plain",
        4, // AgentUpload (self-sourced -> reviewed by controller against sales_doc)
        agent,
        format!(
            "Vendor bill & disbursement schedule · scenario={} · seed={seed}\n",
            scenario.as_str()
        ),
    )?;
    doc_count += 1;
    let review_cap = Capability::embedded(controller, &["approve"])
        .map_err(|e| BookError::KeyFile(e.to_string()))?;
    book.record_review(&review_cap, &vendor_doc.oid(), vec![sales_doc.oid()])??;

    let workpaper_doc = add_doc(
        &mut book,
        21, // Workpaper
        "text/plain",
        3, // HumanUpload
        controller,
        format!(
            "Period-end accrual and forensic workpaper · scenario={} · seed={seed}\n",
            scenario.as_str()
        ),
    )?;
    doc_count += 1;

    let po_doc = add_doc(
        &mut book,
        9, // PurchaseOrder
        "text/plain",
        3, // HumanUpload
        operator,
        format!(
            "Purchase order reservation PO-2026-07 · scenario={} · seed={seed}\n",
            scenario.as_str()
        ),
    )?;
    doc_count += 1;

    // 4. Open, stage, approve, and finalize the opening MigrationRun in `FY2026-OPEN`.
    let (cash_code, ar_code, inv_code, eq_code, ap_code, cap_code, re_code, rev_code, exp_code) =
        match scenario {
            Scenario::Bank => (
                "1110", "1420", "1120", "1600", "2110", "3200", "3400", "4110", "5720",
            ),
            _ => (
                "1010", "1200", "1300", "1510", "2000", "3000", "3200", "4000", "6000",
            ),
        };
    let seed_bump = ((seed % 11) as i128) * 10_000; // deterministic $100.00 increments
    let open_cash = 25_000_000 + seed_bump; // $250,000.00 + bump
    let open_inv = 8_000_000; // $80,000.00
    let open_eq = 12_000_000; // $120,000.00
    let open_cap = 30_000_000; // $300,000.00
    let open_re = (open_cash + open_inv + open_eq) - open_cap;

    let tb_lines = vec![
        TrialBalanceLine {
            account_code: cash_code.into(),
            unit: usd,
            mantissa: open_cash,
        },
        TrialBalanceLine {
            account_code: inv_code.into(),
            unit: usd,
            mantissa: open_inv,
        },
        TrialBalanceLine {
            account_code: eq_code.into(),
            unit: usd,
            mantissa: open_eq,
        },
        TrialBalanceLine {
            account_code: cap_code.into(),
            unit: usd,
            mantissa: -open_cap,
        },
        TrialBalanceLine {
            account_code: re_code.into(),
            unit: usd,
            mantissa: -open_re,
        },
    ];
    let run_body = RunBody {
        book_id,
        run_key: "go-live-2026".into(),
        source_system: "legacy-erp".into(),
        mode: RunMode::OpeningOnly,
        trial_balance: tb_doc.oid(),
        opening_date,
        lines: tb_lines,
        periods: Vec::new(),
        detail_base: Vec::new(),
        sole_opening_source: false,
    };
    let open_mig_proposal = book.open_migration_proposal(
        operator,
        &run_body,
        vec![tb_doc.evidence_ref(1)],
        format!("demo:mig:open:s{seed}").as_bytes(),
        book.seal_text("Open go-live-2026 opening balance migration run")?,
    )?;
    let mig_cap = Capability::embedded(operator, &["post", "migrate"])
        .map_err(|e| BookError::KeyFile(e.to_string()))?;
    let mig_opened = book.open_migration_run(
        &run_body,
        RunControlRequest {
            proposal: open_mig_proposal,
            capability: mig_cap.clone(),
            approvals: Vec::new(),
        },
    )??;
    let migration_run_vid = mig_opened.run;

    let mig_legs = vec![
        LegPayload::simple(
            Side::Debit,
            account_vid(book_id, cash_code),
            Amount::new(usd, open_cash),
        ),
        LegPayload::simple(
            Side::Debit,
            account_vid(book_id, inv_code),
            Amount::new(usd, open_inv),
        ),
        LegPayload::simple(
            Side::Debit,
            account_vid(book_id, eq_code),
            Amount::new(usd, open_eq),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(book_id, cap_code),
            Amount::new(usd, open_cap),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(book_id, re_code),
            Amount::new(usd, open_re),
        ),
    ];
    let mig_chunk_proposal = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::MIGRATION,
        effective_date: opening_date,
        document_date: Some(opening_date),
        description: book.seal_text("Opening trial balance migration chunk (FY2026-OPEN)")?,
        effective_period: Some(PeriodRef {
            calendar: book.context().calendar.id.clone(),
            code: "FY2026-OPEN".into(),
        }),
        unit_totals: EntryPayload::fold_unit_totals(&mig_legs)
            .map_err(fa_journal::KernelError::from)?,
        legs: mig_legs,
        control: None,
        base_totals: None,
        idempotency_key: format!("demo:mig:chunk:s{seed}").into_bytes(),
        origin: EntryOrigin::Migration {
            run_ref: migration_run_vid,
            source_system: "legacy-erp".into(),
            source_id: book.seal_text("TB-OPEN-2026")?,
            source_recorded_at_ns: Some(1_767_225_600_000_000_000),
            source_entered_by: Some(book.seal_text("legacy_controller")?),
            source_approved_by: Some(book.seal_text("legacy_auditor")?),
            batch_oid: tb_doc.oid(),
        },
        principal_ref: operator,
        session_ref: None,
        evidence: vec![tb_doc.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let mig_chunk_approvals =
        two_principal_approvals(&mut book, &mig_chunk_proposal, controller, auditor)?;
    let mig_chunk_ref = post_proposal(
        &mut book,
        mig_chunk_proposal,
        operator,
        &["post", "migrate"],
        mig_chunk_approvals,
    )?;

    let finalize_proposal = book.plan_migration_transition(
        migration_run_vid,
        fa_journal::migration::kind::FINALIZE,
        operator,
        format!("demo:mig:finalize:s{seed}").as_bytes(),
        book.seal_text("Finalize go-live-2026 opening balance migration run")?,
    )??;
    let finalize_approvals =
        two_principal_approvals(&mut book, &finalize_proposal, controller, auditor)?;
    let mig_finalized = book.transition_migration_run(RunControlRequest {
        proposal: finalize_proposal,
        capability: mig_cap,
        approvals: finalize_approvals,
    })??;

    let mut planted_facts = Vec::new();
    let mut entry_count = 1usize; // mig_chunk_ref
    planted_facts.push(PlantedFact {
        id: "MIG-2026-OPEN".into(),
        kind: "MigrationRun".into(),
        period: "FY2026-OPEN".into(),
        entry_vids: vec![mig_chunk_ref.vid, mig_finalized.control_entry],
        summary: format!(
            "Finalized OpeningOnly MigrationRun `go-live-2026` ({:032x}) in FY2026-OPEN with 2-principal SoD approvals",
            migration_run_vid.0
        ),
    });

    // 5. Post operational activity across FY2026-P01 and FY2026-P02, then close P01 and lock P02.
    let p01_inv_day = DateDay::from_ymd(2026, 1, 12).unwrap();
    let p01_rcpt_day = DateDay::from_ymd(2026, 1, 24).unwrap();
    let p01_rent_day = DateDay::from_ymd(2026, 1, 28).unwrap();
    let p01_inv_amt = 1_850_000 + ((seed % 7) as i128) * 2_500; // ~$18,500.00
    let p01_inv_prop = build_proposal(
        &book,
        EntryClass::ORIGINAL,
        p01_inv_day,
        Some(p01_inv_day),
        &format!("demo:p01:inv-101:s{seed}"),
        "January customer invoice INV-2026-101 (CUST-ACME)",
        operator,
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, ar_code),
                Amount::new(usd, p01_inv_amt),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, rev_code),
                Amount::new(usd, p01_inv_amt),
            ),
        ],
        vec![sales_doc.evidence_ref(1)],
        None,
        &[("customer", "CUST-ACME"), ("invoice", "INV-2026-101")],
        &[("cycle", "order-to-cash")],
    )?;
    let p01_inv_ref = post_proposal(&mut book, p01_inv_prop, operator, &["post"], Vec::new())?;
    entry_count += 1;

    // Settle 100% of INV-2026-101 in P01.
    let p01_rcpt_prop = build_proposal(
        &book,
        EntryClass::ORIGINAL,
        p01_rcpt_day,
        Some(p01_rcpt_day),
        &format!("demo:p01:rcpt-101:s{seed}"),
        "January customer remittance settling INV-2026-101 (CUST-ACME)",
        operator,
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, cash_code),
                Amount::new(usd, p01_inv_amt),
            ),
            LegPayload {
                side: Side::Credit,
                account_ref: account_vid(book_id, ar_code),
                amount: Amount::new(usd, p01_inv_amt),
                base_amount: None,
                dimension_set: Vec::new(),
                settles: vec![Settlement {
                    target: p01_inv_ref,
                    ordinal: 0,
                    amount: Amount::new(usd, p01_inv_amt),
                }],
                memo: Some(book.seal_text("settles INV-2026-101")?),
            },
        ],
        vec![rcpt_doc.evidence_ref(1)],
        None,
        &[("customer", "CUST-ACME"), ("remittance", "RCPT-2026-101")],
        &[("cycle", "order-to-cash")],
    )?;
    let _p01_rcpt_ref = post_proposal(&mut book, p01_rcpt_prop, operator, &["post"], Vec::new())?;
    entry_count += 1;

    let p01_rent_prop = build_proposal(
        &book,
        EntryClass::ORIGINAL,
        p01_rent_day,
        Some(p01_rent_day),
        &format!("demo:p01:rent:s{seed}"),
        "January facility lease payment (VEND-METRO)",
        operator,
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, exp_code),
                Amount::new(usd, 350_000),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, cash_code),
                Amount::new(usd, 350_000),
            ),
        ],
        vec![vendor_doc.evidence_ref(1)],
        None,
        &[("vendor", "VEND-METRO"), ("bill", "BILL-2026-01")],
        &[("cycle", "procure-to-pay")],
    )?;
    let _p01_rent_ref = post_proposal(&mut book, p01_rent_prop, operator, &["post"], Vec::new())?;
    entry_count += 1;

    // P02 activity: customer invoice + partial receipt (leaving an open item on AR).
    let p02_inv_day = DateDay::from_ymd(2026, 2, 10).unwrap();
    let p02_rcpt_day = DateDay::from_ymd(2026, 2, 22).unwrap();
    let p02_inv_amt = 2_400_000; // $24,000.00
    let p02_rcpt_amt = 1_500_000; // $15,000.00 settled, $9,000.00 remains open
    let p02_inv_prop = build_proposal(
        &book,
        EntryClass::ORIGINAL,
        p02_inv_day,
        Some(p02_inv_day),
        &format!("demo:p02:inv-102:s{seed}"),
        "February customer invoice INV-2026-102 (CUST-BEACON)",
        operator,
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, ar_code),
                Amount::new(usd, p02_inv_amt),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, rev_code),
                Amount::new(usd, p02_inv_amt),
            ),
        ],
        vec![sales_doc.evidence_ref(1)],
        None,
        &[("customer", "CUST-BEACON"), ("invoice", "INV-2026-102")],
        &[("cycle", "order-to-cash")],
    )?;
    let p02_inv_ref = post_proposal(&mut book, p02_inv_prop, operator, &["post"], Vec::new())?;
    entry_count += 1;

    let p02_rcpt_prop = build_proposal(
        &book,
        EntryClass::ORIGINAL,
        p02_rcpt_day,
        Some(p02_rcpt_day),
        &format!("demo:p02:rcpt-102:s{seed}"),
        "February partial customer remittance on INV-2026-102 (CUST-BEACON)",
        operator,
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, cash_code),
                Amount::new(usd, p02_rcpt_amt),
            ),
            LegPayload {
                side: Side::Credit,
                account_ref: account_vid(book_id, ar_code),
                amount: Amount::new(usd, p02_rcpt_amt),
                base_amount: None,
                dimension_set: Vec::new(),
                settles: vec![Settlement {
                    target: p02_inv_ref,
                    ordinal: 0,
                    amount: Amount::new(usd, p02_rcpt_amt),
                }],
                memo: Some(book.seal_text("partial settlement of INV-2026-102")?),
            },
        ],
        vec![rcpt_doc.evidence_ref(1)],
        None,
        &[("customer", "CUST-BEACON"), ("remittance", "RCPT-2026-102")],
        &[("cycle", "order-to-cash")],
    )?;
    let _p02_rcpt_ref = post_proposal(&mut book, p02_rcpt_prop, operator, &["post"], Vec::new())?;
    entry_count += 1;

    // Transition FY2026-P01: Open -> SoftClosed -> Closed.
    let p01_end = DateDay::from_ymd(2026, 1, 31).unwrap();
    let p01_sc = book.transition_period(
        "FY2026-P01",
        PeriodTransition::SoftClose,
        controller,
        1,
        p01_end,
        format!("demo:p01:softclose:s{seed}").as_bytes(),
        &close_cap,
    )??;
    let p01_cl = book.transition_period(
        "FY2026-P01",
        PeriodTransition::Close,
        controller,
        1,
        p01_end,
        format!("demo:p01:close:s{seed}").as_bytes(),
        &close_cap,
    )??;
    planted_facts.push(PlantedFact {
        id: "PERIOD-CLOSED-P01".into(),
        kind: "PeriodLifecycle".into(),
        period: "FY2026-P01".into(),
        entry_vids: vec![p01_sc.control_entry, p01_cl.control_entry],
        summary: "FY2026-P01 transitioned Open -> SoftClosed -> Closed".into(),
    });

    // Transition FY2026-P02: Open -> SoftClosed -> Closed -> Locked (with independent SoD approval).
    let p02_end = DateDay::from_ymd(2026, 2, 28).unwrap();
    let p02_sc = book.transition_period(
        "FY2026-P02",
        PeriodTransition::SoftClose,
        controller,
        1,
        p02_end,
        format!("demo:p02:softclose:s{seed}").as_bytes(),
        &close_cap,
    )??;
    let p02_cl = book.transition_period(
        "FY2026-P02",
        PeriodTransition::Close,
        controller,
        1,
        p02_end,
        format!("demo:p02:close:s{seed}").as_bytes(),
        &close_cap,
    )??;
    let lock_plan = book.plan_transition(
        "FY2026-P02",
        PeriodTransition::Lock,
        controller,
        1,
        p02_end,
        format!("demo:p02:lock:s{seed}").as_bytes(),
    )??;
    let lock_digest = book.plan_digest(&lock_plan)?;
    let auditor_approve_cap = Capability::embedded(auditor, &["approve"])
        .map_err(|e| BookError::KeyFile(e.to_string()))?;
    let lock_approval: Approved = book.approve(auditor_approve_cap, lock_digest)??;
    let p02_lk = book.transition_planned(
        &lock_plan,
        PeriodTransition::Lock,
        &close_cap,
        &[lock_approval.approval()],
    )??;
    planted_facts.push(PlantedFact {
        id: "PERIOD-LOCKED-P02".into(),
        kind: "PeriodLifecycle".into(),
        period: "FY2026-P02".into(),
        entry_vids: vec![
            p02_sc.control_entry,
            p02_cl.control_entry,
            p02_lk.control_entry,
        ],
        summary:
            "FY2026-P02 transitioned Open -> SoftClosed -> Closed -> Locked (approved by auditor)"
                .into(),
    });

    // 6. FY2026-P03: Two-phase Pending hold and Resolution(Posts), plus auto-reversing Adjusting accrual.
    let hold_day = DateDay::from_ymd(2026, 3, 10).unwrap();
    let resolve_day = DateDay::from_ymd(2026, 3, 16).unwrap();
    let hold_prop = build_proposal(
        &book,
        EntryClass::PENDING,
        hold_day,
        Some(hold_day),
        &format!("demo:p03:hold-07:s{seed}"),
        "Purchase order reservation PO-2026-07 (850.00 USD reserved)",
        operator,
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, exp_code),
                Amount::new(usd, 85_000),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, cash_code),
                Amount::new(usd, 85_000),
            ),
        ],
        vec![po_doc.evidence_ref(1)],
        Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        }),
        &[("po", "PO-2026-07")],
        &[("workflow", "two-phase-hold")],
    )?;
    let hold_ref = post_proposal(&mut book, hold_prop, operator, &["post"], Vec::new())?;
    entry_count += 1;

    let resolve_prop = build_proposal(
        &book,
        EntryClass::RESOLUTION,
        resolve_day,
        Some(resolve_day),
        &format!("demo:p03:resolve-07:s{seed}"),
        "Resolve PO-2026-07 for 720.00 USD posted (releasing 130.00 USD)",
        operator,
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, exp_code),
                Amount::new(usd, 72_000),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, cash_code),
                Amount::new(usd, 72_000),
            ),
        ],
        Vec::new(),
        Some(Pending {
            timeout_ns: None,
            resolution_of: Some(hold_ref),
            disposition: Some(Disposition::Posts {
                source_ordinals: vec![0, 1],
            }),
        }),
        &[("po", "PO-2026-07")],
        &[("workflow", "two-phase-hold")],
    )?;
    let resolve_ref = post_proposal(&mut book, resolve_prop, operator, &["post"], Vec::new())?;
    entry_count += 1;
    planted_facts.push(PlantedFact {
        id: "HOLD-RES-2026-03".into(),
        kind: "TwoPhaseHoldResolution".into(),
        period: "FY2026-P03".into(),
        entry_vids: vec![hold_ref.vid, resolve_ref.vid],
        summary:
            "Pending reservation of 850.00 USD resolved at 720.00 USD posted (130.00 USD released)"
                .into(),
    });

    // Auto-reversing Adjusting accrual on 2026-03-31 scheduled to reverse on 2026-04-01.
    let accrual_day = DateDay::from_ymd(2026, 3, 31).unwrap();
    let reverse_on = DateDay::from_ymd(2026, 4, 1).unwrap();
    let accrual_liab_code = if scenario == Scenario::Bank {
        "2600"
    } else {
        "2200"
    };
    let accrual_base = build_proposal(
        &book,
        EntryClass::ADJUSTING,
        accrual_day,
        Some(accrual_day),
        &format!("demo:p03:accrual:s{seed}"),
        "March period-end utility accrual (auto-reverses 2026-04-01)",
        controller,
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, exp_code),
                Amount::new(usd, 145_000),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, accrual_liab_code),
                Amount::new(usd, 145_000),
            ),
        ],
        vec![workpaper_doc.evidence_ref(1)],
        None,
        &[("schedule", "ACCRUAL-2026-03")],
        &[("workflow", "auto-reverse")],
    )?;
    let accrual_prop = with_auto_reverse(accrual_base, reverse_on);
    let accrual_ref = post_proposal(&mut book, accrual_prop, controller, &["post"], Vec::new())?;
    entry_count += 1;
    planted_facts.push(PlantedFact {
        id: "ACCRUAL-REV-2026-03".into(),
        kind: "AutoReversingAccrual".into(),
        period: "FY2026-P03".into(),
        entry_vids: vec![accrual_ref.vid],
        summary:
            "Adjusting accrual of 1,450.00 USD on 2026-03-31 with bound ReversalSchedule for 2026-04-01"
                .into(),
    });

    // 7. Scenario-specific planted forensic anomalies in FY2026-P03.
    match scenario {
        Scenario::Retail => {
            // Vendor bill + duplicate vendor payments (same-day pair on 2026-03-18 + next-day repeat on 2026-03-19).
            let bill_day = DateDay::from_ymd(2026, 3, 12).unwrap();
            let pay_day_1 = DateDay::from_ymd(2026, 3, 18).unwrap();
            let pay_day_2 = DateDay::from_ymd(2026, 3, 19).unwrap();
            let bill_prop = build_proposal(
                &book,
                EntryClass::ORIGINAL,
                bill_day,
                Some(bill_day),
                &format!("demo:retail:bill-apex:s{seed}"),
                "Inventory replenishment bill BILL-APEX-884 (VEND-APEX)",
                operator,
                vec![
                    LegPayload::simple(
                        Side::Debit,
                        account_vid(book_id, inv_code),
                        Amount::new(usd, 425_000),
                    ),
                    LegPayload::simple(
                        Side::Credit,
                        account_vid(book_id, ap_code),
                        Amount::new(usd, 425_000),
                    ),
                ],
                vec![vendor_doc.evidence_ref(1)],
                None,
                &[("vendor", "VEND-APEX"), ("bill", "BILL-APEX-884")],
                &[("cycle", "procure-to-pay")],
            )?;
            let _bill_ref = post_proposal(&mut book, bill_prop, operator, &["post"], Vec::new())?;
            entry_count += 1;

            let mut dup_vids = Vec::with_capacity(3);
            for (idx, (day, suffix)) in [(pay_day_1, "a"), (pay_day_1, "b"), (pay_day_2, "c")]
                .into_iter()
                .enumerate()
            {
                let p = build_proposal(
                    &book,
                    EntryClass::ORIGINAL,
                    day,
                    Some(day),
                    &format!("demo:retail:dup-pay-{suffix}:s{seed}"),
                    &format!(
                        "Disbursement to VEND-APEX for BILL-APEX-884 (run #{})",
                        idx + 1
                    ),
                    operator,
                    vec![
                        LegPayload::simple(
                            Side::Debit,
                            account_vid(book_id, ap_code),
                            Amount::new(usd, 425_000),
                        ),
                        LegPayload::simple(
                            Side::Credit,
                            account_vid(book_id, cash_code),
                            Amount::new(usd, 425_000),
                        ),
                    ],
                    vec![vendor_doc.evidence_ref(1)],
                    None,
                    &[("vendor", "VEND-APEX"), ("bill", "BILL-APEX-884")],
                    &[("planted", "duplicate-vendor-payment")],
                )?;
                let r = post_proposal(&mut book, p, operator, &["post"], Vec::new())?;
                dup_vids.push(r.vid);
                entry_count += 1;
            }
            planted_facts.push(PlantedFact {
                id: "DUP-PAY-2026-03".into(),
                kind: "DuplicateVendorPayment".into(),
                period: "FY2026-P03".into(),
                entry_vids: dup_vids,
                summary:
                    "Planted duplicate vendor payments of 4,250.00 USD to VEND-APEX on 2026-03-18 and 2026-03-19"
                        .into(),
            });
        }
        Scenario::Bank => {
            // Interbank float loop across 1110, 1120, and 1310 on 2026-03-20..21:
            // 1110 -> 1120 -> 1310 -> 1120 -> 1110.
            let d1 = DateDay::from_ymd(2026, 3, 20).unwrap();
            let d2 = DateDay::from_ymd(2026, 3, 21).unwrap();
            let mut kite_vids = Vec::with_capacity(4);
            for (step, (from_acct, to_acct, day)) in [
                ("1110", "1120", d1),
                ("1120", "1310", d1),
                ("1310", "1120", d2),
                ("1120", "1110", d2),
            ]
            .into_iter()
            .enumerate()
            {
                let p = build_proposal(
                    &book,
                    EntryClass::ORIGINAL,
                    day,
                    Some(day),
                    &format!("demo:bank:kite-{step}:s{seed}"),
                    &format!(
                        "Interbank float transfer leg {} ({from_acct} -> {to_acct})",
                        step + 1
                    ),
                    operator,
                    vec![
                        LegPayload::simple(
                            Side::Debit,
                            account_vid(book_id, to_acct),
                            Amount::new(usd, 2_500_000),
                        ),
                        LegPayload::simple(
                            Side::Credit,
                            account_vid(book_id, from_acct),
                            Amount::new(usd, 2_500_000),
                        ),
                    ],
                    vec![workpaper_doc.evidence_ref(1)],
                    None,
                    &[("wire", &format!("KITE-2026-0{}", step + 1))],
                    &[("planted", "kiting-loop")],
                )?;
                kite_vids.push(post_proposal(&mut book, p, operator, &["post"], Vec::new())?.vid);
                entry_count += 1;
            }
            planted_facts.push(PlantedFact {
                id: "KITE-LOOP-2026-03".into(),
                kind: "KitingLoop".into(),
                period: "FY2026-P03".into(),
                entry_vids: kite_vids,
                summary:
                    "Planted interbank float round-trip cycle (1110 -> 1120 -> 1310 -> 1120 -> 1110) for 25,000.00 USD"
                        .into(),
            });
        }
        Scenario::Ponzi => {
            let d1 = DateDay::from_ymd(2026, 3, 25).unwrap();
            let d2 = DateDay::from_ymd(2026, 3, 26).unwrap();
            let mut ponzi_vids = Vec::new();
            let inflow = build_proposal(
                &book,
                EntryClass::ORIGINAL,
                d1,
                Some(d1),
                &format!("demo:ponzi:inflow:s{seed}"),
                "Tranche B investor subscription sweep into operating cash",
                operator,
                vec![
                    LegPayload::simple(
                        Side::Debit,
                        account_vid(book_id, "1010"),
                        Amount::new(usd, 3_000_000),
                    ),
                    LegPayload::simple(
                        Side::Credit,
                        account_vid(book_id, "1020"),
                        Amount::new(usd, 3_000_000),
                    ),
                ],
                vec![workpaper_doc.evidence_ref(1)],
                None,
                &[("investor", "INV-COHORT-B")],
                &[("planted", "ponzi-funnel")],
            )?;
            ponzi_vids.push(post_proposal(&mut book, inflow, operator, &["post"], Vec::new())?.vid);
            entry_count += 1;

            let payout = build_proposal(
                &book,
                EntryClass::ORIGINAL,
                d1,
                Some(d1),
                &format!("demo:ponzi:payout:s{seed}"),
                "Tranche A promised return redemption sweep",
                operator,
                vec![
                    LegPayload::simple(
                        Side::Debit,
                        account_vid(book_id, "1020"),
                        Amount::new(usd, 3_000_000),
                    ),
                    LegPayload::simple(
                        Side::Credit,
                        account_vid(book_id, "1010"),
                        Amount::new(usd, 3_000_000),
                    ),
                ],
                vec![workpaper_doc.evidence_ref(1)],
                None,
                &[("investor", "INV-COHORT-A")],
                &[("planted", "ponzi-funnel")],
            )?;
            ponzi_vids.push(post_proposal(&mut book, payout, operator, &["post"], Vec::new())?.vid);
            entry_count += 1;

            for (idx, cents) in [960_000i128, 955_000, 950_000].into_iter().enumerate() {
                let sp = build_proposal(
                    &book,
                    EntryClass::ORIGINAL,
                    d2,
                    Some(d2),
                    &format!("demo:ponzi:struct-{idx}:s{seed}"),
                    &format!("Split cash withdrawal #{idx} below CTR threshold"),
                    operator,
                    vec![
                        LegPayload::simple(
                            Side::Debit,
                            account_vid(book_id, "2700"),
                            Amount::new(usd, cents),
                        ),
                        LegPayload::simple(
                            Side::Credit,
                            account_vid(book_id, "1010"),
                            Amount::new(usd, cents),
                        ),
                    ],
                    vec![workpaper_doc.evidence_ref(1)],
                    None,
                    &[("beneficiary", "PROMOTER-TRUST")],
                    &[("planted", "structuring")],
                )?;
                ponzi_vids.push(post_proposal(&mut book, sp, operator, &["post"], Vec::new())?.vid);
                entry_count += 1;
            }
            planted_facts.push(PlantedFact {
                id: "PONZI-CYCLE-2026-03".into(),
                kind: "PonziDistribution".into(),
                period: "FY2026-P03".into(),
                entry_vids: ponzi_vids,
                summary:
                    "Planted investor inflow recycling (30,000.00 USD) and sub-10,000.00 USD structuring splits"
                        .into(),
            });
        }
        Scenario::ShellNetwork => {
            let d1 = DateDay::from_ymd(2026, 3, 22).unwrap();
            let d2 = DateDay::from_ymd(2026, 3, 23).unwrap();
            let mut shell_vids = Vec::with_capacity(4);
            for (step, (from_acct, to_acct, day)) in [
                ("1010", "1900", d1),
                ("1900", "1020", d1),
                ("1020", "1900", d2),
                ("1900", "1010", d2),
            ]
            .into_iter()
            .enumerate()
            {
                let p = build_proposal(
                    &book,
                    EntryClass::ORIGINAL,
                    day,
                    Some(day),
                    &format!("demo:shell:leg-{step}:s{seed}"),
                    &format!(
                        "Related-party conduit transfer leg {} ({from_acct} -> {to_acct})",
                        step + 1
                    ),
                    operator,
                    vec![
                        LegPayload::simple(
                            Side::Debit,
                            account_vid(book_id, to_acct),
                            Amount::new(usd, 1_950_000),
                        ),
                        LegPayload::simple(
                            Side::Credit,
                            account_vid(book_id, from_acct),
                            Amount::new(usd, 1_950_000),
                        ),
                    ],
                    vec![workpaper_doc.evidence_ref(1)],
                    None,
                    &[("shell_entity", &format!("SHELL-NODE-{}", step + 1))],
                    &[("planted", "shell-network")],
                )?;
                shell_vids.push(post_proposal(&mut book, p, operator, &["post"], Vec::new())?.vid);
                entry_count += 1;
            }
            planted_facts.push(PlantedFact {
                id: "SHELL-ROUNDTRIP-2026-03".into(),
                kind: "RelatedPartyShellNetwork".into(),
                period: "FY2026-P03".into(),
                entry_vids: shell_vids,
                summary:
                    "Planted circular related-party conduit transfer (1010 -> 1900 -> 1020 -> 1900 -> 1010) for 19,500.00 USD"
                        .into(),
            });
        }
        Scenario::WorldCom => {
            // Sunday 2026-03-29 round-dollar capitalization of operating expense into fixed assets.
            let sun = DateDay::from_ymd(2026, 3, 29).unwrap();
            let p = build_proposal(
                &book,
                EntryClass::ADJUSTING,
                sun,
                Some(sun),
                &format!("demo:worldcom:capex:s{seed}"),
                "adj",
                controller,
                vec![
                    LegPayload::simple(
                        Side::Debit,
                        account_vid(book_id, "1510"),
                        Amount::new(usd, 5_000_000),
                    ),
                    LegPayload::simple(
                        Side::Credit,
                        account_vid(book_id, "6200"),
                        Amount::new(usd, 5_000_000),
                    ),
                ],
                vec![workpaper_doc.evidence_ref(1)],
                None,
                &[("workpaper", "WP-CAPEX-99")],
                &[("planted", "worldcom-capex")],
            )?;
            let r = post_proposal(&mut book, p, controller, &["post"], Vec::new())?;
            entry_count += 1;
            planted_facts.push(PlantedFact {
                id: "WORLDCOM-CAPEX-2026-03".into(),
                kind: "ImproperCapitalization".into(),
                period: "FY2026-P03".into(),
                entry_vids: vec![r.vid],
                summary:
                    "Planted weekend round-dollar capitalization of 50,000.00 USD from 6200 Utilities to 1510 Equipment on 2026-03-29"
                        .into(),
            });
        }
        Scenario::ChannelStuffing => {
            // Quarter-end 2026-03-31 invoice with document_date 2026-04-04 (next period).
            let eff = DateDay::from_ymd(2026, 3, 31).unwrap();
            let doc_d = DateDay::from_ymd(2026, 4, 4).unwrap();
            let p = build_proposal(
                &book,
                EntryClass::ORIGINAL,
                eff,
                Some(doc_d),
                &format!("demo:stuffing:q1-pull:s{seed}"),
                "Quarter-end distributor pull-in invoice INV-2026-999 (shipped 2026-04-04)",
                operator,
                vec![
                    LegPayload::simple(
                        Side::Debit,
                        account_vid(book_id, "1200"),
                        Amount::new(usd, 8_000_000),
                    ),
                    LegPayload::simple(
                        Side::Credit,
                        account_vid(book_id, "4000"),
                        Amount::new(usd, 8_000_000),
                    ),
                ],
                vec![sales_doc.evidence_ref(1)],
                None,
                &[("customer", "DIST-OMEGA"), ("invoice", "INV-2026-999")],
                &[("planted", "channel-stuffing")],
            )?;
            let r = post_proposal(&mut book, p, operator, &["post"], Vec::new())?;
            entry_count += 1;
            planted_facts.push(PlantedFact {
                id: "STUFFING-CUTOFF-2026-03".into(),
                kind: "ChannelStuffingCutoff".into(),
                period: "FY2026-P03".into(),
                entry_vids: vec![r.vid],
                summary:
                    "Planted 80,000.00 USD quarter-end invoice effective 2026-03-31 with document/shipping date 2026-04-04"
                        .into(),
            });
        }
        Scenario::GhostPayroll => {
            let d1 = DateDay::from_ymd(2026, 3, 27).unwrap();
            let d2 = DateDay::from_ymd(2026, 3, 28).unwrap();
            let mut ghost_vids = Vec::with_capacity(3);
            for (idx, (day, suffix)) in [(d1, "a"), (d1, "b"), (d2, "c")].into_iter().enumerate() {
                let p = build_proposal(
                    &book,
                    EntryClass::ORIGINAL,
                    day,
                    Some(day),
                    &format!("demo:ghost:pay-{suffix}:s{seed}"),
                    &format!("Off-cycle payroll disbursement EMP-GHOST-99 (#{idx})"),
                    operator,
                    vec![
                        LegPayload::simple(
                            Side::Debit,
                            account_vid(book_id, "6100"),
                            Amount::new(usd, 400_000),
                        ),
                        LegPayload::simple(
                            Side::Credit,
                            account_vid(book_id, "1010"),
                            Amount::new(usd, 400_000),
                        ),
                    ],
                    vec![vendor_doc.evidence_ref(1)],
                    None,
                    &[("employee_id", "EMP-GHOST-99")],
                    &[("planted", "ghost-payroll")],
                )?;
                ghost_vids.push(post_proposal(&mut book, p, operator, &["post"], Vec::new())?.vid);
                entry_count += 1;
            }
            planted_facts.push(PlantedFact {
                id: "GHOST-PAYROLL-2026-03".into(),
                kind: "GhostPayroll".into(),
                period: "FY2026-P03".into(),
                entry_vids: ghost_vids,
                summary:
                    "Planted repeated round-dollar ghost-employee payroll disbursements of 4,000.00 USD on 2026-03-27 and 2026-03-28"
                        .into(),
            });
        }
    }

    // 8. Advance registers for every period with activity and publish a signed Notary checkpoint.
    for period_code in ["FY2026-OPEN", "FY2026-P01", "FY2026-P02", "FY2026-P03"] {
        book.advance_registers(period_code)?;
    }
    let witness_cap = Capability::embedded(auditor, &["witness"])
        .map_err(|e| BookError::KeyFile(e.to_string()))?;
    let checkpointed = book.checkpoint(auditor, &witness_cap)??;
    let head_seq = book.head()?;

    // 9. Self-verify all 6 verification dimensions before returning.
    let acc_ver = book.verify_accumulator()?;
    if !acc_ver.is_green() || acc_ver.states.is_empty() {
        return Err(DemoError::Verification(format!(
            "accumulator verification failed: {acc_ver:?}"
        )));
    }
    for period_code in ["FY2026-OPEN", "FY2026-P01", "FY2026-P02", "FY2026-P03"] {
        let reg_ver = book.verify_registers(period_code)?;
        if !reg_ver.is_green() {
            return Err(DemoError::Verification(format!(
                "register verification failed for {period_code}: {reg_ver:?}"
            )));
        }
    }
    let proj_ver = book.verify_projections(None)?;
    if !proj_ver.drift.is_empty() {
        return Err(DemoError::Verification(format!(
            "projections drift: {:?}",
            proj_ver.drift
        )));
    }
    let oi_ver = book.verify_open_items()?;
    if !oi_ver.drift.is_empty() {
        return Err(DemoError::Verification(format!(
            "open-items drift: {:?}",
            oi_ver.drift
        )));
    }
    let avail_ver = book.verify_availability()?;
    if !avail_ver.drift.is_empty() {
        return Err(DemoError::Verification(format!(
            "availability drift: {:?}",
            avail_ver.drift
        )));
    }
    let sched_ver = book.verify_schedules()?;
    if !sched_ver.drift.is_empty() {
        return Err(DemoError::Verification(format!(
            "schedules drift: {:?}",
            sched_ver.drift
        )));
    }
    let per_ver = book.verify_periods(None)?;
    if !per_ver.drift.is_empty() {
        return Err(DemoError::Verification(format!(
            "periods drift: {:?}",
            per_ver.drift
        )));
    }

    let readme = dir.join("README.md");
    let summary = DemoInitialized {
        book_id,
        dir: dir.to_path_buf(),
        keys: keys_file.to_path_buf(),
        readme: readme.clone(),
        scenario,
        seed,
        name: scenario.book_name().to_string(),
        base_unit: "USD".to_string(),
        calendar: book.context().calendar.id.clone(),
        chart_template: scenario.chart_template().to_string(),
        accounts: installed.accounts,
        periods: period_defs.len(),
        documents: doc_count,
        entries: entry_count,
        migration_run_vid,
        checkpoint_oid: checkpointed.checkpoint.oid,
        journal_digest: checkpointed.stored.state.root,
        head_seq,
        planted_facts,
    };
    let readme_text = render_readme(&summary);
    std::fs::write(&readme, readme_text.as_bytes())
        .map_err(|e| BookError::Io(readme.clone(), e))?;
    Ok(summary)
}

/// Render the deterministic `README.md` written into the initialized demo book directory.
#[must_use]
pub fn render_readme(info: &DemoInitialized) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str(&format!(
        "# {} (`{}` · seed `{}`)\n\n",
        info.name,
        info.scenario.as_str(),
        info.seed
    ));
    out.push_str("Generated deterministically by `fa demo init`.\n\n");
    out.push_str("## Book Identity & Digest\n\n");
    out.push_str(&format!("- **Book ID:** `{}`\n", info.book_id.to_hex()));
    out.push_str(&format!("- **Scenario:** `{}`\n", info.scenario.as_str()));
    out.push_str(&format!("- **Seed:** `{}`\n", info.seed));
    out.push_str(&format!("- **Base Unit:** `{}`\n", info.base_unit));
    out.push_str(&format!(
        "- **Calendar:** `{}` (`{}` periods)\n",
        info.calendar, info.periods
    ));
    out.push_str(&format!(
        "- **Chart Template:** `{}` (`{}` accounts)\n",
        info.chart_template, info.accounts
    ));
    out.push_str(&format!("- **Documents:** `{}`\n", info.documents));
    out.push_str(&format!(
        "- **Monetary & Posting Entries:** `{}`\n",
        info.entries
    ));
    out.push_str(&format!(
        "- **Migration Run (`go-live-2026`):** `{:032x}` (`Finalized`)\n",
        info.migration_run_vid.0
    ));
    out.push_str(&format!(
        "- **Transparency Checkpoint OID:** `{}`\n",
        hex(&info.checkpoint_oid.0)
    ));
    out.push_str(&format!(
        "- **Journal Accumulator Root (`journal_digest`):** `{}`\n",
        hex(&info.journal_digest)
    ));
    out.push_str(&format!(
        "- **Recorded Head (`CommitSeq`):** `{}`\n\n",
        info.head_seq.0
    ));

    out.push_str("## Period Lifecycle States\n\n");
    out.push_str("| Period | State | Notes |\n");
    out.push_str("| --- | --- | --- |\n");
    out.push_str("| `FY2026-OPEN` | `Locked` | Pre-opening special period holding finalized `go-live-2026` migration chunk |\n");
    out.push_str("| `FY2026-P01` | `Closed` | January activity posted, registers advanced, transitioned `Open -> SoftClosed -> Closed` |\n");
    out.push_str("| `FY2026-P02` | `Locked` | February activity posted, partial AR settlement, transitioned `Open -> SoftClosed -> Closed -> Locked` |\n");
    out.push_str("| `FY2026-P03` | `Open` | March operational activity, two-phase hold/resolution, auto-reversing accrual, planted forensic facts |\n");
    out.push_str(
        "| `FY2026-P04`..`FY2026-P12` | `Open` | Open for interactive experimentation |\n\n",
    );

    out.push_str("## Planted Facts\n\n");
    out.push_str("| Fact ID | Kind | Period | Entry VIds | Summary |\n");
    out.push_str("| --- | --- | --- | --- | --- |\n");
    for fact in &info.planted_facts {
        let vids = fact
            .entry_vids
            .iter()
            .map(|v| format!("`{:032x}`", v.0))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | {} | {} |\n",
            fact.id, fact.kind, fact.period, vids, fact.summary
        ));
    }

    out.push_str("\n## Suggested Commands\n\n");
    out.push_str("```bash\n");
    out.push_str("# Inspect book health, trial balance, and open items\n");
    out.push_str("fa doctor --book . --json\n");
    out.push_str("fa triage --book . --json\n");
    out.push_str("fa tb --period FY2026-P03 --book . --json\n");
    out.push_str("fa open-items --book . --json\n");
    out.push_str("fa migrate show go-live-2026 --book . --json\n\n");
    out.push_str("# Verify all 6 independent journal and projection invariants\n");
    out.push_str("fa verify registers --book . --json\n");
    out.push_str("fa verify accumulator --book . --json\n");
    out.push_str("fa verify projections --book . --json\n");
    out.push_str("fa verify open-items --book . --json\n");
    out.push_str("fa verify schedules --book . --json\n");
    out.push_str("fa verify periods --book . --json\n\n");
    out.push_str("# Run Lantern audit/forensic procedures over FY2026-P03\n");
    out.push_str("fa procedure list --json\n");
    out.push_str(
        "fa procedure run duplicates.same_same_same --period FY2026-P03 --book . --json\n",
    );
    out.push_str(
        "fa procedure run duplicates.same_same_different --period FY2026-P03 --book . --json\n",
    );
    out.push_str("```\n");
    out
}
