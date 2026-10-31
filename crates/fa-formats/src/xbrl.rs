//! XBRL instance emission, in-house taxonomy/linkbase XML parsing, statement
//! concept mapping, and calculation-linkbase validation (plan §12.1, §12.6,
//! §16.3, beads `fa-npi` and `fa-faim`).
//!
//! Validates every summation-item arc (`weight ∈ {-1, +1}`) in a statement's
//! calculation linkbase against the reported XBRL instance facts in exact
//! fixed-scale integer arithmetic. A failed calculation check is a
//! statement-definition or concept-mapping defect and fails the gate.

mod activity;
pub use activity::{XbrlIncomeAttribution, XbrlReportInputs, read_xbrl_income_attribution};

use std::collections::{BTreeMap, BTreeSet};

use fa_model::AccountType;
use fa_money::UnitId;
use fa_time::DateDay;

use crate::{
    ExportCoordinate, FormatError, FormatJournal, UnitCatalog, format_exact_decimal, hex_decode,
    hex_encode, parse_exact_decimal,
    saft::{xml_escape, xml_unescape},
};

/// Vendored US-GAAP 2026 small-company taxonomy schema (`us_gaap_2026_small_company.xsd`).
pub const EMBEDDED_US_GAAP_2026_SMALL_COMPANY_XSD: &str =
    include_str!("../corpora/us_gaap_2026_small_company.xsd");

/// Vendored US-GAAP 2026 small-company calculation linkbase (`us_gaap_2026_small_company_cal.xml`).
pub const EMBEDDED_US_GAAP_2026_SMALL_COMPANY_CAL_XML: &str =
    include_str!("../corpora/us_gaap_2026_small_company_cal.xml");

const EQUITY_PROFILE: &str = "parent-minority-v1";
const EQUITY_ROLE: &str = "http://frankenaccounting.org/role/TypeLevelStatementsEquityV2";

/// The accounts assigned the registered `noncontrolling_interest` role at
/// the journal's recorded coordinate. Account codes and names never imply
/// this attribution. The caller supplies the historical, authorized role fold.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XbrlEquityAttribution {
    pub noncontrolling_accounts: BTreeSet<String>,
}

impl XbrlEquityAttribution {
    fn encoded_accounts(&self) -> String {
        self.noncontrolling_accounts
            .iter()
            .map(|code| hex_encode(code.as_bytes()))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn digest(&self, coordinate: &ExportCoordinate) -> [u8; 32] {
        fa_model::domain_digest(
            b"fa:xbrl-equity-attribution:v1",
            &[
                &coordinate.certificate_digest,
                self.encoded_accounts().as_bytes(),
            ],
        )
    }

    fn validate(&self, journal: &FormatJournal) -> Result<(), FormatError> {
        for code in &self.noncontrolling_accounts {
            let account = journal
                .accounts
                .iter()
                .find(|account| account.code == *code)
                .ok_or_else(|| FormatError::UnknownAccount {
                    format: "xbrl_equity_attribution_v1",
                    account_code: code.clone(),
                })?;
            if account.account_type != AccountType::EQUITY {
                return Err(equity_error(format!(
                    "noncontrolling interest account {code:?} is not an Equity account"
                )));
            }
        }
        Ok(())
    }
}

fn equity_error(detail: impl Into<String>) -> FormatError {
    FormatError::Parse {
        format: "xbrl_equity_attribution_v1",
        detail: detail.into(),
    }
}

fn coordinate_comment(xml: &str) -> Result<&str, FormatError> {
    let mut comments = xml
        .lines()
        .filter(|line| line.trim().starts_with("<!-- fa:xbrl-coordinate "));
    let comment = comments
        .next()
        .ok_or_else(|| equity_error("missing fa:xbrl-coordinate certificate comment"))?;
    if comments.next().is_some() {
        return Err(equity_error(
            "multiple fa:xbrl-coordinate certificate comments",
        ));
    }
    Ok(comment)
}

/// Read the export's declared equity profile. This is content, not authority:
/// verification against a book must obtain its own role fold at the saved
/// coordinate. `None` identifies the historical type-level encoding.
pub fn read_xbrl_equity_attribution(
    xml: &str,
) -> Result<Option<XbrlEquityAttribution>, FormatError> {
    let comment = coordinate_comment(xml)?;
    let Some(profile) = extract_xml_attr(comment, "equity_profile") else {
        if extract_xml_attr(comment, "noncontrolling_accounts").is_some()
            || extract_xml_attr(comment, "equity_attribution_digest").is_some()
        {
            return Err(equity_error("equity metadata has no versioned profile"));
        }
        return Ok(None);
    };
    if profile != EQUITY_PROFILE {
        return Err(equity_error(format!(
            "unsupported equity profile {profile:?}"
        )));
    }
    let encoded = extract_xml_attr(comment, "noncontrolling_accounts")
        .ok_or_else(|| equity_error("missing noncontrolling_accounts"))?;
    let mut attribution = XbrlEquityAttribution::default();
    if !encoded.is_empty() {
        for item in encoded.split(',') {
            if item.is_empty() || !item.len().is_multiple_of(2) || !item.is_ascii() {
                return Err(equity_error("noncanonical noncontrolling account encoding"));
            }
            let bytes = item
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let hi = (pair[0] as char).to_digit(16);
                    let lo = (pair[1] as char).to_digit(16);
                    match (hi, lo) {
                        (Some(hi), Some(lo)) => Ok((hi * 16 + lo) as u8),
                        _ => Err(equity_error("noncontrolling account is not hex")),
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            let code = String::from_utf8(bytes)
                .map_err(|_| equity_error("noncontrolling account is not UTF-8"))?;
            if !attribution.noncontrolling_accounts.insert(code) {
                return Err(equity_error("duplicate noncontrolling account"));
            }
        }
    }
    if attribution.encoded_accounts() != encoded {
        return Err(equity_error(
            "noncontrolling accounts are not canonically ordered",
        ));
    }
    Ok(Some(attribution))
}

/// XBRL 2.1 period type for a monetary taxonomy concept (`instant` or `duration`, plan §12.6, `fa-faim`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum XbrlPeriodType {
    Instant,
    Duration,
}

/// XBRL 2.1 natural balance attribute (`debit` or `credit`) on a monetary concept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum XbrlBalanceSide {
    Debit,
    Credit,
}

/// Maps one statement definition line (`line_code`) to an XBRL taxonomy concept QName (`us-gaap:...`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlConceptBinding {
    pub line_code: String,
    pub concept: String,
    pub period_type: XbrlPeriodType,
    pub balance_side: Option<XbrlBalanceSide>,
}

/// Mapping from a statement definition's line codes to XBRL taxonomy concepts
/// and calculation-linkbase role URI (plan §12.6, §16.3, bead `fa-faim`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementXbrlMapping {
    pub mapping_id: String,
    pub statement_definition_name: String,
    pub taxonomy_namespace: String,
    pub taxonomy_schema_href: String,
    pub role_uri: String,
    pub bindings: Vec<XbrlConceptBinding>,
}

impl StatementXbrlMapping {
    /// Standard US-GAAP concept mapping for FrankenAccounting's built-in type-level Balance Sheet.
    ///
    /// Element names are cited from the published FASB US-GAAP Financial Reporting Taxonomy
    /// (`http://fasb.org/us-gaap/2026`, Statement of Financial Position — Classified `104000`):
    /// - `unclosed_earnings` binds to `us-gaap:RetainedEarningsAccumulatedDeficit`
    ///   (`xbrli:monetaryItemType`, `xbrli:periodType="instant"`, `xbrli:balance="credit"`).
    pub fn us_gaap_type_level_balance_sheet() -> Self {
        let b = |line_code: &str, concept: &str, side: XbrlBalanceSide| XbrlConceptBinding {
            line_code: line_code.into(),
            concept: concept.into(),
            period_type: XbrlPeriodType::Instant,
            balance_side: Some(side),
        };
        Self {
            mapping_id: "fa_xbrl_us_gaap_type_level_balance_sheet_v1".into(),
            statement_definition_name: "balance-sheet".into(),
            taxonomy_namespace: "http://fasb.org/us-gaap/2026".into(),
            taxonomy_schema_href: "us_gaap_2026_small_company.xsd".into(),
            role_uri: "http://frankenaccounting.org/role/TypeLevelStatements".into(),
            bindings: vec![
                b("assets", "us-gaap:Assets", XbrlBalanceSide::Debit),
                b(
                    "liabilities",
                    "us-gaap:Liabilities",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "equity",
                    "us-gaap:StockholdersEquity",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "unclosed_earnings",
                    "us-gaap:RetainedEarningsAccumulatedDeficit",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "total_equity",
                    "us-gaap:StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "liabilities_and_equity",
                    "us-gaap:LiabilitiesAndStockholdersEquity",
                    XbrlBalanceSide::Credit,
                ),
            ],
        }
    }

    /// Parent equity includes the unclosed earnings; minority equity is a
    /// separate registered-role fold. Unclosed earnings alone are not an
    /// accumulated retained-earnings balance and have no standalone fact here.
    pub fn us_gaap_attributed_balance_sheet() -> Self {
        let mut mapping = Self::us_gaap_type_level_balance_sheet();
        mapping.mapping_id = "fa_xbrl_us_gaap_attributed_balance_sheet_v1".into();
        mapping.role_uri = EQUITY_ROLE.into();
        mapping
            .bindings
            .retain(|binding| binding.line_code != "unclosed_earnings");
        mapping.bindings.push(XbrlConceptBinding {
            line_code: "noncontrolling_interest".into(),
            concept: "us-gaap:MinorityInterest".into(),
            period_type: XbrlPeriodType::Instant,
            balance_side: Some(XbrlBalanceSide::Credit),
        });
        mapping
    }

    /// Standard US-GAAP concept mapping for FrankenAccounting's built-in type-level Income Statement.
    pub fn us_gaap_type_level_income_statement() -> Self {
        let b = |line_code: &str, concept: &str, side: XbrlBalanceSide| XbrlConceptBinding {
            line_code: line_code.into(),
            concept: concept.into(),
            period_type: XbrlPeriodType::Duration,
            balance_side: Some(side),
        };
        Self {
            mapping_id: "fa_xbrl_us_gaap_type_level_income_statement_v1".into(),
            statement_definition_name: "income-statement".into(),
            taxonomy_namespace: "http://fasb.org/us-gaap/2026".into(),
            taxonomy_schema_href: "us_gaap_2026_small_company.xsd".into(),
            role_uri: "http://frankenaccounting.org/role/TypeLevelStatements".into(),
            bindings: vec![
                b("revenue", "us-gaap:Revenues", XbrlBalanceSide::Credit),
                b(
                    "expense",
                    "us-gaap:OperatingExpenses",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "net_income",
                    "us-gaap:NetIncomeLoss",
                    XbrlBalanceSide::Credit,
                ),
            ],
        }
    }

    /// Income activity with the NCI allocation presented separately. FASB's
    /// Other Comprehensive Income implementation guide identifies ProfitLoss
    /// as group profit, NetIncomeLoss as parent profit, and the NCI amount as
    /// a debit-normal attribution, not an operating expense.
    pub fn us_gaap_income_activity() -> Self {
        let mut mapping = Self::us_gaap_type_level_income_statement();
        mapping.mapping_id = "fa_xbrl_us_gaap_income_activity_v2".into();
        mapping.role_uri = activity::INCOME_ROLE.into();
        mapping.bindings.extend([
            XbrlConceptBinding {
                line_code: "group_profit".into(),
                concept: "us-gaap:ProfitLoss".into(),
                period_type: XbrlPeriodType::Duration,
                balance_side: Some(XbrlBalanceSide::Credit),
            },
            XbrlConceptBinding {
                line_code: "noncontrolling_income".into(),
                concept: "us-gaap:NetIncomeLossAttributableToNoncontrollingInterest".into(),
                period_type: XbrlPeriodType::Duration,
                balance_side: Some(XbrlBalanceSide::Debit),
            },
        ]);
        mapping
    }

    /// US-GAAP small-company classified Balance Sheet concept mapping (`StatementOfFinancialPositionClassified`).
    pub fn us_gaap_small_company_balance_sheet() -> Self {
        let b = |line_code: &str, concept: &str, side: XbrlBalanceSide| XbrlConceptBinding {
            line_code: line_code.into(),
            concept: concept.into(),
            period_type: XbrlPeriodType::Instant,
            balance_side: Some(side),
        };
        Self {
            mapping_id: "fa_xbrl_us_gaap_small_company_balance_sheet_v1".into(),
            statement_definition_name: "us_gaap_small_company_balance_sheet".into(),
            taxonomy_namespace: "http://fasb.org/us-gaap/2026".into(),
            taxonomy_schema_href: "us_gaap_2026_small_company.xsd".into(),
            role_uri:
                "http://fasb.org/us-gaap/role/statement/StatementOfFinancialPositionClassified"
                    .into(),
            bindings: vec![
                b(
                    "cash",
                    "us-gaap:CashAndCashEquivalentsAtCarryingValue",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "accounts_receivable",
                    "us-gaap:AccountsReceivableNetCurrent",
                    XbrlBalanceSide::Debit,
                ),
                b("inventory", "us-gaap:InventoryNet", XbrlBalanceSide::Debit),
                b(
                    "current_assets",
                    "us-gaap:AssetsCurrent",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "ppe_net",
                    "us-gaap:PropertyPlantAndEquipmentNet",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "noncurrent_assets",
                    "us-gaap:AssetsNoncurrent",
                    XbrlBalanceSide::Debit,
                ),
                b("total_assets", "us-gaap:Assets", XbrlBalanceSide::Debit),
                b(
                    "accounts_payable",
                    "us-gaap:AccountsPayableCurrent",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "accrued_liabilities",
                    "us-gaap:AccruedLiabilitiesCurrent",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "current_liabilities",
                    "us-gaap:LiabilitiesCurrent",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "long_term_debt",
                    "us-gaap:LongTermDebtNoncurrent",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "noncurrent_liabilities",
                    "us-gaap:LiabilitiesNoncurrent",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "total_liabilities",
                    "us-gaap:Liabilities",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "common_stock",
                    "us-gaap:CommonStockValue",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "retained_earnings",
                    "us-gaap:RetainedEarningsAccumulatedDeficit",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "total_equity",
                    "us-gaap:StockholdersEquity",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "liabilities_and_equity",
                    "us-gaap:LiabilitiesAndStockholdersEquity",
                    XbrlBalanceSide::Credit,
                ),
            ],
        }
    }

    /// US-GAAP small-company multi-step Income Statement concept mapping (`StatementOfIncome`).
    pub fn us_gaap_small_company_income_statement() -> Self {
        let b = |line_code: &str, concept: &str, side: XbrlBalanceSide| XbrlConceptBinding {
            line_code: line_code.into(),
            concept: concept.into(),
            period_type: XbrlPeriodType::Duration,
            balance_side: Some(side),
        };
        Self {
            mapping_id: "fa_xbrl_us_gaap_small_company_income_statement_v1".into(),
            statement_definition_name: "us_gaap_small_company_income_statement".into(),
            taxonomy_namespace: "http://fasb.org/us-gaap/2026".into(),
            taxonomy_schema_href: "us_gaap_2026_small_company.xsd".into(),
            role_uri: "http://fasb.org/us-gaap/role/statement/StatementOfIncome".into(),
            bindings: vec![
                b("revenues", "us-gaap:Revenues", XbrlBalanceSide::Credit),
                b(
                    "cogs",
                    "us-gaap:CostOfGoodsAndServicesSold",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "gross_profit",
                    "us-gaap:GrossProfit",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "operating_expenses",
                    "us-gaap:OperatingExpenses",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "operating_income",
                    "us-gaap:OperatingIncomeLoss",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "income_tax_expense",
                    "us-gaap:IncomeTaxExpenseBenefit",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "net_income",
                    "us-gaap:NetIncomeLoss",
                    XbrlBalanceSide::Credit,
                ),
            ],
        }
    }
}

/// One evaluated statement line (`(line_code, unit_id) -> amounts per column`) ready for XBRL mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedStatementLine {
    pub code: String,
    pub unit_id: u32,
    pub amounts: Vec<i128>,
}

/// Evaluated statement input for [`export_statement_lines_to_xbrl`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedStatementForXbrl {
    pub definition_name: String,
    pub column_labels: Vec<String>,
    pub period_end: DateDay,
    pub lines: Vec<EvaluatedStatementLine>,
}

/// One weighted summation arc in an XBRL calculation linkbase (`parent = Σ weight_i * child_i`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlCalculationArc {
    pub parent_concept: String,
    pub child_concept: String,
    /// XBRL 2.1 calculation weight (`+1` or `-1`).
    pub weight: i8,
    pub order: u32,
}

/// An XBRL calculation linkbase for a financial statement role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlCalculationLinkbase {
    pub role_uri: String,
    pub arcs: Vec<XbrlCalculationArc>,
}

/// One monetary concept element parsed from a vendored XBRL taxonomy schema (`.xsd`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlTaxonomyConcept {
    pub id: String,
    pub name: String,
    pub qname: String,
    pub period_type: XbrlPeriodType,
    pub balance_side: Option<XbrlBalanceSide>,
}

/// Parsed XBRL taxonomy schema (`.xsd`) holding target namespace and declared monetary concepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlTaxonomySchema {
    pub target_namespace: String,
    pub prefix: String,
    pub concepts: BTreeMap<String, XbrlTaxonomyConcept>,
}

/// One reported monetary fact in an XBRL instance document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlFact {
    pub concept: String,
    pub context_ref: String,
    pub unit_code: String,
    pub scale: u8,
    pub mantissa: i128,
}

/// An XBRL instance document with its reported facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlInstance {
    pub entity_identifier: String,
    pub period_start: Option<String>,
    pub period_end: String,
    pub facts: Vec<XbrlFact>,
}

/// Detailed audit log row for one parent concept calculation check (`fa-faim`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlCalculationCheckRow {
    pub role_uri: String,
    pub context_ref: String,
    pub unit_code: String,
    pub concept: String,
    pub computed_mantissa: i128,
    pub reported_mantissa: i128,
    pub delta_mantissa: i128,
    pub passed: bool,
}

impl XbrlCalculationCheckRow {
    /// Deterministic greppable log line (`concept=... computed=... reported=... delta=...`).
    pub fn to_log_line(&self) -> String {
        format!(
            "xbrl_calc_check role={} context={} unit={} concept={} computed={} reported={} delta={} status={}",
            self.role_uri,
            self.context_ref,
            self.unit_code,
            self.concept,
            self.computed_mantissa,
            self.reported_mantissa,
            self.delta_mantissa,
            if self.passed { "PASS" } else { "FAIL" }
        )
    }
}

/// Detailed validation report produced by [`validate_calculation_linkbase_detailed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlValidationReport {
    pub role_uri: String,
    pub checks_passed: usize,
    pub rows: Vec<XbrlCalculationCheckRow>,
}

impl XbrlValidationReport {
    pub fn log_lines(&self) -> Vec<String> {
        self.rows
            .iter()
            .map(XbrlCalculationCheckRow::to_log_line)
            .collect()
    }
}

impl XbrlTaxonomySchema {
    /// Parse the vendored US-GAAP 2026 small-company taxonomy schema (`us_gaap_2026_small_company.xsd`).
    pub fn embedded_us_gaap_small_company() -> Result<Self, FormatError> {
        parse_xbrl_taxonomy_schema_xml(EMBEDDED_US_GAAP_2026_SMALL_COMPANY_XSD)
    }
}

impl XbrlCalculationLinkbase {
    /// Parse all calculation linkbases from the vendored US-GAAP 2026 small-company linkbase XML.
    pub fn embedded_us_gaap_small_company() -> Result<Vec<Self>, FormatError> {
        parse_xbrl_calculation_linkbase_xml(EMBEDDED_US_GAAP_2026_SMALL_COMPANY_CAL_XML)
    }

    /// Look up one calculation linkbase role from the vendored US-GAAP 2026 small-company linkbase XML.
    pub fn embedded_for_role(role_uri: &str) -> Result<Self, FormatError> {
        let all = Self::embedded_us_gaap_small_company()?;
        all.into_iter()
            .find(|lb| lb.role_uri == role_uri)
            .ok_or_else(|| FormatError::Parse {
                format: "xbrl_calculation_linkbase",
                detail: format!("unknown calculation linkbase role URI {role_uri:?}"),
            })
    }

    /// Standard US-GAAP / IFRS Balance Sheet calculation linkbase:
    /// - `Assets = CurrentAssets + NoncurrentAssets`
    /// - `LiabilitiesAndStockholdersEquity = Liabilities + StockholdersEquity`
    pub fn standard_balance_sheet() -> Self {
        Self {
            role_uri: "http://frankenaccounting.org/role/BalanceSheet".to_owned(),
            arcs: vec![
                XbrlCalculationArc {
                    parent_concept: "us-gaap:Assets".to_owned(),
                    child_concept: "us-gaap:CurrentAssets".to_owned(),
                    weight: 1,
                    order: 10,
                },
                XbrlCalculationArc {
                    parent_concept: "us-gaap:Assets".to_owned(),
                    child_concept: "us-gaap:NoncurrentAssets".to_owned(),
                    weight: 1,
                    order: 20,
                },
                XbrlCalculationArc {
                    parent_concept: "us-gaap:LiabilitiesAndStockholdersEquity".to_owned(),
                    child_concept: "us-gaap:Liabilities".to_owned(),
                    weight: 1,
                    order: 10,
                },
                XbrlCalculationArc {
                    parent_concept: "us-gaap:LiabilitiesAndStockholdersEquity".to_owned(),
                    child_concept: "us-gaap:StockholdersEquity".to_owned(),
                    weight: 1,
                    order: 20,
                },
            ],
        }
    }

    /// Standard US-GAAP / IFRS Income Statement calculation linkbase:
    /// - `GrossProfit = Revenues - CostOfGoodsAndServicesSold`
    /// - `NetIncomeLoss = GrossProfit - OperatingExpenses`
    pub fn standard_income_statement() -> Self {
        Self {
            role_uri: "http://frankenaccounting.org/role/IncomeStatement".to_owned(),
            arcs: vec![
                XbrlCalculationArc {
                    parent_concept: "us-gaap:GrossProfit".to_owned(),
                    child_concept: "us-gaap:Revenues".to_owned(),
                    weight: 1,
                    order: 10,
                },
                XbrlCalculationArc {
                    parent_concept: "us-gaap:GrossProfit".to_owned(),
                    child_concept: "us-gaap:CostOfGoodsAndServicesSold".to_owned(),
                    weight: -1,
                    order: 20,
                },
                XbrlCalculationArc {
                    parent_concept: "us-gaap:NetIncomeLoss".to_owned(),
                    child_concept: "us-gaap:GrossProfit".to_owned(),
                    weight: 1,
                    order: 10,
                },
                XbrlCalculationArc {
                    parent_concept: "us-gaap:NetIncomeLoss".to_owned(),
                    child_concept: "us-gaap:OperatingExpenses".to_owned(),
                    weight: -1,
                    order: 20,
                },
            ],
        }
    }
}

/// Extract an XML attribute `attr="value"` from an opening/self-closing XML tag string.
fn extract_xml_attr<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    let mut search_from = 0usize;
    while let Some(rel) = tag[search_from..].find(attr) {
        let pos = search_from + rel;
        let prev_ok = pos == 0
            || tag.as_bytes()[pos - 1].is_ascii_whitespace()
            || tag.as_bytes()[pos - 1] == b'<';
        let after_name = pos + attr.len();
        if prev_ok && tag[after_name..].starts_with("=\"") {
            let val_start = after_name + 2;
            let val_end = tag[val_start..].find('"')? + val_start;
            return Some(&tag[val_start..val_end]);
        }
        search_from = after_name;
    }
    None
}

/// Iterate over `<...>` XML tags (excluding `<?...?>` processing instructions and `<!--...-->` comments).
fn iter_xml_tags(xml: &str) -> Result<Vec<&str>, FormatError> {
    let mut tags = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        rest = &rest[start..];
        if rest.starts_with("<!--") {
            let end = rest.find("-->").ok_or_else(|| FormatError::Parse {
                format: "xbrl_xml",
                detail: "unclosed XML comment".into(),
            })?;
            rest = &rest[end + 3..];
            continue;
        }
        if rest.starts_with("<?") {
            let end = rest.find("?>").ok_or_else(|| FormatError::Parse {
                format: "xbrl_xml",
                detail: "unclosed XML processing instruction".into(),
            })?;
            rest = &rest[end + 2..];
            continue;
        }
        let end = rest.find('>').ok_or_else(|| FormatError::Parse {
            format: "xbrl_xml",
            detail: "unclosed XML tag".into(),
        })?;
        tags.push(&rest[..=end]);
        rest = &rest[end + 1..];
    }
    Ok(tags)
}

/// In-house parser for a vendored XBRL 2.1 taxonomy schema (`.xsd`, plan §12.6, `fa-faim`).
pub fn parse_xbrl_taxonomy_schema_xml(xsd: &str) -> Result<XbrlTaxonomySchema, FormatError> {
    let tags = iter_xml_tags(xsd)?;
    let mut target_namespace = String::new();
    let mut prefix = "us-gaap".to_owned();
    let mut concepts = BTreeMap::new();

    for tag in tags {
        if tag.starts_with("<xs:schema") {
            if let Some(ns) = extract_xml_attr(tag, "targetNamespace") {
                target_namespace = xml_unescape(ns);
            }
        } else if tag.starts_with("<xs:element") {
            let id = extract_xml_attr(tag, "id")
                .ok_or_else(|| FormatError::Parse {
                    format: "xbrl_taxonomy_xsd",
                    detail: format!("xs:element missing id attribute: {tag}"),
                })?
                .to_owned();
            let name = extract_xml_attr(tag, "name")
                .ok_or_else(|| FormatError::Parse {
                    format: "xbrl_taxonomy_xsd",
                    detail: format!("xs:element missing name attribute: {tag}"),
                })?
                .to_owned();
            let period_type = match extract_xml_attr(tag, "xbrli:periodType") {
                Some("instant") => XbrlPeriodType::Instant,
                Some("duration") => XbrlPeriodType::Duration,
                other => {
                    return Err(FormatError::Parse {
                        format: "xbrl_taxonomy_xsd",
                        detail: format!(
                            "xs:element {id} has unsupported xbrli:periodType {other:?}"
                        ),
                    });
                }
            };
            let balance_side = match extract_xml_attr(tag, "xbrli:balance") {
                Some("debit") => Some(XbrlBalanceSide::Debit),
                Some("credit") => Some(XbrlBalanceSide::Credit),
                None => None,
                Some(other) => {
                    return Err(FormatError::Parse {
                        format: "xbrl_taxonomy_xsd",
                        detail: format!("xs:element {id} has invalid xbrli:balance {other:?}"),
                    });
                }
            };
            if let Some((pfx, _)) = id.split_once('_') {
                prefix = pfx.to_owned();
            }
            let qname = format!("{prefix}:{name}");
            let concept = XbrlTaxonomyConcept {
                id,
                name,
                qname: qname.clone(),
                period_type,
                balance_side,
            };
            if concepts.insert(qname.clone(), concept).is_some() {
                return Err(FormatError::Parse {
                    format: "xbrl_taxonomy_xsd",
                    detail: format!("duplicate concept {qname} in taxonomy schema"),
                });
            }
        }
    }

    if target_namespace.is_empty() || concepts.is_empty() {
        return Err(FormatError::Parse {
            format: "xbrl_taxonomy_xsd",
            detail: "taxonomy schema missing targetNamespace or concepts".into(),
        });
    }

    Ok(XbrlTaxonomySchema {
        target_namespace,
        prefix,
        concepts,
    })
}

/// In-house parser for a vendored XBRL 2.1 calculation linkbase (`_cal.xml`, plan §12.6, `fa-faim`).
pub fn parse_xbrl_calculation_linkbase_xml(
    xml: &str,
) -> Result<Vec<XbrlCalculationLinkbase>, FormatError> {
    let tags = iter_xml_tags(xml)?;
    let mut linkbases = Vec::new();
    let mut current_role: Option<String> = None;
    let mut locators: BTreeMap<String, String> = BTreeMap::new();
    let mut arcs: Vec<XbrlCalculationArc> = Vec::new();

    for tag in tags {
        if tag.starts_with("<link:calculationLink") {
            let role = extract_xml_attr(tag, "xlink:role").ok_or_else(|| FormatError::Parse {
                format: "xbrl_calculation_linkbase",
                detail: "link:calculationLink missing xlink:role".into(),
            })?;
            current_role = Some(xml_unescape(role));
            locators.clear();
            arcs.clear();
        } else if tag.starts_with("</link:calculationLink") {
            let role_uri = current_role.take().ok_or_else(|| FormatError::Parse {
                format: "xbrl_calculation_linkbase",
                detail: "unexpected </link:calculationLink>".into(),
            })?;
            arcs.sort_by(|a, b| {
                (&a.parent_concept, a.order, &a.child_concept).cmp(&(
                    &b.parent_concept,
                    b.order,
                    &b.child_concept,
                ))
            });
            linkbases.push(XbrlCalculationLinkbase {
                role_uri,
                arcs: std::mem::take(&mut arcs),
            });
        } else if tag.starts_with("<link:loc") && current_role.is_some() {
            let href = extract_xml_attr(tag, "xlink:href").ok_or_else(|| FormatError::Parse {
                format: "xbrl_calculation_linkbase",
                detail: format!("link:loc missing xlink:href: {tag}"),
            })?;
            let label = extract_xml_attr(tag, "xlink:label").ok_or_else(|| FormatError::Parse {
                format: "xbrl_calculation_linkbase",
                detail: format!("link:loc missing xlink:label: {tag}"),
            })?;
            let (_, fragment) = href.split_once('#').ok_or_else(|| FormatError::Parse {
                format: "xbrl_calculation_linkbase",
                detail: format!("link:loc xlink:href {href:?} missing #fragment"),
            })?;
            let qname = if let Some((pfx, name)) = fragment.split_once('_') {
                format!("{pfx}:{name}")
            } else {
                fragment.to_owned()
            };
            locators.insert(label.to_owned(), qname);
        } else if tag.starts_with("<link:calculationArc") && current_role.is_some() {
            let from_label =
                extract_xml_attr(tag, "xlink:from").ok_or_else(|| FormatError::Parse {
                    format: "xbrl_calculation_linkbase",
                    detail: format!("link:calculationArc missing xlink:from: {tag}"),
                })?;
            let to_label = extract_xml_attr(tag, "xlink:to").ok_or_else(|| FormatError::Parse {
                format: "xbrl_calculation_linkbase",
                detail: format!("link:calculationArc missing xlink:to: {tag}"),
            })?;
            let weight_str = extract_xml_attr(tag, "weight").ok_or_else(|| FormatError::Parse {
                format: "xbrl_calculation_linkbase",
                detail: format!("link:calculationArc missing weight: {tag}"),
            })?;
            let order_str = extract_xml_attr(tag, "order").unwrap_or("1");
            let weight: i8 = match weight_str.trim() {
                "1" | "+1" | "1.0" => 1,
                "-1" | "-1.0" => -1,
                other => {
                    return Err(FormatError::Parse {
                        format: "xbrl_calculation_linkbase",
                        detail: format!("invalid calculationArc weight {other:?}"),
                    });
                }
            };
            let order: u32 = order_str.trim().parse().map_err(|_| FormatError::Parse {
                format: "xbrl_calculation_linkbase",
                detail: format!("invalid calculationArc order {order_str:?}"),
            })?;
            let parent_concept = locators
                .get(from_label)
                .ok_or_else(|| FormatError::Parse {
                    format: "xbrl_calculation_linkbase",
                    detail: format!("unknown calculationArc xlink:from locator {from_label:?}"),
                })?
                .clone();
            let child_concept = locators
                .get(to_label)
                .ok_or_else(|| FormatError::Parse {
                    format: "xbrl_calculation_linkbase",
                    detail: format!("unknown calculationArc xlink:to locator {to_label:?}"),
                })?
                .clone();
            arcs.push(XbrlCalculationArc {
                parent_concept,
                child_concept,
                weight,
                order,
            });
        }
    }

    if linkbases.is_empty() {
        return Err(FormatError::Parse {
            format: "xbrl_calculation_linkbase",
            detail: "no <link:calculationLink> found in calculation linkbase XML".into(),
        });
    }

    Ok(linkbases)
}

/// Emit an XBRL 2.1 instance XML document for the given [`XbrlInstance`].
pub fn write_xbrl_instance_xml(instance: &XbrlInstance) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(
        "<xbrli:xbrl xmlns:xbrli=\"http://www.xbrl.org/2003/instance\" xmlns:link=\"http://www.xbrl.org/2003/linkbase\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" xmlns:iso4217=\"http://www.xbrl.org/2003/iso4217\" xmlns:us-gaap=\"http://fasb.org/us-gaap/2026\">\n",
    );
    xml.push_str(
        "  <link:schemaRef xlink:type=\"simple\" xlink:href=\"us_gaap_2026_small_company.xsd\"/>\n",
    );

    let mut contexts: BTreeSet<&str> = BTreeSet::new();
    let mut units: BTreeSet<&str> = BTreeSet::new();
    for fact in &instance.facts {
        contexts.insert(fact.context_ref.as_str());
        units.insert(fact.unit_code.as_str());
    }
    if contexts.is_empty() {
        contexts.insert("ctx_current");
    }

    let has_explicit_duration_ctx = contexts.iter().any(|c| c.starts_with("ctx_duration"));
    for ctx_id in contexts {
        xml.push_str(&format!(
            "  <xbrli:context id=\"{}\">\n",
            xml_escape(ctx_id)
        ));
        xml.push_str("    <xbrli:entity>\n");
        xml.push_str(&format!(
            "      <xbrli:identifier scheme=\"http://frankenaccounting.org/entity\">{}</xbrli:identifier>\n",
            xml_escape(&instance.entity_identifier)
        ));
        xml.push_str("    </xbrli:entity>\n");
        xml.push_str("    <xbrli:period>\n");
        let is_duration = ctx_id.starts_with("ctx_duration")
            || (instance.period_start.is_some() && !has_explicit_duration_ctx);
        if is_duration {
            let start = instance
                .period_start
                .as_deref()
                .unwrap_or(&instance.period_end);
            xml.push_str(&format!(
                "      <xbrli:startDate>{}</xbrli:startDate>\n      <xbrli:endDate>{}</xbrli:endDate>\n",
                xml_escape(start),
                xml_escape(&instance.period_end)
            ));
        } else {
            xml.push_str(&format!(
                "      <xbrli:instant>{}</xbrli:instant>\n",
                xml_escape(&instance.period_end)
            ));
        }
        xml.push_str("    </xbrli:period>\n");
        xml.push_str("  </xbrli:context>\n");
    }

    for unit_code in units {
        xml.push_str(&format!(
            "  <xbrli:unit id=\"{}\">\n    <xbrli:measure>iso4217:{}</xbrli:measure>\n  </xbrli:unit>\n",
            xml_escape(unit_code),
            xml_escape(unit_code)
        ));
    }

    for fact in &instance.facts {
        let amt = format_exact_decimal(fact.mantissa, fact.scale);
        xml.push_str(&format!(
            "  <{} contextRef=\"{}\" unitRef=\"{}\" decimals=\"{}\">{}</{}>\n",
            fact.concept,
            xml_escape(&fact.context_ref),
            xml_escape(&fact.unit_code),
            fact.scale,
            amt,
            fact.concept
        ));
    }
    xml.push_str("</xbrli:xbrl>\n");
    xml
}

/// Read an XBRL 2.1 instance XML document emitted by [`write_xbrl_instance_xml`]
/// back into an [`XbrlInstance`] using the in-house XML parser (zero third-party crates).
pub fn read_xbrl_instance_xml(xml: &str) -> Result<XbrlInstance, FormatError> {
    let mut entity_identifier = String::new();
    let mut period_start: Option<String> = None;
    let mut period_end = String::new();
    let mut saw_end_date = false;
    let mut facts = Vec::new();

    for raw_line in xml.lines() {
        let line = raw_line.trim();
        if let Some(rest) =
            line.strip_prefix("<xbrli:identifier scheme=\"http://frankenaccounting.org/entity\">")
        {
            if let Some(inner) = rest.strip_suffix("</xbrli:identifier>")
                && entity_identifier.is_empty()
            {
                entity_identifier = xml_unescape(inner);
            }
        } else if let Some(rest) = line.strip_prefix("<xbrli:startDate>") {
            if let Some(inner) = rest.strip_suffix("</xbrli:startDate>")
                && period_start.is_none()
            {
                period_start = Some(xml_unescape(inner));
            }
        } else if let Some(rest) = line.strip_prefix("<xbrli:endDate>") {
            if let Some(inner) = rest.strip_suffix("</xbrli:endDate>") {
                saw_end_date = true;
                if period_end.is_empty() {
                    period_end = xml_unescape(inner);
                }
            }
        } else if let Some(rest) = line.strip_prefix("<xbrli:instant>") {
            if let Some(inner) = rest.strip_suffix("</xbrli:instant>")
                && period_end.is_empty()
            {
                period_end = xml_unescape(inner);
            }
        } else if line.starts_with("<us-gaap:") {
            let open_end = line.find('>').ok_or_else(|| FormatError::Parse {
                format: "xbrl_gl_instance_v1",
                detail: format!("malformed fact line: {line}"),
            })?;
            let open_tag = &line[..=open_end];
            let concept_end = open_tag[1..]
                .find(|c: char| c.is_ascii_whitespace() || c == '>')
                .ok_or_else(|| FormatError::Parse {
                    format: "xbrl_gl_instance_v1",
                    detail: format!("malformed fact tag: {open_tag}"),
                })?
                + 1;
            let concept = open_tag[1..concept_end].to_owned();
            let close_tag = format!("</{concept}>");
            let value_str = line[open_end + 1..]
                .strip_suffix(&close_tag)
                .ok_or_else(|| FormatError::Parse {
                    format: "xbrl_gl_instance_v1",
                    detail: format!("mismatched closing tag on fact line: {line}"),
                })?;
            let context_ref =
                xml_unescape(extract_xml_attr(open_tag, "contextRef").ok_or_else(|| {
                    FormatError::Parse {
                        format: "xbrl_gl_instance_v1",
                        detail: format!("fact {concept} missing contextRef"),
                    }
                })?);
            let unit_code =
                xml_unescape(extract_xml_attr(open_tag, "unitRef").ok_or_else(|| {
                    FormatError::Parse {
                        format: "xbrl_gl_instance_v1",
                        detail: format!("fact {concept} missing unitRef"),
                    }
                })?);
            let decimals_str =
                extract_xml_attr(open_tag, "decimals").ok_or_else(|| FormatError::Parse {
                    format: "xbrl_gl_instance_v1",
                    detail: format!("fact {concept} missing decimals"),
                })?;
            let scale: u8 = decimals_str.parse().map_err(|_| FormatError::Parse {
                format: "xbrl_gl_instance_v1",
                detail: format!("fact {concept} invalid decimals {decimals_str:?}"),
            })?;
            let mantissa = parse_exact_decimal("xbrl_gl_instance_v1", value_str.trim(), scale)?;
            facts.push(XbrlFact {
                concept,
                context_ref,
                unit_code,
                scale,
                mantissa,
            });
        }
    }

    if entity_identifier.is_empty() || period_end.is_empty() {
        return Err(FormatError::Parse {
            format: "xbrl_gl_instance_v1",
            detail: "XBRL instance missing entity identifier or period instant/endDate".into(),
        });
    }
    if period_start.is_some() != saw_end_date {
        return Err(FormatError::Parse {
            format: "xbrl_gl_instance_v1",
            detail: "XBRL duration context must specify both startDate and endDate".into(),
        });
    }

    Ok(XbrlInstance {
        entity_identifier,
        period_start,
        period_end,
        facts,
    })
}

/// Validate an [`XbrlInstance`] against an [`XbrlCalculationLinkbase`] and optional
/// [`XbrlTaxonomySchema`], returning a structured [`XbrlValidationReport`] logging
/// `concept`, `computed`, `reported`, and `delta` for every parent summation check.
pub fn validate_calculation_linkbase_detailed(
    instance: &XbrlInstance,
    linkbase: &XbrlCalculationLinkbase,
    schema: Option<&XbrlTaxonomySchema>,
) -> Result<XbrlValidationReport, FormatError> {
    let mut fact_map: BTreeMap<(String, String, String), i128> = BTreeMap::new();
    let mut contexts_and_units: BTreeSet<(String, String)> = BTreeSet::new();
    let has_explicit_duration_ctx = instance
        .facts
        .iter()
        .any(|f| f.context_ref.starts_with("ctx_duration"));

    for fact in &instance.facts {
        if fact.weight_check_invalid() {
            return Err(FormatError::Parse {
                format: "xbrl_gl_instance_v1",
                detail: format!("empty concept or unit on fact {:?}", fact.concept),
            });
        }
        if let Some(tax) = schema {
            let Some(tax_concept) = tax.concepts.get(&fact.concept) else {
                return Err(FormatError::Parse {
                    format: "xbrl_gl_instance_v1",
                    detail: format!(
                        "fact concept {:?} is not declared in taxonomy {}",
                        fact.concept, tax.target_namespace
                    ),
                });
            };
            let is_duration_ctx = fact.context_ref.starts_with("ctx_duration")
                || (instance.period_start.is_some() && !has_explicit_duration_ctx);
            let ctx_period_type = if is_duration_ctx {
                XbrlPeriodType::Duration
            } else {
                XbrlPeriodType::Instant
            };
            if tax_concept.period_type != ctx_period_type {
                return Err(FormatError::Parse {
                    format: "xbrl_gl_instance_v1",
                    detail: format!(
                        "xbrl_period_type_check concept={} binding_period_type={:?} taxonomy_period_type={:?} context={} status=FAIL: fact concept `{}` period_type {:?} mismatches context `{}` ({:?})",
                        fact.concept,
                        ctx_period_type,
                        tax_concept.period_type,
                        fact.context_ref,
                        fact.concept,
                        tax_concept.period_type,
                        fact.context_ref,
                        ctx_period_type,
                    ),
                });
            }
        }
        fact_map.insert(
            (
                fact.concept.clone(),
                fact.context_ref.clone(),
                fact.unit_code.clone(),
            ),
            fact.mantissa,
        );
        contexts_and_units.insert((fact.context_ref.clone(), fact.unit_code.clone()));
    }

    let mut parents: BTreeMap<&str, Vec<&XbrlCalculationArc>> = BTreeMap::new();
    for arc in &linkbase.arcs {
        if arc.weight != 1 && arc.weight != -1 {
            return Err(FormatError::Parse {
                format: "xbrl_gl_instance_v1",
                detail: format!(
                    "invalid calculation weight {} on {} -> {} (must be +1 or -1)",
                    arc.weight, arc.parent_concept, arc.child_concept
                ),
            });
        }
        if let Some(tax) = schema {
            for c in [&arc.parent_concept, &arc.child_concept] {
                if !tax.concepts.contains_key(c) {
                    return Err(FormatError::Parse {
                        format: "xbrl_calculation_linkbase",
                        detail: format!(
                            "calculation arc concept {c:?} is not declared in taxonomy {}",
                            tax.target_namespace
                        ),
                    });
                }
            }
        }
        parents
            .entry(arc.parent_concept.as_str())
            .or_default()
            .push(arc);
    }

    let mut rows = Vec::new();
    let mut first_failure: Option<FormatError> = None;

    for (ctx, unit) in &contexts_and_units {
        for (parent_concept, arcs) in &parents {
            let Some(&reported_parent) =
                fact_map.get(&((*parent_concept).to_owned(), ctx.clone(), unit.clone()))
            else {
                continue;
            };
            let mut sum = 0i128;
            let mut any_child_present = false;
            for arc in arcs {
                if let Some(&child_val) =
                    fact_map.get(&(arc.child_concept.clone(), ctx.clone(), unit.clone()))
                {
                    any_child_present = true;
                    let term = child_val
                        .checked_mul(i128::from(arc.weight))
                        .ok_or_else(|| FormatError::Overflow {
                            format: "xbrl_gl_instance_v1",
                            detail: "calculation weight multiplication overflow".to_owned(),
                        })?;
                    sum = sum.checked_add(term).ok_or_else(|| FormatError::Overflow {
                        format: "xbrl_gl_instance_v1",
                        detail: "calculation child summation overflow".to_owned(),
                    })?;
                }
            }
            if any_child_present {
                let delta =
                    reported_parent
                        .checked_sub(sum)
                        .ok_or_else(|| FormatError::Overflow {
                            format: "xbrl_gl_instance_v1",
                            detail: "calculation delta subtraction overflow".to_owned(),
                        })?;
                let passed = delta == 0;
                rows.push(XbrlCalculationCheckRow {
                    role_uri: linkbase.role_uri.clone(),
                    context_ref: ctx.clone(),
                    unit_code: unit.clone(),
                    concept: (*parent_concept).to_owned(),
                    computed_mantissa: sum,
                    reported_mantissa: reported_parent,
                    delta_mantissa: delta,
                    passed,
                });
                if !passed && first_failure.is_none() {
                    first_failure = Some(FormatError::XbrlCalculationInconsistency {
                        parent_concept: (*parent_concept).to_owned(),
                        unit_code: unit.clone(),
                        reported_mantissa: reported_parent,
                        computed_children_mantissa: sum,
                    });
                }
            }
        }
    }

    if let Some(err) = first_failure {
        return Err(err);
    }

    Ok(XbrlValidationReport {
        role_uri: linkbase.role_uri.clone(),
        checks_passed: rows.len(),
        rows,
    })
}

/// Validate an [`XbrlInstance`] against an [`XbrlCalculationLinkbase`].
///
/// Every parent concept that has at least one present child fact in a given
/// `(context_ref, unit_code)` must equal the exact weighted sum of its children
/// (`Σ weight_i * child_i`). Any discrepancy returns
/// `Err(FormatError::XbrlCalculationInconsistency)`.
pub fn validate_calculation_linkbase(
    instance: &XbrlInstance,
    linkbase: &XbrlCalculationLinkbase,
) -> Result<usize, FormatError> {
    let report = validate_calculation_linkbase_detailed(instance, linkbase, None)?;
    Ok(report.checks_passed)
}

/// Export evaluated statement lines ([`EvaluatedStatementForXbrl`]) to an [`XbrlInstance`]
/// using a [`StatementXbrlMapping`], validating every mapped concept against the
/// [`XbrlTaxonomySchema`] and [`XbrlCalculationLinkbase`] before returning (`fa-faim`).
pub fn export_statement_lines_to_xbrl(
    statement: &EvaluatedStatementForXbrl,
    mapping: &StatementXbrlMapping,
    entity_identifier: &str,
    unit_catalog: &UnitCatalog,
    schema: &XbrlTaxonomySchema,
    linkbase: &XbrlCalculationLinkbase,
) -> Result<(XbrlInstance, XbrlValidationReport), FormatError> {
    if statement.definition_name != mapping.statement_definition_name {
        return Err(FormatError::Parse {
            format: "xbrl_gl_instance_v1",
            detail: format!(
                "statement definition {:?} does not match XBRL mapping target {:?}",
                statement.definition_name, mapping.statement_definition_name
            ),
        });
    }
    if mapping.role_uri != linkbase.role_uri {
        return Err(FormatError::Parse {
            format: "xbrl_gl_instance_v1",
            detail: format!(
                "XBRL mapping role URI {:?} does not match calculation linkbase role URI {:?}",
                mapping.role_uri, linkbase.role_uri
            ),
        });
    }
    if statement.column_labels.is_empty() {
        return Err(FormatError::Parse {
            format: "xbrl_gl_instance_v1",
            detail: "statement has no columns to export".into(),
        });
    }

    let mut binding_by_line: BTreeMap<&str, _> = BTreeMap::new();
    let mut used_concepts: BTreeSet<&str> = BTreeSet::new();
    for b in &mapping.bindings {
        let tax_concept = schema
            .concepts
            .get(&b.concept)
            .ok_or_else(|| FormatError::Parse {
                format: "xbrl_gl_instance_v1",
                detail: format!(
                    "line `{}` maps to unknown taxonomy concept `{}`",
                    b.line_code, b.concept
                ),
            })?;
        if tax_concept.period_type != b.period_type {
            let ctx_ref = match b.period_type {
                XbrlPeriodType::Instant => "ctx_current",
                XbrlPeriodType::Duration => "ctx_duration_current",
            };
            return Err(FormatError::Parse {
                format: "xbrl_gl_instance_v1",
                detail: format!(
                    "xbrl_period_type_check concept={} binding_period_type={:?} taxonomy_period_type={:?} context={} status=FAIL: line `{}` concept `{}` period_type {:?} mismatches taxonomy {:?} in context `{}`",
                    b.concept,
                    b.period_type,
                    tax_concept.period_type,
                    ctx_ref,
                    b.line_code,
                    b.concept,
                    b.period_type,
                    tax_concept.period_type,
                    ctx_ref,
                ),
            });
        }
        if b.balance_side != tax_concept.balance_side {
            return Err(FormatError::Parse {
                format: "xbrl_gl_instance_v1",
                detail: format!(
                    "line `{}` concept `{}` balance_side {:?} mismatches taxonomy {:?}",
                    b.line_code, b.concept, b.balance_side, tax_concept.balance_side
                ),
            });
        }
        if !used_concepts.insert(b.concept.as_str()) {
            return Err(FormatError::Parse {
                format: "xbrl_gl_instance_v1",
                detail: format!(
                    "duplicate taxonomy concept `{}` in statement mapping `{}`",
                    b.concept, mapping.mapping_id
                ),
            });
        }
        if binding_by_line.insert(b.line_code.as_str(), b).is_some() {
            return Err(FormatError::Parse {
                format: "xbrl_gl_instance_v1",
                detail: format!(
                    "duplicate line_code `{}` in statement mapping `{}`",
                    b.line_code, mapping.mapping_id
                ),
            });
        }
    }

    let mut facts = Vec::new();
    for (col_idx, col_label) in statement.column_labels.iter().enumerate() {
        for line in &statement.lines {
            let Some(binding) = binding_by_line.get(line.code.as_str()) else {
                continue;
            };
            let context_ref = match binding.period_type {
                XbrlPeriodType::Instant => {
                    if col_idx == 0 {
                        "ctx_current".to_owned()
                    } else {
                        format!("ctx_col_{col_idx}_{col_label}")
                    }
                }
                XbrlPeriodType::Duration => {
                    if col_idx == 0 {
                        "ctx_duration_current".to_owned()
                    } else {
                        format!("ctx_duration_col_{col_idx}_{col_label}")
                    }
                }
            };
            let (unit_code, scale) =
                unit_catalog
                    .lookup_id(UnitId(line.unit_id))
                    .ok_or_else(|| FormatError::UnknownUnit {
                        format: "xbrl_gl_instance_v1",
                        unit: line.unit_id.to_string(),
                    })?;
            facts.push(XbrlFact {
                concept: binding.concept.clone(),
                context_ref,
                unit_code: unit_code.to_owned(),
                scale,
                mantissa: line.amounts[col_idx],
            });
        }
    }

    let has_duration = mapping
        .bindings
        .iter()
        .any(|b| b.period_type == XbrlPeriodType::Duration);
    let period_start = if has_duration {
        Some(
            DateDay::from_ymd(statement.period_end.year(), 1, 1)
                .unwrap_or(statement.period_end)
                .render(),
        )
    } else {
        None
    };
    let period_end = statement.period_end.render();
    let instance = XbrlInstance {
        entity_identifier: entity_identifier.to_owned(),
        period_start,
        period_end,
        facts,
    };

    let report = validate_calculation_linkbase_detailed(&instance, linkbase, Some(schema))?;
    Ok((instance, report))
}

/// Fold a [`FormatJournal`] at its coordinate into the certified type-level Balance Sheet
/// and Income Statement lines, map every line to the vendored US-GAAP taxonomy, validate
/// the calculation linkbase, and emit a deterministic XBRL 2.1 instance XML document
/// carrying the [`ExportCoordinate`] certificate (`fa export xbrl`, bead `fa-faim`).
pub fn write_format_journal_xbrl_xml(journal: &FormatJournal) -> Result<String, FormatError> {
    write_format_journal_xbrl_xml_with_equity(journal, &XbrlEquityAttribution::default())
}

/// Export parent and noncontrolling equity separately under the supplied
/// historical role selection. The selection and its coordinate-bound digest
/// are retained in the export. Its digest is not a signature or proof that
/// a caller's role declarations were authorized.
pub fn write_format_journal_xbrl_xml_with_equity(
    journal: &FormatJournal,
    attribution: &XbrlEquityAttribution,
) -> Result<String, FormatError> {
    attribution.validate(journal)?;
    write_format_journal_xbrl_profile(journal, Some(attribution), None)
}

/// Export v2 using independently selected historical income activity.
/// Closing transfers remain in balance-sheet stock but cannot erase revenue
/// and expense activity. The published default and equity-v1 writers retain
/// their exact encodings for callers and historical export verification.
pub fn write_format_journal_xbrl_xml_with_activity(
    journal: &FormatJournal,
    inputs: &XbrlReportInputs,
) -> Result<String, FormatError> {
    inputs.validate(journal)?;
    write_format_journal_xbrl_profile(journal, Some(&inputs.equity), Some(inputs))
}

/// Reproduce the historical type-level encoding when verifying an existing
/// export. New CLI exports use the explicitly versioned activity profile.
pub fn write_legacy_format_journal_xbrl_xml(
    journal: &FormatJournal,
) -> Result<String, FormatError> {
    write_format_journal_xbrl_profile(journal, None, None)
}

fn write_format_journal_xbrl_profile(
    journal: &FormatJournal,
    attribution: Option<&XbrlEquityAttribution>,
    activity: Option<&XbrlReportInputs>,
) -> Result<String, FormatError> {
    let unit_catalog = UnitCatalog::embedded()?;
    let schema = XbrlTaxonomySchema::embedded_us_gaap_small_company()?;
    let role = if activity.is_some() {
        activity::INCOME_ROLE
    } else if attribution.is_some() {
        EQUITY_ROLE
    } else {
        "http://frankenaccounting.org/role/TypeLevelStatements"
    };
    let linkbase = XbrlCalculationLinkbase::embedded_for_role(role)?;

    let mut acct_type_by_code: BTreeMap<&str, AccountType> = BTreeMap::new();
    for acc in &journal.accounts {
        acct_type_by_code.insert(acc.code.as_str(), acc.account_type);
    }

    let balances = journal.fold_balances()?;
    let mut units_seen: BTreeSet<u32> = BTreeSet::new();
    if let Some((base_uid, _)) = unit_catalog.lookup_code(&journal.coordinate.base_unit_code) {
        units_seen.insert(base_uid.0);
    }

    // Per unit, fold signed (Dr - Cr) balances by AccountType:
    // Asset: Dr - Cr; Liability: Cr - Dr; Equity: Cr - Dr; Revenue: Cr - Dr; Expense: Dr - Cr.
    let mut type_sums: BTreeMap<(u32, u8), i128> = BTreeMap::new();
    let mut minority_sums: BTreeMap<u32, i128> = BTreeMap::new();
    for ((code, unit_code), &dr_minus_cr) in &balances {
        let (uid, _) =
            unit_catalog
                .lookup_code(unit_code)
                .ok_or_else(|| FormatError::UnknownUnit {
                    format: "xbrl_gl_instance_v1",
                    unit: unit_code.clone(),
                })?;
        units_seen.insert(uid.0);
        let acct_ty = acct_type_by_code
            .get(code.as_str())
            .copied()
            .ok_or_else(|| FormatError::UnknownAccount {
                format: "xbrl_gl_instance_v1",
                account_code: code.clone(),
            })?;
        let natural = match acct_ty {
            AccountType::ASSET | AccountType::EXPENSE => dr_minus_cr,
            AccountType::LIABILITY | AccountType::EQUITY | AccountType::REVENUE => dr_minus_cr
                .checked_neg()
                .ok_or_else(|| FormatError::Overflow {
                    format: "xbrl_gl_instance_v1",
                    detail: "negation overflow in natural balance".into(),
                })?,
            _ => continue,
        };
        let cell = type_sums.entry((uid.0, acct_ty.0)).or_insert(0);
        *cell = cell
            .checked_add(natural)
            .ok_or_else(|| FormatError::Overflow {
                format: "xbrl_gl_instance_v1",
                detail: "account type summation overflow".into(),
            })?;
        if attribution.is_some_and(|roles| roles.noncontrolling_accounts.contains(code)) {
            let minority = minority_sums.entry(uid.0).or_default();
            *minority = minority
                .checked_add(natural)
                .ok_or_else(|| FormatError::Overflow {
                    format: "xbrl_equity_attribution_v1",
                    detail: "noncontrolling equity summation overflow".into(),
                })?;
        }
    }

    let income_totals = activity
        .map(|input| input.totals(journal))
        .transpose()?
        .unwrap_or_default();
    units_seen.extend(income_totals.keys().copied());
    let mut bs_lines = Vec::new();
    let mut is_lines = Vec::new();
    for uid in units_seen {
        let assets = *type_sums.get(&(uid, AccountType::ASSET.0)).unwrap_or(&0);
        let liabilities = *type_sums
            .get(&(uid, AccountType::LIABILITY.0))
            .unwrap_or(&0);
        let equity = *type_sums.get(&(uid, AccountType::EQUITY.0)).unwrap_or(&0);
        let revenue = *type_sums.get(&(uid, AccountType::REVENUE.0)).unwrap_or(&0);
        let expense = *type_sums.get(&(uid, AccountType::EXPENSE.0)).unwrap_or(&0);
        let unclosed_earnings =
            revenue
                .checked_sub(expense)
                .ok_or_else(|| FormatError::Overflow {
                    format: "xbrl_gl_instance_v1",
                    detail: "unclosed earnings overflow".into(),
                })?;
        let total_equity =
            equity
                .checked_add(unclosed_earnings)
                .ok_or_else(|| FormatError::Overflow {
                    format: "xbrl_gl_instance_v1",
                    detail: "total equity overflow".into(),
                })?;
        let liabilities_and_equity =
            liabilities
                .checked_add(total_equity)
                .ok_or_else(|| FormatError::Overflow {
                    format: "xbrl_gl_instance_v1",
                    detail: "liabilities and equity overflow".into(),
                })?;

        let minority = minority_sums.get(&uid).copied().unwrap_or_default();
        let parent_equity =
            total_equity
                .checked_sub(minority)
                .ok_or_else(|| FormatError::Overflow {
                    format: "xbrl_equity_attribution_v1",
                    detail: "parent equity subtraction overflow".into(),
                })?;

        for (code, val) in [
            ("assets", assets),
            ("liabilities", liabilities),
            (
                "equity",
                if attribution.is_some() {
                    parent_equity
                } else {
                    equity
                },
            ),
            ("unclosed_earnings", unclosed_earnings),
            ("total_equity", total_equity),
            ("liabilities_and_equity", liabilities_and_equity),
        ] {
            bs_lines.push(EvaluatedStatementLine {
                code: code.into(),
                unit_id: uid,
                amounts: vec![val],
            });
        }

        if attribution.is_some_and(|roles| !roles.noncontrolling_accounts.is_empty()) {
            bs_lines.push(EvaluatedStatementLine {
                code: "noncontrolling_interest".into(),
                unit_id: uid,
                amounts: vec![minority],
            });
        }

        let (income_revenue, income_expense, parent_income) = if activity.is_some() {
            let (income_revenue, income_expense, nci_income) =
                income_totals.get(&uid).copied().unwrap_or_default();
            let group_profit = income_revenue.checked_sub(income_expense).ok_or_else(|| {
                FormatError::Overflow {
                    format: "xbrl_income_activity_v2",
                    detail: "group profit subtraction overflow".into(),
                }
            })?;
            let parent_income =
                group_profit
                    .checked_sub(nci_income)
                    .ok_or_else(|| FormatError::Overflow {
                        format: "xbrl_income_activity_v2",
                        detail: "parent profit subtraction overflow".into(),
                    })?;
            for (code, value) in [
                ("group_profit", group_profit),
                ("noncontrolling_income", nci_income),
            ] {
                is_lines.push(EvaluatedStatementLine {
                    code: code.into(),
                    unit_id: uid,
                    amounts: vec![value],
                });
            }
            (income_revenue, income_expense, parent_income)
        } else {
            (revenue, expense, unclosed_earnings)
        };
        for (code, val) in [
            ("revenue", income_revenue),
            ("expense", income_expense),
            ("net_income", parent_income),
        ] {
            is_lines.push(EvaluatedStatementLine {
                code: code.into(),
                unit_id: uid,
                amounts: vec![val],
            });
        }
    }

    let bs_stmt = EvaluatedStatementForXbrl {
        definition_name: "balance-sheet".into(),
        column_labels: vec!["current".into()],
        period_end: journal.coordinate.effective_through,
        lines: bs_lines,
    };
    let is_stmt = EvaluatedStatementForXbrl {
        definition_name: "income-statement".into(),
        column_labels: vec!["current".into()],
        period_end: journal.coordinate.effective_through,
        lines: is_lines,
    };

    let mut bs_mapping = if attribution.is_some() {
        StatementXbrlMapping::us_gaap_attributed_balance_sheet()
    } else {
        StatementXbrlMapping::us_gaap_type_level_balance_sheet()
    };
    bs_mapping.role_uri = role.into();
    let mut is_mapping = if activity.is_some() {
        StatementXbrlMapping::us_gaap_income_activity()
    } else {
        StatementXbrlMapping::us_gaap_type_level_income_statement()
    };
    is_mapping.role_uri = role.into();
    let (bs_inst, _) = export_statement_lines_to_xbrl(
        &bs_stmt,
        &bs_mapping,
        &journal.coordinate.book_name,
        &unit_catalog,
        &schema,
        &linkbase,
    )?;
    let (mut is_inst, _) = export_statement_lines_to_xbrl(
        &is_stmt,
        &is_mapping,
        &journal.coordinate.book_name,
        &unit_catalog,
        &schema,
        &linkbase,
    )?;

    // This producer folds every exported entry, including prior-year activity.
    // Extend the existing January start only when that cumulative fold needs it;
    // same-year and empty exports retain their existing bytes.
    if let Some(earliest) = journal
        .entries
        .iter()
        .map(|entry| entry.effective_date)
        .min()
        && earliest.year() < journal.coordinate.effective_through.year()
    {
        is_inst.period_start = Some(earliest.render());
    }

    let mut combined_facts = bs_inst.facts;
    combined_facts.extend(is_inst.facts);
    let combined = XbrlInstance {
        entity_identifier: journal.coordinate.book_name.clone(),
        period_start: is_inst.period_start,
        period_end: journal.coordinate.effective_through.render(),
        facts: combined_facts,
    };

    let _ = validate_calculation_linkbase_detailed(&combined, &linkbase, Some(&schema))?;

    let mut xml = write_xbrl_instance_xml(&combined);
    let mut equity_metadata = attribution.map_or_else(String::new, |roles| {
        format!(
            " equity_profile=\"{EQUITY_PROFILE}\" noncontrolling_accounts=\"{}\" equity_attribution_digest=\"{}\"",
            roles.encoded_accounts(),
            hex_encode(&roles.digest(&journal.coordinate)),
        )
    });
    if let Some(activity) = activity {
        equity_metadata.push_str(&activity.metadata(&journal.coordinate)?);
    }
    let cert_comment = format!(
        "<!-- fa:xbrl-coordinate book_name=\"{}\" base_unit=\"{}\" base_unit_scale=\"{}\" effective_through=\"{}\" known_at_seq=\"{}\" entry_count=\"{}\" content_digest=\"{}\" certificate_digest=\"{}\"{equity_metadata} -->\n",
        xml_escape(&journal.coordinate.book_name),
        xml_escape(&journal.coordinate.base_unit_code),
        journal.coordinate.base_unit_scale,
        journal.coordinate.effective_through.render(),
        journal.coordinate.known_at_seq,
        journal.coordinate.entry_count,
        hex_encode(&journal.coordinate.content_digest),
        hex_encode(&journal.coordinate.certificate_digest),
    );
    if let Some(pos) = xml.find('\n') {
        xml.insert_str(pos + 1, &cert_comment);
    }
    Ok(xml)
}

/// Validate a published XBRL profile's canonical XML, taxonomy calculations,
/// coordinate and attribution metadata integrity. These checks do not prove
/// historical roles or complete income activity: book-backed verification
/// independently reconstructs the selected sources and compares exact bytes.
pub fn verify_format_journal_xbrl_xml(
    xml: &str,
) -> Result<(ExportCoordinate, XbrlValidationReport), FormatError> {
    let attribution = read_xbrl_equity_attribution(xml)?;
    let income_attribution = read_xbrl_income_attribution(xml)?;
    let instance = read_xbrl_instance_xml(xml)?;
    let schema = XbrlTaxonomySchema::embedded_us_gaap_small_company()?;
    let linkbase = XbrlCalculationLinkbase::embedded_for_role(if income_attribution.is_some() {
        activity::INCOME_ROLE
    } else if attribution.is_some() {
        EQUITY_ROLE
    } else {
        "http://frankenaccounting.org/role/TypeLevelStatements"
    })?;
    let report = validate_calculation_linkbase_detailed(&instance, &linkbase, Some(&schema))?;

    let stripped_xml: String = xml
        .lines()
        .filter(|l| !l.trim().starts_with("<!-- fa:xbrl-coordinate "))
        .map(|l| format!("{l}\n"))
        .collect();
    if write_xbrl_instance_xml(&instance) != stripped_xml {
        return Err(FormatError::Parse {
            format: "xbrl_gl_instance_v1",
            detail: "XBRL instance did not round-trip byte-for-byte".into(),
        });
    }

    let comment_line = coordinate_comment(xml)?;
    let attr = |name: &str| -> Result<String, FormatError> {
        extract_xml_attr(comment_line, name)
            .map(xml_unescape)
            .ok_or_else(|| FormatError::Parse {
                format: "xbrl_gl_instance_v1",
                detail: format!("fa:xbrl-coordinate missing attribute {name}"),
            })
    };
    let book_name = attr("book_name")?;
    let base_unit_code = attr("base_unit")?;
    let base_unit_scale: u8 = attr("base_unit_scale")?
        .parse()
        .map_err(|_| FormatError::Parse {
            format: "xbrl_gl_instance_v1",
            detail: "invalid base_unit_scale".into(),
        })?;
    let effective_through =
        DateDay::parse(&attr("effective_through")?).map_err(|e| FormatError::Parse {
            format: "xbrl_gl_instance_v1",
            detail: format!("invalid effective_through: {e}"),
        })?;
    let known_at_seq: u64 = attr("known_at_seq")?
        .parse()
        .map_err(|_| FormatError::Parse {
            format: "xbrl_gl_instance_v1",
            detail: "invalid known_at_seq".into(),
        })?;
    let entry_count: u64 = attr("entry_count")?
        .parse()
        .map_err(|_| FormatError::Parse {
            format: "xbrl_gl_instance_v1",
            detail: "invalid entry_count".into(),
        })?;
    let content_digest = hex_decode("xbrl_gl_instance_v1", &attr("content_digest")?)?;
    let certificate_digest = hex_decode("xbrl_gl_instance_v1", &attr("certificate_digest")?)?;

    let coordinate = ExportCoordinate {
        book_name,
        base_unit_code,
        base_unit_scale,
        effective_through,
        known_at_seq,
        entry_count,
        content_digest,
        certificate_digest,
        account_scope: None,
    };
    coordinate.verify(&content_digest)?;
    if let Some(attribution) = &attribution {
        let declared: [u8; 32] = hex_decode(
            "xbrl_equity_attribution_v1",
            &attr("equity_attribution_digest")?,
        )?;
        if declared != attribution.digest(&coordinate) {
            return Err(equity_error(
                "equity attribution digest differs from its coordinate",
            ));
        }
    }
    if let Some(income) = income_attribution {
        let equity = attribution
            .as_ref()
            .ok_or_else(|| equity_error("income activity profile has no equity attribution"))?;
        income.verify(xml, &coordinate, equity)?;
    }
    Ok((coordinate, report))
}

impl XbrlFact {
    fn weight_check_invalid(&self) -> bool {
        self.concept.trim().is_empty() || self.unit_code.trim().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn us_gaap_small_company_fixture_validates_against_vendored_taxonomy_and_planted_mapping_error_fails()
     {
        let unit_catalog = UnitCatalog::embedded().unwrap();
        let schema = XbrlTaxonomySchema::embedded_us_gaap_small_company().unwrap();
        let bs_linkbase = XbrlCalculationLinkbase::embedded_for_role(
            "http://fasb.org/us-gaap/role/statement/StatementOfFinancialPositionClassified",
        )
        .unwrap();
        let is_linkbase = XbrlCalculationLinkbase::embedded_for_role(
            "http://fasb.org/us-gaap/role/statement/StatementOfIncome",
        )
        .unwrap();

        // US-GAAP small-company classified Balance Sheet & multi-step Income Statement fixture:
        // Assets: Cash 45_000, AR 22_000, Inv 18_000 => CurrentAssets = 85_000
        //         PPE 65_000 => NoncurrentAssets = 65_000 => TotalAssets = 150_000
        // Liabilities: AP 14_000, Accrued 6_000 => CurrentLiabilities = 20_000
        //              Term Loan 40_000 => NoncurrentLiabilities = 40_000 => TotalLiabilities = 60_000
        // Equity: Common Stock 50_000, Retained Earnings (incl. NI) 40_000 => TotalEquity = 90_000
        //         L+E = 150_000
        let bs_stmt = EvaluatedStatementForXbrl {
            definition_name: "us_gaap_small_company_balance_sheet".into(),
            column_labels: vec!["FY2026".into()],
            period_end: DateDay(20_543),
            lines: vec![
                ("cash", 45_000),
                ("accounts_receivable", 22_000),
                ("inventory", 18_000),
                ("current_assets", 85_000),
                ("ppe_net", 65_000),
                ("noncurrent_assets", 65_000),
                ("total_assets", 150_000),
                ("accounts_payable", 14_000),
                ("accrued_liabilities", 6_000),
                ("current_liabilities", 20_000),
                ("long_term_debt", 40_000),
                ("noncurrent_liabilities", 40_000),
                ("total_liabilities", 60_000),
                ("common_stock", 50_000),
                ("retained_earnings", 40_000),
                ("total_equity", 90_000),
                ("liabilities_and_equity", 150_000),
            ]
            .into_iter()
            .map(|(code, amt)| EvaluatedStatementLine {
                code: code.into(),
                unit_id: 1,
                amounts: vec![amt],
            })
            .collect(),
        };

        // Income Statement: Revenues 100_000, COGS 45_000 => GrossProfit = 55_000
        //                   OpEx 22_000 => OperatingIncome = 33_000
        //                   Tax 8_000 => NetIncome = 25_000
        let is_stmt = EvaluatedStatementForXbrl {
            definition_name: "us_gaap_small_company_income_statement".into(),
            column_labels: vec!["FY2026".into()],
            period_end: DateDay(20_543),
            lines: vec![
                ("revenues", 100_000),
                ("cogs", 45_000),
                ("gross_profit", 55_000),
                ("operating_expenses", 22_000),
                ("operating_income", 33_000),
                ("income_tax_expense", 8_000),
                ("net_income", 25_000),
            ]
            .into_iter()
            .map(|(code, amt)| EvaluatedStatementLine {
                code: code.into(),
                unit_id: 1,
                amounts: vec![amt],
            })
            .collect(),
        };

        let bs_mapping = StatementXbrlMapping::us_gaap_small_company_balance_sheet();
        let is_mapping = StatementXbrlMapping::us_gaap_small_company_income_statement();

        let (bs_instance, bs_report) = export_statement_lines_to_xbrl(
            &bs_stmt,
            &bs_mapping,
            "ACME-SMALL-CO",
            &unit_catalog,
            &schema,
            &bs_linkbase,
        )
        .unwrap();
        assert_eq!(bs_report.checks_passed, 8);
        for line in bs_report.log_lines() {
            println!("{line}");
            assert!(line.contains("delta=0 status=PASS"));
        }

        let (is_instance, is_report) = export_statement_lines_to_xbrl(
            &is_stmt,
            &is_mapping,
            "ACME-SMALL-CO",
            &unit_catalog,
            &schema,
            &is_linkbase,
        )
        .unwrap();
        assert_eq!(is_report.checks_passed, 3);
        for line in is_report.log_lines() {
            println!("{line}");
            assert!(line.contains("delta=0 status=PASS"));
        }

        // Write and round-trip parse the XBRL 2.1 instance XML.
        let xml = write_xbrl_instance_xml(&bs_instance);
        let parsed = read_xbrl_instance_xml(&xml).unwrap();
        assert_eq!(parsed, bs_instance);
        let is_xml = write_xbrl_instance_xml(&is_instance);
        assert_eq!(read_xbrl_instance_xml(&is_xml).unwrap(), is_instance);

        // Planted mapping error: swap `gross_profit` and `operating_income` concept bindings in the IS mapping.
        // The calculation linkbase evaluator must detect the discrepancy (`GrossProfit != Revenues - COGS`) and fail!
        let mut defective_mapping = is_mapping;
        defective_mapping.bindings[2].concept = "us-gaap:OperatingIncomeLoss".into();
        defective_mapping.bindings[4].concept = "us-gaap:GrossProfit".into();
        let err = export_statement_lines_to_xbrl(
            &is_stmt,
            &defective_mapping,
            "ACME-SMALL-CO",
            &unit_catalog,
            &schema,
            &is_linkbase,
        )
        .unwrap_err();
        println!("xbrl_calc_check planted_mapping_error_caught={err}");
        assert!(matches!(
            err,
            FormatError::XbrlCalculationInconsistency {
                ref parent_concept,
                reported_mantissa: 33_000,
                computed_children_mantissa: 55_000,
                ..
            } if parent_concept == "us-gaap:GrossProfit"
        ));
    }

    #[test]
    fn income_statement_facts_are_written_in_duration_contexts() {
        let unit_catalog = UnitCatalog::embedded().unwrap();
        let schema = XbrlTaxonomySchema::embedded_us_gaap_small_company().unwrap();
        let linkbase = XbrlCalculationLinkbase::embedded_for_role(
            "http://frankenaccounting.org/role/TypeLevelStatements",
        )
        .unwrap();

        let is_stmt = EvaluatedStatementForXbrl {
            definition_name: "income-statement".into(),
            column_labels: vec!["current".into()],
            period_end: DateDay::from_ymd(2026, 3, 31).unwrap(),
            lines: vec![
                ("revenue", 100_000),
                ("expense", 40_000),
                ("net_income", 60_000),
            ]
            .into_iter()
            .map(|(code, amt)| EvaluatedStatementLine {
                code: code.into(),
                unit_id: 1,
                amounts: vec![amt],
            })
            .collect(),
        };

        let (instance, report) = export_statement_lines_to_xbrl(
            &is_stmt,
            &StatementXbrlMapping::us_gaap_type_level_income_statement(),
            "ACME-CORP",
            &unit_catalog,
            &schema,
            &linkbase,
        )
        .unwrap();
        assert_eq!(instance.period_start.as_deref(), Some("2026-01-01"));
        assert_eq!(instance.period_end, "2026-03-31");
        assert_eq!(report.checks_passed, 1);

        let xml = write_xbrl_instance_xml(&instance);
        assert!(
            xml.contains("<xbrli:startDate>2026-01-01</xbrli:startDate>"),
            "missing startDate in {xml}"
        );
        assert!(
            xml.contains("<xbrli:endDate>2026-03-31</xbrli:endDate>"),
            "missing endDate in {xml}"
        );
        assert!(
            !xml.contains("<xbrli:instant>"),
            "pure duration instance must not emit instant context: {xml}"
        );

        let round_tripped = read_xbrl_instance_xml(&xml).unwrap();
        assert_eq!(round_tripped, instance);
        assert_eq!(write_xbrl_instance_xml(&round_tripped), xml);
    }

    #[test]
    fn no_binding_names_a_concept_outside_the_published_taxonomy_list() {
        // Published FASB US-GAAP Financial Reporting Taxonomy (http://fasb.org/us-gaap/2026):
        // - Statement of Financial Position — Classified (104000):
        //   Assets, AssetsCurrent, AssetsNoncurrent, CashAndCashEquivalentsAtCarryingValue,
        //   AccountsReceivableNetCurrent, InventoryNet, PropertyPlantAndEquipmentNet,
        //   Liabilities, LiabilitiesCurrent, LiabilitiesNoncurrent, AccountsPayableCurrent,
        //   AccruedLiabilitiesCurrent, LongTermDebtNoncurrent, CommonStockValue,
        //   RetainedEarningsAccumulatedDeficit, StockholdersEquity,
        //   StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest,
        //   LiabilitiesAndStockholdersEquity.
        // - Statement of Income (124000):
        //   Revenues, CostOfGoodsAndServicesSold, GrossProfit, OperatingExpenses,
        //   OperatingIncomeLoss, IncomeTaxExpenseBenefit, NetIncomeLoss.
        let published_us_gaap: BTreeSet<&str> = [
            "us-gaap:Assets",
            "us-gaap:AssetsCurrent",
            "us-gaap:AssetsNoncurrent",
            "us-gaap:CashAndCashEquivalentsAtCarryingValue",
            "us-gaap:AccountsReceivableNetCurrent",
            "us-gaap:InventoryNet",
            "us-gaap:PropertyPlantAndEquipmentNet",
            "us-gaap:Liabilities",
            "us-gaap:LiabilitiesCurrent",
            "us-gaap:LiabilitiesNoncurrent",
            "us-gaap:AccountsPayableCurrent",
            "us-gaap:AccruedLiabilitiesCurrent",
            "us-gaap:LongTermDebtNoncurrent",
            "us-gaap:CommonStockValue",
            "us-gaap:RetainedEarningsAccumulatedDeficit",
            "us-gaap:StockholdersEquity",
            "us-gaap:MinorityInterest",
            "us-gaap:StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest",
            "us-gaap:LiabilitiesAndStockholdersEquity",
            "us-gaap:Revenues",
            "us-gaap:CostOfGoodsAndServicesSold",
            "us-gaap:GrossProfit",
            "us-gaap:OperatingExpenses",
            "us-gaap:OperatingIncomeLoss",
            "us-gaap:IncomeTaxExpenseBenefit",
            "us-gaap:NetIncomeLoss",
            "us-gaap:ProfitLoss",
            "us-gaap:NetIncomeLossAttributableToNoncontrollingInterest",
        ]
        .into_iter()
        .collect();

        let check_mapping = |m: &StatementXbrlMapping| -> Result<(), String> {
            for b in &m.bindings {
                if b.concept.starts_with("us-gaap:")
                    && !published_us_gaap.contains(b.concept.as_str())
                {
                    return Err(format!(
                        "xbrl_taxonomy_membership_check mapping={} line={} concept={} status=FAIL (not in published US-GAAP list)",
                        m.mapping_id, b.line_code, b.concept
                    ));
                }
            }
            Ok(())
        };

        for mapping in [
            StatementXbrlMapping::us_gaap_type_level_balance_sheet(),
            StatementXbrlMapping::us_gaap_attributed_balance_sheet(),
            StatementXbrlMapping::us_gaap_type_level_income_statement(),
            StatementXbrlMapping::us_gaap_income_activity(),
            StatementXbrlMapping::us_gaap_small_company_balance_sheet(),
            StatementXbrlMapping::us_gaap_small_company_income_statement(),
        ] {
            if let Err(msg) = check_mapping(&mapping) {
                panic!("{msg}");
            }
        }

        // Cross-check the fa-statements copy of the mappings so the two crates never drift.
        let statements_custom_rs = include_str!("../../fa-statements/src/custom.rs");
        for line in statements_custom_rs.lines() {
            let mut rest = line;
            while let Some(pos) = rest.find("\"us-gaap:") {
                let after = &rest[pos + 1..];
                if let Some(end) = after.find('"') {
                    let qname = &after[..end];
                    assert!(
                        published_us_gaap.contains(qname),
                        "fa-statements/src/custom.rs binds non-published US-GAAP concept `{qname}`"
                    );
                    rest = &after[end + 1..];
                } else {
                    break;
                }
            }
        }

        // Check every calculation arc in the vendored TypeLevelStatements role.
        let tl_linkbase = XbrlCalculationLinkbase::embedded_for_role(
            "http://frankenaccounting.org/role/TypeLevelStatements",
        )
        .unwrap();
        for arc in &tl_linkbase.arcs {
            for c in [&arc.parent_concept, &arc.child_concept] {
                assert!(
                    published_us_gaap.contains(c.as_str()),
                    "TypeLevelStatements calculation arc references non-published concept `{c}`"
                );
            }
        }

        // Planted negative: a mapping copy binding `us-gaap:CurrentPeriodNetIncome` must fail
        // both the published-taxonomy membership list and the vendored schema check.
        let mut planted = StatementXbrlMapping::us_gaap_type_level_balance_sheet();
        planted.bindings[3].concept = "us-gaap:CurrentPeriodNetIncome".into();
        let err_msg =
            check_mapping(&planted).expect_err("planted CurrentPeriodNetIncome must fail");
        println!("{err_msg}");
        assert!(err_msg.contains("us-gaap:CurrentPeriodNetIncome"));
    }

    #[test]
    fn an_activity_concept_in_an_instant_context_fails() {
        let unit_catalog = UnitCatalog::embedded().unwrap();
        let schema = XbrlTaxonomySchema::embedded_us_gaap_small_company().unwrap();
        let linkbase = XbrlCalculationLinkbase::embedded_for_role(
            "http://frankenaccounting.org/role/TypeLevelStatements",
        )
        .unwrap();

        let is_stmt = EvaluatedStatementForXbrl {
            definition_name: "income-statement".into(),
            column_labels: vec!["current".into()],
            period_end: DateDay::from_ymd(2026, 3, 31).unwrap(),
            lines: vec![
                ("revenue", 100_000),
                ("expense", 40_000),
                ("net_income", 60_000),
            ]
            .into_iter()
            .map(|(code, amt)| EvaluatedStatementLine {
                code: code.into(),
                unit_id: 1,
                amounts: vec![amt],
            })
            .collect(),
        };

        // Planted negative: bind activity concept `us-gaap:NetIncomeLoss` with `XbrlPeriodType::Instant`.
        let mut bad_mapping = StatementXbrlMapping::us_gaap_type_level_income_statement();
        bad_mapping.bindings[2].period_type = XbrlPeriodType::Instant;
        let err = export_statement_lines_to_xbrl(
            &is_stmt,
            &bad_mapping,
            "ACME-CORP",
            &unit_catalog,
            &schema,
            &linkbase,
        )
        .expect_err("NetIncomeLoss with Instant period_type must be refused");
        let msg = err.to_string();
        println!("{msg}");
        assert!(msg.contains("us-gaap:NetIncomeLoss"), "{msg}");
        assert!(msg.contains("Instant"), "{msg}");
        assert!(msg.contains("ctx_current"), "{msg}");
    }

    #[test]
    fn noncontrolling_interest_is_not_parent_equity() {
        use crate::{FormatAccount, FormatEntry, FormatLeg};
        use fa_model::EntryClass;
        use fa_money::{Amount, Side};

        let day = DateDay::from_ymd(2026, 3, 31).unwrap();
        let (usd, scale) = UnitCatalog::embedded().unwrap().lookup_code("USD").unwrap();
        let journal = |earnings: i128| {
            let leg = |code: &str, side, amount| FormatLeg {
                account_code: code.into(),
                side,
                amount: Amount::new(usd, amount),
                unit_code: "USD".into(),
                unit_scale: scale,
                memo: None,
            };
            let mut entries = vec![FormatEntry {
                entry_id: "opening".into(),
                effective_date: day,
                recorded_seq: 1,
                class: EntryClass::ORIGINAL,
                description: "capital".into(),
                migrated_from: None,
                legs: vec![
                    leg("1000", Side::Debit, 100_000),
                    leg("3000", Side::Credit, 60_000),
                    leg("3100", Side::Credit, 40_000),
                ],
            }];
            if earnings != 0 {
                entries.push(FormatEntry {
                    entry_id: "income".into(),
                    effective_date: day,
                    recorded_seq: 2,
                    class: EntryClass::ORIGINAL,
                    description: "unclosed income".into(),
                    migrated_from: None,
                    legs: vec![
                        leg("1000", Side::Debit, earnings),
                        leg("4000", Side::Credit, earnings),
                    ],
                });
            }
            FormatJournal::new(
                "parent and minority",
                "USD",
                scale,
                day,
                2,
                [
                    ("1000", AccountType::ASSET, Side::Debit),
                    ("3000", AccountType::EQUITY, Side::Credit),
                    ("3100", AccountType::EQUITY, Side::Credit),
                    ("4000", AccountType::REVENUE, Side::Credit),
                ]
                .into_iter()
                .map(|(code, account_type, normal_side)| FormatAccount {
                    code: code.into(),
                    name: code.into(),
                    account_type,
                    normal_side,
                })
                .collect(),
                entries,
                Vec::new(),
            )
            .unwrap()
        };
        let attribution = XbrlEquityAttribution {
            noncontrolling_accounts: BTreeSet::from(["3100".into()]),
        };
        let fact = |xml: &str, concept: &str| {
            read_xbrl_instance_xml(xml)
                .unwrap()
                .facts
                .into_iter()
                .find(|fact| fact.concept == concept)
                .map(|fact| fact.mantissa)
        };
        for earnings in [0, 20_000] {
            let journal = journal(earnings);
            let xml = write_format_journal_xbrl_xml_with_equity(&journal, &attribution).unwrap();
            assert_eq!(
                fact(&xml, "us-gaap:StockholdersEquity"),
                Some(60_000 + earnings)
            );
            assert_eq!(fact(&xml, "us-gaap:MinorityInterest"), Some(40_000));
            assert_eq!(
                fact(
                    &xml,
                    "us-gaap:StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest"
                ),
                Some(100_000 + earnings)
            );
            assert_eq!(
                fact(&xml, "us-gaap:LiabilitiesAndStockholdersEquity"),
                Some(100_000 + earnings)
            );
            assert_eq!(
                fact(&xml, "us-gaap:RetainedEarningsAccumulatedDeficit"),
                None
            );
            let (coordinate, checks) = verify_format_journal_xbrl_xml(&xml).unwrap();
            assert_eq!(coordinate, journal.coordinate);
            assert_eq!(checks.checks_passed, 3);
            assert_eq!(
                read_xbrl_equity_attribution(&xml).unwrap(),
                Some(attribution.clone())
            );

            // Without journaled attribution all equity belongs to the parent;
            // no account code or label is treated as a minority-interest hint.
            let unclassified = write_format_journal_xbrl_xml(&journal).unwrap();
            assert_eq!(
                fact(&unclassified, "us-gaap:StockholdersEquity"),
                Some(100_000 + earnings)
            );
            assert_eq!(fact(&unclassified, "us-gaap:MinorityInterest"), None);
            assert!(verify_format_journal_xbrl_xml(&unclassified).is_ok());

            // The previous durable profile is still reproducible and verifiable,
            // with its original type-level semantics rather than new facts.
            let legacy = write_legacy_format_journal_xbrl_xml(&journal).unwrap();
            assert_eq!(read_xbrl_equity_attribution(&legacy).unwrap(), None);
            assert_eq!(fact(&legacy, "us-gaap:StockholdersEquity"), Some(100_000));
            assert!(verify_format_journal_xbrl_xml(&legacy).is_ok());

            let altered = xml.replace(
                "noncontrolling_accounts=\"33313030\"",
                "noncontrolling_accounts=\"33303030\"",
            );
            assert!(verify_format_journal_xbrl_xml(&altered).is_err());
            let unknown = xml.replace("parent-minority-v1", "parent-minority-v999");
            assert!(verify_format_journal_xbrl_xml(&unknown).is_err());
        }
        let journal = journal(0);
        for invalid in ["9999", "1000"] {
            let bad = XbrlEquityAttribution {
                noncontrolling_accounts: BTreeSet::from([invalid.into()]),
            };
            assert!(write_format_journal_xbrl_xml_with_equity(&journal, &bad).is_err());
        }
    }

    #[test]
    fn cumulative_export_duration_covers_prior_year_and_preserves_same_year_and_empty_bytes() {
        use crate::{FormatAccount, FormatEntry, FormatLeg};
        use fa_model::EntryClass;
        use fa_money::{Amount, Side};

        let cutoff = DateDay::from_ymd(2026, 3, 31).unwrap();
        let current = DateDay::from_ymd(2026, 3, 15).unwrap();
        let prior = DateDay::from_ymd(2025, 12, 15).unwrap();
        let (usd, scale) = UnitCatalog::embedded().unwrap().lookup_code("USD").unwrap();
        let journal = |dates: &[DateDay]| {
            FormatJournal::new(
                "xbrl-cumulative-interval",
                "USD",
                scale,
                cutoff,
                u64::try_from(dates.len()).unwrap(),
                [
                    ("1000", AccountType::ASSET, Side::Debit),
                    ("4000", AccountType::REVENUE, Side::Credit),
                ]
                .into_iter()
                .map(|(code, account_type, normal_side)| FormatAccount {
                    code: code.into(),
                    name: code.into(),
                    account_type,
                    normal_side,
                })
                .collect(),
                dates
                    .iter()
                    .enumerate()
                    .map(|(index, &effective_date)| FormatEntry {
                        entry_id: format!("entry-{index}"),
                        effective_date,
                        recorded_seq: u64::try_from(index).unwrap().checked_add(1).unwrap(),
                        class: EntryClass::ORIGINAL,
                        description: "cash revenue".into(),
                        migrated_from: None,
                        legs: [("1000", Side::Debit), ("4000", Side::Credit)]
                            .into_iter()
                            .map(|(account, side)| FormatLeg {
                                account_code: account.into(),
                                side,
                                amount: Amount::new(usd, 100),
                                unit_code: "USD".into(),
                                unit_scale: scale,
                                memo: None,
                            })
                            .collect(),
                    })
                    .collect(),
                Vec::new(),
            )
            .unwrap()
        };

        for (dates, start, earnings) in [
            (vec![current], "2026-01-01", 100),
            (Vec::new(), "2026-01-01", 0),
            (vec![prior, current], "2025-12-15", 200),
        ] {
            let journal = journal(&dates);
            let xml = write_format_journal_xbrl_xml(&journal).unwrap();
            let (coordinate, report) = verify_format_journal_xbrl_xml(&xml).unwrap();
            assert_eq!(coordinate, journal.coordinate);
            assert_eq!(report.checks_passed, 3);

            // Pin the corrected parent-equity body, including concept/context
            // spelling, ordering and exact amounts. Cross-year also pins the
            // extended lower bound and both entries' amounts.
            let expected = XbrlInstance {
                entity_identifier: "xbrl-cumulative-interval".into(),
                period_start: Some(start.into()),
                period_end: "2026-03-31".into(),
                facts: [
                    ("us-gaap:Assets", earnings, false),
                    ("us-gaap:Liabilities", 0, false),
                    ("us-gaap:StockholdersEquity", earnings, false),
                    (
                        "us-gaap:StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest",
                        earnings,
                        false,
                    ),
                    ("us-gaap:LiabilitiesAndStockholdersEquity", earnings, false),
                    ("us-gaap:Revenues", earnings, true),
                    ("us-gaap:OperatingExpenses", 0, true),
                    ("us-gaap:NetIncomeLoss", earnings, true),
                ]
                .into_iter()
                .map(|(concept, mantissa, duration)| XbrlFact {
                    concept: concept.into(),
                    context_ref: if duration {
                        "ctx_duration_current".into()
                    } else {
                        "ctx_current".into()
                    },
                    unit_code: "USD".into(),
                    scale,
                    mantissa,
                })
                .collect(),
            };
            let body: String = xml
                .lines()
                .filter(|line| !line.trim().starts_with("<!-- fa:xbrl-coordinate "))
                .map(|line| format!("{line}\n"))
                .collect();
            assert_eq!(body, write_xbrl_instance_xml(&expected));
        }
    }
}
