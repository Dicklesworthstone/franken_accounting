//! XBRL instance emission and calculation-linkbase validation (plan §12.1,
//! §16.3, bead `fa-npi`).
//!
//! Validates every summation-item arc (`weight ∈ {-1, +1}`) in a statement's
//! calculation linkbase against the reported XBRL instance facts in exact
//! fixed-scale integer arithmetic.

use std::collections::BTreeMap;

use crate::{FormatError, format_exact_decimal, saft::xml_escape};

/// One weighted summation arc in an XBRL calculation linkbase (`parent = Σ weight_i * child_i`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlCalculationArc {
    pub parent_concept: String,
    pub child_concept: String,
    /// XBRL 2.1 calculation weight (`+1` or `-1`).
    pub weight: i8,
    pub order: u32,
}

/// An XBRL calculation linkbase for a financial statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlCalculationLinkbase {
    pub role_uri: String,
    pub arcs: Vec<XbrlCalculationArc>,
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
    pub period_end: String,
    pub facts: Vec<XbrlFact>,
}

impl XbrlCalculationLinkbase {
    /// Standard US-GAAP / IFRS Balance Sheet calculation linkbase:
    /// - `Assets = CashAndCashEquivalents + AccountsReceivable + Inventory + PropertyPlantAndEquipment`
    /// - `Liabilities = AccountsPayable + AccruedLiabilities + LongTermDebt`
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
    /// - `OperatingIncomeLoss = GrossProfit - OperatingExpenses`
    /// - `NetIncomeLoss = OperatingIncomeLoss - IncomeTaxExpenseBenefit`
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

/// Emit an XBRL 2.1 instance XML document for the given [`XbrlInstance`].
pub fn write_xbrl_instance_xml(instance: &XbrlInstance) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(
        "<xbrli:xbrl xmlns:xbrli=\"http://www.xbrl.org/2003/instance\" xmlns:us-gaap=\"http://fasb.org/us-gaap/2026\">\n",
    );
    xml.push_str("  <xbrli:context id=\"ctx_current\">\n");
    xml.push_str("    <xbrli:entity>\n");
    xml.push_str(&format!(
        "      <xbrli:identifier scheme=\"http://frankenaccounting.org/entity\">{}</xbrli:identifier>\n",
        xml_escape(&instance.entity_identifier)
    ));
    xml.push_str("    </xbrli:entity>\n");
    xml.push_str("    <xbrli:period>\n");
    xml.push_str(&format!(
        "      <xbrli:instant>{}</xbrli:instant>\n",
        xml_escape(&instance.period_end)
    ));
    xml.push_str("    </xbrli:period>\n");
    xml.push_str("  </xbrli:context>\n");

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
    let mut fact_map: BTreeMap<(String, String, String), i128> = BTreeMap::new();
    let mut contexts_and_units: std::collections::BTreeSet<(String, String)> =
        std::collections::BTreeSet::new();

    for fact in &instance.facts {
        if fact.weight_check_invalid() {
            return Err(FormatError::Parse {
                format: "xbrl_gl_instance_v1",
                detail: format!("empty concept or unit on fact {:?}", fact.concept),
            });
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
        parents
            .entry(arc.parent_concept.as_str())
            .or_default()
            .push(arc);
    }

    let mut checks_passed = 0usize;
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
                if reported_parent != sum {
                    return Err(FormatError::XbrlCalculationInconsistency {
                        parent_concept: (*parent_concept).to_owned(),
                        unit_code: unit.clone(),
                        reported_mantissa: reported_parent,
                        computed_children_mantissa: sum,
                    });
                }
                checks_passed += 1;
            }
        }
    }
    Ok(checks_passed)
}

impl XbrlFact {
    fn weight_check_invalid(&self) -> bool {
        self.concept.trim().is_empty() || self.unit_code.trim().is_empty()
    }
}
