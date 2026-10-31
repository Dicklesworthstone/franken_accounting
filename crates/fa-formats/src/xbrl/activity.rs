//! XBRL v2's separately selected income activity. Stock remains the canonical
//! interop journal; this input follows the income statement's Closing and
//! verified reversal-lineage law at the same admitted historical coordinate.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{AccountType, Writer};
use fa_money::UnitId;
use fa_time::DateDay;

use super::{XbrlEquityAttribution, coordinate_comment, extract_xml_attr};
use crate::{ExportCoordinate, FormatError, FormatJournal, UnitCatalog, hex_decode, hex_encode};

pub(crate) const INCOME_PROFILE: &str = "closing-excluded-v2";
pub(crate) const INCOME_ROLE: &str =
    "http://frankenaccounting.org/role/TypeLevelStatementsActivityV2";

/// Historical inputs for the v2 exporter. Income balances are debit minus
/// credit, selected by the ordinary income statement's accounting-class law.
/// The caller supplies an authorized complete activity fold, including
/// verified reversal lineage, and both role sets from this same prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlReportInputs {
    pub equity: XbrlEquityAttribution,
    pub noncontrolling_income_accounts: BTreeSet<String>,
    pub known_at_seq: u64,
    pub effective_through: DateDay,
    pub income_balances: BTreeMap<(String, String), i128>,
}

/// Declared v2 metadata. Its self-consistent digest proves neither source
/// completeness nor historical role authority. Book-backed verification
/// independently reselects the activity and both role sets before comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlIncomeAttribution {
    pub noncontrolling_income_accounts: BTreeSet<String>,
    pub activity_digest: [u8; 32],
}

fn invalid(detail: impl Into<String>) -> FormatError {
    FormatError::Parse {
        format: "xbrl_income_activity_v2",
        detail: detail.into(),
    }
}

fn overflow(detail: &str) -> FormatError {
    FormatError::Overflow {
        format: "xbrl_income_activity_v2",
        detail: detail.into(),
    }
}

fn encoded_accounts(accounts: &BTreeSet<String>) -> String {
    accounts
        .iter()
        .map(|code| hex_encode(code.as_bytes()))
        .collect::<Vec<_>>()
        .join(",")
}

impl XbrlReportInputs {
    pub(crate) fn validate(&self, journal: &FormatJournal) -> Result<(), FormatError> {
        self.equity.validate(journal)?;
        if self.known_at_seq != journal.coordinate.known_at_seq
            || self.effective_through != journal.coordinate.effective_through
            || journal.coordinate.account_scope.is_some()
        {
            return Err(invalid(
                "income activity and whole-journal coordinates differ",
            ));
        }
        let accounts = journal
            .accounts
            .iter()
            .map(|account| (account.code.as_str(), account.account_type))
            .collect::<BTreeMap<_, _>>();
        for code in &self.noncontrolling_income_accounts {
            if accounts.get(code.as_str()) != Some(&AccountType::EXPENSE) {
                return Err(invalid(format!(
                    "noncontrolling income account {code:?} must be a historical Expense account"
                )));
            }
        }
        let units = UnitCatalog::embedded()?;
        let mut journal_units = journal
            .entries
            .iter()
            .flat_map(|entry| entry.legs.iter().map(|leg| leg.unit_code.as_str()))
            .collect::<BTreeSet<_>>();
        journal_units.insert(&journal.coordinate.base_unit_code);
        for (code, unit) in self.income_balances.keys() {
            if !matches!(
                accounts.get(code.as_str()),
                Some(&AccountType::REVENUE | &AccountType::EXPENSE)
            ) {
                return Err(invalid(format!(
                    "income activity account {code:?} must be a historical Revenue or Expense account"
                )));
            }
            if units.lookup_code(unit).is_none() || !journal_units.contains(unit.as_str()) {
                return Err(invalid(format!(
                    "income activity names a unit outside journal scope: {unit:?}"
                )));
            }
        }
        Ok(())
    }

    fn attribution(&self) -> Result<XbrlIncomeAttribution, FormatError> {
        let mut w = Writer::new();
        w.u64(self.known_at_seq)
            .i32(self.effective_through.0)
            .u64(self.income_balances.len() as u64);
        // BTreeMap supplies unique rows in canonical (account, unit) order.
        for ((account, unit), net) in &self.income_balances {
            w.str(account).str(unit).i128(*net);
        }
        let bytes = w
            .finish()
            .map_err(|error| invalid(format!("income activity encoding: {error}")))?;
        Ok(XbrlIncomeAttribution {
            noncontrolling_income_accounts: self.noncontrolling_income_accounts.clone(),
            activity_digest: fa_model::domain_digest(b"fa:xbrl-income-activity:v2", &[&bytes]),
        })
    }

    pub(crate) fn metadata(&self, coordinate: &ExportCoordinate) -> Result<String, FormatError> {
        let attribution = self.attribution()?;
        Ok(format!(
            " income_profile=\"{INCOME_PROFILE}\" noncontrolling_income_accounts=\"{}\" income_activity_digest=\"{}\" income_attribution_digest=\"{}\"",
            encoded_accounts(&attribution.noncontrolling_income_accounts),
            hex_encode(&attribution.activity_digest),
            hex_encode(&attribution.digest(coordinate, &self.equity)),
        ))
    }

    /// Per unit: revenue, ordinary expenses, and NCI income. The NCI role
    /// names a debit-normal allocation, including a negative share of losses.
    pub(crate) fn totals(
        &self,
        journal: &FormatJournal,
    ) -> Result<BTreeMap<u32, (i128, i128, i128)>, FormatError> {
        let catalog = UnitCatalog::embedded()?;
        let account_types = journal
            .accounts
            .iter()
            .map(|account| (account.code.as_str(), account.account_type))
            .collect::<BTreeMap<_, _>>();
        let mut totals = BTreeMap::<u32, (i128, i128, i128)>::new();
        for ((account, unit), &net) in &self.income_balances {
            let (UnitId(unit_id), _) = catalog
                .lookup_code(unit)
                .ok_or_else(|| invalid("income unit was not validated"))?;
            let sum = totals.entry(unit_id).or_default();
            let slot = if self.noncontrolling_income_accounts.contains(account) {
                &mut sum.2
            } else if account_types.get(account.as_str()) == Some(&AccountType::REVENUE) {
                let revenue = net
                    .checked_neg()
                    .ok_or_else(|| overflow("revenue negation"))?;
                sum.0 = sum
                    .0
                    .checked_add(revenue)
                    .ok_or_else(|| overflow("revenue sum"))?;
                continue;
            } else {
                &mut sum.1
            };
            *slot = slot
                .checked_add(net)
                .ok_or_else(|| overflow("expense or NCI income sum"))?;
        }
        Ok(totals)
    }
}

impl XbrlIncomeAttribution {
    fn digest(&self, coordinate: &ExportCoordinate, equity: &XbrlEquityAttribution) -> [u8; 32] {
        fa_model::domain_digest(
            b"fa:xbrl-income-attribution:v2",
            &[
                &coordinate.certificate_digest,
                &equity.digest(coordinate),
                encoded_accounts(&self.noncontrolling_income_accounts).as_bytes(),
                &self.activity_digest,
            ],
        )
    }

    pub(crate) fn verify(
        &self,
        xml: &str,
        coordinate: &ExportCoordinate,
        equity: &XbrlEquityAttribution,
    ) -> Result<(), FormatError> {
        let comment = coordinate_comment(xml)?;
        let declared = extract_xml_attr(comment, "income_attribution_digest")
            .ok_or_else(|| invalid("missing income_attribution_digest"))?;
        let expected = self.digest(coordinate, equity);
        if declared != hex_encode(&expected) {
            return Err(invalid(
                "income attribution digest differs from its coordinate and roles",
            ));
        }
        Ok(())
    }
}

/// Read v2's declared profile without treating it as historical authority.
/// Absence preserves both the legacy and parent-minority-v1 encodings.
pub fn read_xbrl_income_attribution(
    xml: &str,
) -> Result<Option<XbrlIncomeAttribution>, FormatError> {
    let comment = coordinate_comment(xml)?;
    let attributes = [
        "noncontrolling_income_accounts",
        "income_activity_digest",
        "income_attribution_digest",
    ];
    let Some(profile) = extract_xml_attr(comment, "income_profile") else {
        if attributes
            .iter()
            .any(|name| extract_xml_attr(comment, name).is_some())
        {
            return Err(invalid("income metadata has no versioned profile"));
        }
        return Ok(None);
    };
    if profile != INCOME_PROFILE {
        return Err(invalid(format!("unsupported income profile {profile:?}")));
    }
    if super::read_xbrl_equity_attribution(xml)?.is_none() {
        return Err(invalid(
            "income activity v2 requires the explicit equity attribution profile",
        ));
    }
    let encoded = extract_xml_attr(comment, "noncontrolling_income_accounts")
        .ok_or_else(|| invalid("missing noncontrolling_income_accounts"))?;
    let mut accounts = BTreeSet::new();
    if !encoded.is_empty() {
        for item in encoded.split(',') {
            if item.is_empty() || !item.len().is_multiple_of(2) || !item.is_ascii() {
                return Err(invalid(
                    "noncanonical noncontrolling income account encoding",
                ));
            }
            let bytes = item
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    match (
                        (pair[0] as char).to_digit(16),
                        (pair[1] as char).to_digit(16),
                    ) {
                        (Some(hi), Some(lo)) => Ok((hi * 16 + lo) as u8),
                        _ => Err(invalid("noncontrolling income account is not hex")),
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            let code = String::from_utf8(bytes)
                .map_err(|_| invalid("noncontrolling income account is not UTF-8"))?;
            if !accounts.insert(code) {
                return Err(invalid("duplicate noncontrolling income account"));
            }
        }
    }
    if encoded_accounts(&accounts) != encoded {
        return Err(invalid(
            "noncontrolling income accounts are not canonically ordered",
        ));
    }
    let encoded_digest = extract_xml_attr(comment, "income_activity_digest")
        .ok_or_else(|| invalid("missing income_activity_digest"))?;
    let activity_digest = hex_decode("xbrl_income_activity_v2", encoded_digest)?;
    if hex_encode(&activity_digest) != encoded_digest {
        return Err(invalid("noncanonical income activity digest"));
    }
    Ok(Some(XbrlIncomeAttribution {
        noncontrolling_income_accounts: accounts,
        activity_digest,
    }))
}

#[cfg(test)]
mod tests;
