//! FDIC 12 CFR Part 370 (Recordkeeping for Timely Deposit Insurance
//! Determination) profile: deposit `Instrument` ↔ `Party` participant role
//! edges with ownership-right-and-capacity (`ORC`) codes, aggregation per
//! owner across accounts and capacities, writers for the four prescribed
//! pipe-delimited Part 370 output files (`customer.txt`, `account.txt`,
//! `account_participant.txt`, `pending.txt`) at an end-of-day effective date,
//! and certificate replay (plan §12.6, §15.6 workflow 3, bead `fa-pbm`).
//!
//! No-claim boundary: this module produces the prescribed Part 370 output
//! files and deterministic owner-capacity aggregations from the ledger and
//! instrument-participant graph; regulatory sufficiency is counsel's or the
//! regulator's determination.

use std::collections::{BTreeMap, BTreeSet};

use fa_time::DateDay;
use fgdb_crypto::Hasher;

use crate::{ExportCoordinate, FormatError, format_exact_decimal, hex_encode};

/// Vendored golden FDIC Part 370 Customer File (`customer.txt`).
pub const GOLDEN_PART370_CUSTOMER_TXT: &str =
    include_str!("../corpora/part370_customer_golden.txt");

/// Vendored golden FDIC Part 370 Account File (`account.txt`).
pub const GOLDEN_PART370_ACCOUNT_TXT: &str = include_str!("../corpora/part370_account_golden.txt");

/// Vendored golden FDIC Part 370 Account Participant File (`account_participant.txt`).
pub const GOLDEN_PART370_ACCOUNT_PARTICIPANT_TXT: &str =
    include_str!("../corpora/part370_account_participant_golden.txt");

/// Vendored golden FDIC Part 370 Pending File (`pending.txt`).
pub const GOLDEN_PART370_PENDING_TXT: &str = include_str!("../corpora/part370_pending_golden.txt");

/// Standard Deposit Insurance Amount (`$250,000.00` = `25_000_000` cents at scale 2).
pub const FDIC_SDIA_USD_CENTS: i128 = 25_000_000;

/// Maximum number of unique eligible beneficiaries counted per trust owner under
/// 12 CFR § 330.10 (effective April 1, 2024: up to 5 beneficiaries = $1,250,000).
pub const FDIC_TRUST_MAX_BENEFICIARIES: u32 = 5;

/// FDIC 12 CFR Part 370 Appendix A Ownership Right and Capacity (`ORC`) code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Part370OrcCode {
    /// `SGL` — Single Accounts (12 CFR § 330.6).
    Sgl,
    /// `JNT` — Joint Accounts (12 CFR § 330.9).
    Jnt,
    /// `REV` — Revocable Trust Accounts (12 CFR § 330.10).
    Rev,
    /// `IRR` — Irrevocable Trust Accounts (12 CFR § 330.13).
    Irr,
    /// `CRA` — Certain Retirement Accounts (12 CFR § 330.14(b)(2)).
    Cra,
    /// `EBP` — Employee Benefit Plan Accounts (12 CFR § 330.14).
    Ebp,
    /// `BUS` — Business/Organization Accounts (12 CFR § 330.11).
    Bus,
    /// `GOV1` — Government Accounts: Official Custodian of In-State Time & Savings (12 CFR § 330.15).
    Gov1,
    /// `GOV2` — Government Accounts: Official Custodian of In-State Demand (12 CFR § 330.15).
    Gov2,
    /// `GOV3` — Government Accounts: Official Custodian Out-of-State (12 CFR § 330.15).
    Gov3,
    /// `MSA` — Mortgage Servicing Accounts (12 CFR § 330.7(d)).
    Msa,
    /// `ANC` — Depository Institution as Trustee of an Irrevocable Trust (12 CFR § 330.12).
    Anc,
    /// `PBA` — Public Bond Accounts (12 CFR § 330.15(c)).
    Pba,
    /// `BIA` — Custodian Accounts for American Indians (12 CFR § 330.7(e)).
    Bia,
}

impl Part370OrcCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sgl => "SGL",
            Self::Jnt => "JNT",
            Self::Rev => "REV",
            Self::Irr => "IRR",
            Self::Cra => "CRA",
            Self::Ebp => "EBP",
            Self::Bus => "BUS",
            Self::Gov1 => "GOV1",
            Self::Gov2 => "GOV2",
            Self::Gov3 => "GOV3",
            Self::Msa => "MSA",
            Self::Anc => "ANC",
            Self::Pba => "PBA",
            Self::Bia => "BIA",
        }
    }

    pub fn parse(raw: &str, field_name: &'static str, context: &str) -> Result<Self, FormatError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(FormatError::Parse {
                format: "fdic_part370_v1",
                detail: format!("missing required field `{field_name}` on {context}"),
            });
        }
        match trimmed {
            "SGL" => Ok(Self::Sgl),
            "JNT" => Ok(Self::Jnt),
            "REV" => Ok(Self::Rev),
            "IRR" => Ok(Self::Irr),
            "CRA" => Ok(Self::Cra),
            "EBP" => Ok(Self::Ebp),
            "BUS" => Ok(Self::Bus),
            "GOV1" => Ok(Self::Gov1),
            "GOV2" => Ok(Self::Gov2),
            "GOV3" => Ok(Self::Gov3),
            "MSA" => Ok(Self::Msa),
            "ANC" => Ok(Self::Anc),
            "PBA" => Ok(Self::Pba),
            "BIA" => Ok(Self::Bia),
            other => Err(FormatError::Parse {
                format: "fdic_part370_v1",
                detail: format!(
                    "invalid `{field_name}` value {other:?} on {context}; expected registered FDIC Part 370 ORC code"
                ),
            }),
        }
    }
}

/// Participant role on a deposit `Instrument` ↔ `Party` edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Part370ParticipantRole {
    /// `OWN` — Deposit owner / co-owner.
    Own,
    /// `BEN` — Trust or POD beneficiary.
    Ben,
    /// `AGT` — Agent, custodian, or fiduciary.
    Agt,
    /// `TST` — Trustee.
    Tst,
}

impl Part370ParticipantRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Own => "OWN",
            Self::Ben => "BEN",
            Self::Agt => "AGT",
            Self::Tst => "TST",
        }
    }
}

/// Customer (`Party`) record for FDIC Part 370 `customer.txt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part370Customer {
    pub cs_unique_id: String,
    pub first_name: String,
    pub middle_name: String,
    pub last_name: String,
    pub name_suffix: String,
    pub entity_name: String,
    pub tax_id: String,
    pub tax_id_type: String,
    pub street_address_1: String,
    pub city: String,
    pub state: String,
    pub postal_code: String,
    pub country: String,
}

/// Deposit account (`Instrument { kind: Deposit }`) record at the end-of-day effective date.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part370DepositAccount {
    pub dp_acct_id: String,
    pub primary_cs_unique_id: String,
    /// Account-level ownership right and capacity code (`DP_Right_Capacity`).
    /// Required; `None` or empty string is refused with the field named.
    pub dp_right_capacity: Option<String>,
    pub prod_cat: String,
    pub unit_code: String,
    pub scale: u8,
    pub current_balance_mantissa: i128,
    pub accrued_interest_mantissa: i128,
    pub hold_amount_mantissa: i128,
}

/// Role-typed edge between a deposit `Instrument` and a `Party` participant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part370AccountParticipantEdge {
    pub dp_acct_id: String,
    pub cs_unique_id: String,
    /// Participant ownership right and capacity code (`AP_Right_Capacity`).
    /// Required; `None` or empty string is refused with `AP_Right_Capacity` named.
    pub ap_right_capacity: Option<String>,
    pub participant_role: Part370ParticipantRole,
    /// Ownership share in basis points (`10_000 == 100.00%`).
    pub ownership_pct_bps: u32,
    /// Number of unique eligible beneficiaries for trust capacities (`REV` / `IRR`).
    pub beneficiary_count: u32,
}

/// Provisional hold or pending item (`Pending` entry under receivership or settlement hold)
/// for FDIC Part 370 `pending.txt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part370PendingItem {
    pub dp_acct_id: String,
    pub pending_id: String,
    /// Pending-item ownership right and capacity code (`PD_Right_Capacity`).
    pub pd_right_capacity: Option<String>,
    pub hold_reason: String,
    pub unit_code: String,
    pub scale: u8,
    pub amount_mantissa: i128,
    pub effective_date: DateDay,
}

/// Complete input snapshot for producing FDIC Part 370 output files at an end-of-day effective date.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part370BankBook {
    pub coordinate: ExportCoordinate,
    pub effective_date: DateDay,
    pub sdia_mantissa: i128,
    pub customers: Vec<Part370Customer>,
    pub accounts: Vec<Part370DepositAccount>,
    pub participants: Vec<Part370AccountParticipantEdge>,
    pub pending_items: Vec<Part370PendingItem>,
}

/// Aggregated deposit position for one `(cs_unique_id, orc_code)` pair across all accounts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part370OwnerSummaryRow {
    pub cs_unique_id: String,
    pub orc_code: Part370OrcCode,
    pub unit_code: String,
    pub scale: u8,
    pub aggregate_balance_mantissa: i128,
    pub insured_amount_mantissa: i128,
    pub uninsured_amount_mantissa: i128,
}

/// Certified FDIC Part 370 output bundle containing the four prescribed pipe-delimited
/// files, owner-capacity aggregations, and a domain-separated BLAKE3 certificate digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part370OutputBundle {
    pub coordinate: ExportCoordinate,
    pub effective_date: DateDay,
    pub customer_file: String,
    pub account_file: String,
    pub account_participant_file: String,
    pub pending_file: String,
    pub owner_aggregations: Vec<Part370OwnerSummaryRow>,
    pub certificate_digest_hex: String,
}

impl Part370OutputBundle {
    /// Compute the deterministic domain-separated BLAKE3 certificate digest over the
    /// coordinate, effective date, four Part 370 output files, and owner aggregations.
    #[must_use]
    pub fn compute_certificate_digest(&self) -> [u8; 32] {
        let mut h = Hasher::new_derive_key("fa.formats.fdic_part370.v1");
        h.update(&self.coordinate.certificate_digest);
        h.update(self.effective_date.to_string().as_bytes());
        h.update(&(self.customer_file.len() as u64).to_le_bytes());
        h.update(self.customer_file.as_bytes());
        h.update(&(self.account_file.len() as u64).to_le_bytes());
        h.update(self.account_file.as_bytes());
        h.update(&(self.account_participant_file.len() as u64).to_le_bytes());
        h.update(self.account_participant_file.as_bytes());
        h.update(&(self.pending_file.len() as u64).to_le_bytes());
        h.update(self.pending_file.as_bytes());
        h.update(&(self.owner_aggregations.len() as u64).to_le_bytes());
        for row in &self.owner_aggregations {
            h.update(row.cs_unique_id.as_bytes());
            h.update(&[0]);
            h.update(row.orc_code.as_str().as_bytes());
            h.update(&[0]);
            h.update(&row.aggregate_balance_mantissa.to_le_bytes());
            h.update(&row.insured_amount_mantissa.to_le_bytes());
            h.update(&row.uninsured_amount_mantissa.to_le_bytes());
        }
        h.finalize().0
    }
}

/// Produce the four FDIC 12 CFR Part 370 output files (`customer.txt`, `account.txt`,
/// `account_participant.txt`, `pending.txt`) and owner-capacity aggregations at the
/// end-of-day effective date, refusing any account, participant, or pending item
/// with a missing or invalid capacity code.
pub fn generate_part370_bundle(book: &Part370BankBook) -> Result<Part370OutputBundle, FormatError> {
    if book.sdia_mantissa <= 0 {
        return Err(FormatError::Parse {
            format: "fdic_part370_v1",
            detail: "sdia_mantissa must be positive".into(),
        });
    }

    let mut customer_ids = BTreeSet::new();
    let mut sorted_customers = book.customers.clone();
    sorted_customers.sort_by(|a, b| a.cs_unique_id.cmp(&b.cs_unique_id));
    for cust in &sorted_customers {
        if cust.cs_unique_id.trim().is_empty() {
            return Err(FormatError::Parse {
                format: "fdic_part370_v1",
                detail: "missing required field `CS_Unique_ID` on customer record".into(),
            });
        }
        if !customer_ids.insert(cust.cs_unique_id.clone()) {
            return Err(FormatError::Parse {
                format: "fdic_part370_v1",
                detail: format!("duplicate customer `CS_Unique_ID` {:?}", cust.cs_unique_id),
            });
        }
    }

    let mut account_map: BTreeMap<String, (&Part370DepositAccount, Part370OrcCode, i128)> =
        BTreeMap::new();
    let mut sorted_accounts = book.accounts.clone();
    sorted_accounts.sort_by(|a, b| a.dp_acct_id.cmp(&b.dp_acct_id));
    for acct in &sorted_accounts {
        if acct.dp_acct_id.trim().is_empty() {
            return Err(FormatError::Parse {
                format: "fdic_part370_v1",
                detail: "missing required field `DP_Acct_Identifier` on account record".into(),
            });
        }
        if !customer_ids.contains(&acct.primary_cs_unique_id) {
            return Err(FormatError::Parse {
                format: "fdic_part370_v1",
                detail: format!(
                    "account {:?} references unknown primary customer {:?}",
                    acct.dp_acct_id, acct.primary_cs_unique_id
                ),
            });
        }
        let raw_orc = acct.dp_right_capacity.as_deref().unwrap_or("");
        let orc = Part370OrcCode::parse(
            raw_orc,
            "DP_Right_Capacity",
            &format!("account {}", acct.dp_acct_id),
        )?;
        let total_pi = acct
            .current_balance_mantissa
            .checked_add(acct.accrued_interest_mantissa)
            .ok_or_else(|| FormatError::Overflow {
                format: "fdic_part370_v1",
                detail: format!("principal + interest overflow on account {}", acct.dp_acct_id),
            })?;
        if account_map
            .insert(acct.dp_acct_id.clone(), (acct, orc, total_pi))
            .is_some()
        {
            return Err(FormatError::Parse {
                format: "fdic_part370_v1",
                detail: format!("duplicate account `DP_Acct_Identifier` {:?}", acct.dp_acct_id),
            });
        }
    }

    // Validate participant edges and compute allocable shares per account.
    let mut sorted_participants = book.participants.clone();
    sorted_participants.sort_by(|a, b| {
        a.dp_acct_id
            .cmp(&b.dp_acct_id)
            .then_with(|| a.cs_unique_id.cmp(&b.cs_unique_id))
    });

    let mut bps_by_account: BTreeMap<String, u32> = BTreeMap::new();
    for edge in &sorted_participants {
        let (acct, acct_orc, _) = account_map.get(&edge.dp_acct_id).ok_or_else(|| {
            FormatError::Parse {
                format: "fdic_part370_v1",
                detail: format!(
                    "participant edge references unknown account {:?}",
                    edge.dp_acct_id
                ),
            }
        })?;
        if !customer_ids.contains(&edge.cs_unique_id) {
            return Err(FormatError::Parse {
                format: "fdic_part370_v1",
                detail: format!(
                    "participant edge on account {:?} references unknown customer {:?}",
                    edge.dp_acct_id, edge.cs_unique_id
                ),
            });
        }
        let raw_orc = edge.ap_right_capacity.as_deref().unwrap_or("");
        let edge_orc = Part370OrcCode::parse(
            raw_orc,
            "AP_Right_Capacity",
            &format!(
                "participant {} on account {}",
                edge.cs_unique_id, acct.dp_acct_id
            ),
        )?;
        if edge_orc != *acct_orc {
            return Err(FormatError::Parse {
                format: "fdic_part370_v1",
                detail: format!(
                    "participant {} on account {} has AP_Right_Capacity {} != account DP_Right_Capacity {}",
                    edge.cs_unique_id,
                    acct.dp_acct_id,
                    edge_orc.as_str(),
                    acct_orc.as_str()
                ),
            });
        }
        if edge.participant_role == Part370ParticipantRole::Own {
            if edge.ownership_pct_bps == 0 || edge.ownership_pct_bps > 10_000 {
                return Err(FormatError::Parse {
                    format: "fdic_part370_v1",
                    detail: format!(
                        "invalid `AP_Ownership_Pct_Bps` {} on participant {} for account {}",
                        edge.ownership_pct_bps, edge.cs_unique_id, acct.dp_acct_id
                    ),
                });
            }
            *bps_by_account.entry(acct.dp_acct_id.clone()).or_insert(0) += edge.ownership_pct_bps;
        }
    }

    for acct in &sorted_accounts {
        let total_bps = bps_by_account.get(&acct.dp_acct_id).copied().unwrap_or(0);
        if total_bps != 10_000 {
            return Err(FormatError::Parse {
                format: "fdic_part370_v1",
                detail: format!(
                    "owner `AP_Ownership_Pct_Bps` on account {} sum to {}, expected 10000",
                    acct.dp_acct_id, total_bps
                ),
            });
        }
    }

    // Track remaining insurance limit per (cs_unique_id, orc_code) in deterministic account order.
    let mut remaining_insurance: BTreeMap<(String, Part370OrcCode), i128> = BTreeMap::new();
    let mut owner_agg_map: BTreeMap<(String, Part370OrcCode), Part370OwnerSummaryRow> =
        BTreeMap::new();

    struct ComputedParticipantRow {
        dp_acct_id: String,
        cs_unique_id: String,
        orc_code: Part370OrcCode,
        role: Part370ParticipantRole,
        ownership_pct_bps: u32,
        beneficiary_count: u32,
        scale: u8,
        allocable_mantissa: i128,
        insured_mantissa: i128,
        uninsured_mantissa: i128,
    }

    let mut participant_rows = Vec::with_capacity(sorted_participants.len());
    for edge in &sorted_participants {
        let &(acct, orc, total_pi) = account_map.get(&edge.dp_acct_id).unwrap();
        let allocable = total_pi
            .checked_mul(i128::from(edge.ownership_pct_bps))
            .ok_or_else(|| FormatError::Overflow {
                format: "fdic_part370_v1",
                detail: "allocable share multiplication overflow".into(),
            })?
            / 10_000;

        let cap_multiplier: i128 = match orc {
            Part370OrcCode::Rev | Part370OrcCode::Irr => {
                let count = edge.beneficiary_count.clamp(1, FDIC_TRUST_MAX_BENEFICIARIES);
                i128::from(count)
            }
            _ => 1,
        };
        let capacity_limit =
            book.sdia_mantissa
                .checked_mul(cap_multiplier)
                .ok_or_else(|| FormatError::Overflow {
                    format: "fdic_part370_v1",
                    detail: "insurance limit overflow".into(),
                })?;

        let key = (edge.cs_unique_id.clone(), orc);
        let rem = remaining_insurance.entry(key.clone()).or_insert(capacity_limit);
        let insured = allocable.max(0).min(*rem);
        *rem -= insured;
        let uninsured = allocable - insured;

        let agg = owner_agg_map
            .entry(key)
            .or_insert_with(|| Part370OwnerSummaryRow {
                cs_unique_id: edge.cs_unique_id.clone(),
                orc_code: orc,
                unit_code: acct.unit_code.clone(),
                scale: acct.scale,
                aggregate_balance_mantissa: 0,
                insured_amount_mantissa: 0,
                uninsured_amount_mantissa: 0,
            });
        agg.aggregate_balance_mantissa = agg
            .aggregate_balance_mantissa
            .checked_add(allocable)
            .ok_or_else(|| FormatError::Overflow {
                format: "fdic_part370_v1",
                detail: "owner aggregate balance overflow".into(),
            })?;
        agg.insured_amount_mantissa = agg
            .insured_amount_mantissa
            .checked_add(insured)
            .ok_or_else(|| FormatError::Overflow {
                format: "fdic_part370_v1",
                detail: "owner insured amount overflow".into(),
            })?;
        agg.uninsured_amount_mantissa = agg
            .uninsured_amount_mantissa
            .checked_add(uninsured)
            .ok_or_else(|| FormatError::Overflow {
                format: "fdic_part370_v1",
                detail: "owner uninsured amount overflow".into(),
            })?;

        participant_rows.push(ComputedParticipantRow {
            dp_acct_id: edge.dp_acct_id.clone(),
            cs_unique_id: edge.cs_unique_id.clone(),
            orc_code: orc,
            role: edge.participant_role,
            ownership_pct_bps: edge.ownership_pct_bps,
            beneficiary_count: edge.beneficiary_count,
            scale: acct.scale,
            allocable_mantissa: allocable,
            insured_mantissa: insured,
            uninsured_mantissa: uninsured,
        });
    }

    // Validate pending items.
    let mut sorted_pending = book.pending_items.clone();
    sorted_pending.sort_by(|a, b| {
        a.dp_acct_id
            .cmp(&b.dp_acct_id)
            .then_with(|| a.pending_id.cmp(&b.pending_id))
    });
    let mut pending_rows = Vec::with_capacity(sorted_pending.len());
    for item in &sorted_pending {
        if !account_map.contains_key(&item.dp_acct_id) {
            return Err(FormatError::Parse {
                format: "fdic_part370_v1",
                detail: format!(
                    "pending item {} references unknown account {}",
                    item.pending_id, item.dp_acct_id
                ),
            });
        }
        let raw_orc = item.pd_right_capacity.as_deref().unwrap_or("");
        let orc = Part370OrcCode::parse(
            raw_orc,
            "PD_Right_Capacity",
            &format!("pending item {}", item.pending_id),
        )?;
        pending_rows.push((item, orc));
    }

    // 1. Write Customer File (`customer.txt`)
    let mut customer_file = String::from(
        "CS_Unique_ID|CS_First_Name|CS_Middle_Name|CS_Last_Name|CS_Name_Suffix|CS_Entity_Name|CS_Tax_ID|CS_Tax_ID_Type|CS_Street_Address_1|CS_City|CS_State|CS_Postal_Code|CS_Country\n",
    );
    for c in &sorted_customers {
        customer_file.push_str(&format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            c.cs_unique_id,
            c.first_name,
            c.middle_name,
            c.last_name,
            c.name_suffix,
            c.entity_name,
            c.tax_id,
            c.tax_id_type,
            c.street_address_1,
            c.city,
            c.state,
            c.postal_code,
            c.country
        ));
    }

    // 2. Write Account File (`account.txt`)
    let mut account_file = String::from(
        "DP_Acct_Identifier|CS_Unique_ID|DP_Right_Capacity|DP_Prod_Cat|DP_Cur_Bal|DP_Acc_Int|DP_Total_PI|DP_Hold_Amount|DP_Currency|DP_Effective_Date\n",
    );
    for acct in &sorted_accounts {
        let &(_, orc, total_pi) = account_map.get(&acct.dp_acct_id).unwrap();
        account_file.push_str(&format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            acct.dp_acct_id,
            acct.primary_cs_unique_id,
            orc.as_str(),
            acct.prod_cat,
            format_exact_decimal(acct.current_balance_mantissa, acct.scale),
            format_exact_decimal(acct.accrued_interest_mantissa, acct.scale),
            format_exact_decimal(total_pi, acct.scale),
            format_exact_decimal(acct.hold_amount_mantissa, acct.scale),
            acct.unit_code,
            book.effective_date
        ));
    }

    // 3. Write Account Participant File (`account_participant.txt`)
    let mut account_participant_file = String::from(
        "DP_Acct_Identifier|CS_Unique_ID|AP_Right_Capacity|AP_Participant_Type|AP_Ownership_Pct_Bps|AP_Beneficiary_Count|AP_Allocable_Share|AP_Insured_Share|AP_Uninsured_Share\n",
    );
    for row in &participant_rows {
        account_participant_file.push_str(&format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            row.dp_acct_id,
            row.cs_unique_id,
            row.orc_code.as_str(),
            row.role.as_str(),
            row.ownership_pct_bps,
            row.beneficiary_count,
            format_exact_decimal(row.allocable_mantissa, row.scale),
            format_exact_decimal(row.insured_mantissa, row.scale),
            format_exact_decimal(row.uninsured_mantissa, row.scale)
        ));
    }

    // 4. Write Pending File (`pending.txt`)
    let mut pending_file = String::from(
        "DP_Acct_Identifier|PD_Pending_ID|PD_Right_Capacity|PD_Hold_Reason|PD_Amount|PD_Currency|PD_Effective_Date\n",
    );
    for (item, orc) in &pending_rows {
        pending_file.push_str(&format!(
            "{}|{}|{}|{}|{}|{}|{}\n",
            item.dp_acct_id,
            item.pending_id,
            orc.as_str(),
            item.hold_reason,
            format_exact_decimal(item.amount_mantissa, item.scale),
            item.unit_code,
            item.effective_date
        ));
    }

    let owner_aggregations = owner_agg_map.into_values().collect();

    let mut bundle = Part370OutputBundle {
        coordinate: book.coordinate.clone(),
        effective_date: book.effective_date,
        customer_file,
        account_file,
        account_participant_file,
        pending_file,
        owner_aggregations,
        certificate_digest_hex: String::new(),
    };
    bundle.certificate_digest_hex = hex_encode(&bundle.compute_certificate_digest());
    Ok(bundle)
}

/// Replay and verify an FDIC Part 370 output bundle against the bank book,
/// checking byte-for-byte file equality, owner-capacity aggregations, and the
/// certificate digest (`fa-cqk`).
pub fn verify_part370_bundle(
    book: &Part370BankBook,
    bundle: &Part370OutputBundle,
) -> Result<(), FormatError> {
    let expected_cert = hex_encode(&bundle.compute_certificate_digest());
    if expected_cert != bundle.certificate_digest_hex {
        return Err(FormatError::CertificateMismatch {
            format: "fdic_part370_v1",
            expected_hex: expected_cert,
            observed_hex: bundle.certificate_digest_hex.clone(),
        });
    }
    let replayed = generate_part370_bundle(book)?;
    if replayed != *bundle {
        return Err(FormatError::RoundTripMismatch {
            format: "fdic_part370_v1".into(),
            detail: "replayed Part 370 bundle does not match certified bundle".into(),
        });
    }
    Ok(())
}

/// Canonical fixture bank book for FDIC Part 370 testing and golden verification.
#[must_use]
pub fn fixture_part370_bank_book() -> Part370BankBook {
    let effective_date = DateDay::from_ymd(2026, 4, 10).unwrap();
    Part370BankBook {
        coordinate: ExportCoordinate::compute(
            "first-national-hartford",
            "USD",
            2,
            effective_date,
            370,
            5,
            [0x37; 32],
        ),
        effective_date,
        sdia_mantissa: FDIC_SDIA_USD_CENTS,
        customers: vec![
            Part370Customer {
                cs_unique_id: "CUST-001".into(),
                first_name: "Alice".into(),
                middle_name: "M".into(),
                last_name: "Vance".into(),
                name_suffix: String::new(),
                entity_name: String::new(),
                tax_id: "999-01-0001".into(),
                tax_id_type: "S".into(),
                street_address_1: "100 Oak Street".into(),
                city: "Hartford".into(),
                state: "CT".into(),
                postal_code: "06103".into(),
                country: "US".into(),
            },
            Part370Customer {
                cs_unique_id: "CUST-002".into(),
                first_name: "Bob".into(),
                middle_name: "J".into(),
                last_name: "Vance".into(),
                name_suffix: String::new(),
                entity_name: String::new(),
                tax_id: "999-01-0002".into(),
                tax_id_type: "S".into(),
                street_address_1: "100 Oak Street".into(),
                city: "Hartford".into(),
                state: "CT".into(),
                postal_code: "06103".into(),
                country: "US".into(),
            },
            Part370Customer {
                cs_unique_id: "CUST-003".into(),
                first_name: String::new(),
                middle_name: String::new(),
                last_name: String::new(),
                name_suffix: String::new(),
                entity_name: "Apex Manufacturing LLC".into(),
                tax_id: "99-7000003".into(),
                tax_id_type: "T".into(),
                street_address_1: "500 Industrial Way".into(),
                city: "New Haven".into(),
                state: "CT".into(),
                postal_code: "06511".into(),
                country: "US".into(),
            },
        ],
        accounts: vec![
            Part370DepositAccount {
                dp_acct_id: "DEP-1001".into(),
                primary_cs_unique_id: "CUST-001".into(),
                dp_right_capacity: Some("SGL".into()),
                prod_cat: "DDA".into(),
                unit_code: "USD".into(),
                scale: 2,
                current_balance_mantissa: 18_000_000,
                accrued_interest_mantissa: 50_000,
                hold_amount_mantissa: 0,
            },
            Part370DepositAccount {
                dp_acct_id: "DEP-1002".into(),
                primary_cs_unique_id: "CUST-001".into(),
                dp_right_capacity: Some("SGL".into()),
                prod_cat: "CD".into(),
                unit_code: "USD".into(),
                scale: 2,
                current_balance_mantissa: 10_000_000,
                accrued_interest_mantissa: 200_000,
                hold_amount_mantissa: 0,
            },
            Part370DepositAccount {
                dp_acct_id: "DEP-2001".into(),
                primary_cs_unique_id: "CUST-001".into(),
                dp_right_capacity: Some("JNT".into()),
                prod_cat: "MMDA".into(),
                unit_code: "USD".into(),
                scale: 2,
                current_balance_mantissa: 40_000_000,
                accrued_interest_mantissa: 0,
                hold_amount_mantissa: 0,
            },
            Part370DepositAccount {
                dp_acct_id: "DEP-3001".into(),
                primary_cs_unique_id: "CUST-002".into(),
                dp_right_capacity: Some("REV".into()),
                prod_cat: "SAV".into(),
                unit_code: "USD".into(),
                scale: 2,
                current_balance_mantissa: 45_000_000,
                accrued_interest_mantissa: 100_000,
                hold_amount_mantissa: 0,
            },
            Part370DepositAccount {
                dp_acct_id: "DEP-4001".into(),
                primary_cs_unique_id: "CUST-003".into(),
                dp_right_capacity: Some("BUS".into()),
                prod_cat: "DDA".into(),
                unit_code: "USD".into(),
                scale: 2,
                current_balance_mantissa: 31_000_000,
                accrued_interest_mantissa: 0,
                hold_amount_mantissa: 1_500_000,
            },
        ],
        participants: vec![
            Part370AccountParticipantEdge {
                dp_acct_id: "DEP-1001".into(),
                cs_unique_id: "CUST-001".into(),
                ap_right_capacity: Some("SGL".into()),
                participant_role: Part370ParticipantRole::Own,
                ownership_pct_bps: 10_000,
                beneficiary_count: 0,
            },
            Part370AccountParticipantEdge {
                dp_acct_id: "DEP-1002".into(),
                cs_unique_id: "CUST-001".into(),
                ap_right_capacity: Some("SGL".into()),
                participant_role: Part370ParticipantRole::Own,
                ownership_pct_bps: 10_000,
                beneficiary_count: 0,
            },
            Part370AccountParticipantEdge {
                dp_acct_id: "DEP-2001".into(),
                cs_unique_id: "CUST-001".into(),
                ap_right_capacity: Some("JNT".into()),
                participant_role: Part370ParticipantRole::Own,
                ownership_pct_bps: 5_000,
                beneficiary_count: 0,
            },
            Part370AccountParticipantEdge {
                dp_acct_id: "DEP-2001".into(),
                cs_unique_id: "CUST-002".into(),
                ap_right_capacity: Some("JNT".into()),
                participant_role: Part370ParticipantRole::Own,
                ownership_pct_bps: 5_000,
                beneficiary_count: 0,
            },
            Part370AccountParticipantEdge {
                dp_acct_id: "DEP-3001".into(),
                cs_unique_id: "CUST-002".into(),
                ap_right_capacity: Some("REV".into()),
                participant_role: Part370ParticipantRole::Own,
                ownership_pct_bps: 10_000,
                beneficiary_count: 2,
            },
            Part370AccountParticipantEdge {
                dp_acct_id: "DEP-4001".into(),
                cs_unique_id: "CUST-003".into(),
                ap_right_capacity: Some("BUS".into()),
                participant_role: Part370ParticipantRole::Own,
                ownership_pct_bps: 10_000,
                beneficiary_count: 0,
            },
        ],
        pending_items: vec![Part370PendingItem {
            dp_acct_id: "DEP-4001".into(),
            pending_id: "PND-9001".into(),
            pd_right_capacity: Some("BUS".into()),
            hold_reason: "RECEIVERSHIP_HOLD".into(),
            unit_code: "USD".into(),
            scale: 2,
            amount_mantissa: 1_500_000,
            effective_date,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_bank_book_produces_part370_files_matching_golden_set_and_replays_certificate() {
        let book = fixture_part370_bank_book();
        let bundle = generate_part370_bundle(&book).unwrap();

        assert_eq!(bundle.customer_file, GOLDEN_PART370_CUSTOMER_TXT);
        assert_eq!(bundle.account_file, GOLDEN_PART370_ACCOUNT_TXT);
        assert_eq!(
            bundle.account_participant_file,
            GOLDEN_PART370_ACCOUNT_PARTICIPANT_TXT
        );
        assert_eq!(bundle.pending_file, GOLDEN_PART370_PENDING_TXT);

        // Verify owner-capacity aggregation invariants:
        // CUST-001 in SGL: 282,500.00 -> 250,000.00 insured + 32,500.00 uninsured
        // CUST-001 in JNT: 200,000.00 -> 200,000.00 insured + 0.00 uninsured
        // CUST-002 in JNT: 200,000.00 -> 200,000.00 insured + 0.00 uninsured
        // CUST-002 in REV: 451,000.00 -> 451,000.00 insured + 0.00 uninsured (2 beneficiaries = $500k cap)
        // CUST-003 in BUS: 310,000.00 -> 250,000.00 insured + 60,000.00 uninsured
        assert_eq!(bundle.owner_aggregations.len(), 5);
        for row in &bundle.owner_aggregations {
            assert_eq!(
                row.insured_amount_mantissa + row.uninsured_amount_mantissa,
                row.aggregate_balance_mantissa
            );
        }

        verify_part370_bundle(&book, &bundle).unwrap();
    }

    #[test]
    fn participant_without_capacity_code_is_refused_with_field_named() {
        let mut book = fixture_part370_bank_book();
        book.participants[2].ap_right_capacity = None;
        let err = generate_part370_bundle(&book).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("AP_Right_Capacity"),
            "expected refusal to name missing field AP_Right_Capacity, got: {msg}"
        );
        assert!(
            msg.contains("CUST-001") && msg.contains("DEP-2001"),
            "expected refusal to identify participant and account, got: {msg}"
        );

        // Also test account missing DP_Right_Capacity.
        let mut book2 = fixture_part370_bank_book();
        book2.accounts[0].dp_right_capacity = Some(String::new());
        let err2 = generate_part370_bundle(&book2).unwrap_err();
        assert!(err2.to_string().contains("DP_Right_Capacity"));
    }
}
