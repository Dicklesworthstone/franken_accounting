//! Deposit participant profiles (plan §15.6 workflow 3, bead `fa-p370`).
//!
//! A deposit is an `Instrument { kind: Deposit }`: the bank's liability to
//! its depositors, mirrored by a Liability leaf. FDIC 12 CFR Part 370 reads
//! each deposit account with its ownership right and capacity (`ORC`), its
//! product category and its participants: the owners with their exact
//! ownership shares, beneficiaries, agents and trustees.
//!
//! `RecordDepositProfile` (`SchemaChange` `kind = 23`) journals that whole
//! profile for one deposit from a valid-from date. A later profile of the
//! same deposit takes over from its own date; at one date the profile
//! recorded last is the one known. The profile changes no account and no
//! balance: balances stay the mirrored leaf's register.
//!
//! The participant set is complete and checked as a whole: at least one
//! owner; owner shares in basis points summing to exactly 10,000; other
//! roles carry no share; a beneficiary count only on a trust capacity's
//! owners; the primary customer is an owner.

use fa_time::DateDay;
use fgdb_types::VId;

use crate::canon::{DecodeError, EncodeError, Reader, Writer};

/// `SchemaChange` kind of a deposit participant profile.
pub const SCHEMA_CHANGE_RECORD_DEPOSIT_PROFILE: u16 = 23;
/// Participants one profile names.
pub const MAX_DEPOSIT_PARTICIPANTS: usize = 32;
/// The owners' shares of one deposit, in basis points.
pub const DEPOSIT_WHOLE_BPS: u32 = 10_000;

/// FDIC 12 CFR Part 370 Appendix A ownership right and capacity (`ORC`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum DepositCapacity {
    /// `SGL`: single accounts (12 CFR § 330.6).
    Single = 1,
    /// `JNT`: joint accounts (§ 330.9).
    Joint = 2,
    /// `REV`: revocable trust accounts (§ 330.10).
    RevocableTrust = 3,
    /// `IRR`: irrevocable trust accounts (§ 330.13).
    IrrevocableTrust = 4,
    /// `CRA`: certain retirement accounts (§ 330.14(b)(2)).
    Retirement = 5,
    /// `EBP`: employee benefit plan accounts (§ 330.14).
    EmployeeBenefitPlan = 6,
    /// `BUS`: business or organization accounts (§ 330.11).
    Business = 7,
    /// `GOV1`: official custodian of in-state time and savings (§ 330.15).
    GovernmentInStateTime = 8,
    /// `GOV2`: official custodian of in-state demand deposits (§ 330.15).
    GovernmentInStateDemand = 9,
    /// `GOV3`: official custodian out of state (§ 330.15).
    GovernmentOutOfState = 10,
    /// `MSA`: mortgage servicing accounts (§ 330.7(d)).
    MortgageServicing = 11,
    /// `ANC`: depository institution as trustee of an irrevocable trust (§ 330.12).
    InstitutionTrustee = 12,
    /// `PBA`: public bond accounts (§ 330.15(c)).
    PublicBond = 13,
    /// `BIA`: custodian accounts for American Indians (§ 330.7(e)).
    AmericanIndianCustodian = 14,
}

impl DepositCapacity {
    pub const ALL: [Self; 14] = [
        Self::Single,
        Self::Joint,
        Self::RevocableTrust,
        Self::IrrevocableTrust,
        Self::Retirement,
        Self::EmployeeBenefitPlan,
        Self::Business,
        Self::GovernmentInStateTime,
        Self::GovernmentInStateDemand,
        Self::GovernmentOutOfState,
        Self::MortgageServicing,
        Self::InstitutionTrustee,
        Self::PublicBond,
        Self::AmericanIndianCustodian,
    ];

    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.tag() == tag)
    }

    /// The Part 370 code (`SGL`, `JNT`, ...).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Single => "SGL",
            Self::Joint => "JNT",
            Self::RevocableTrust => "REV",
            Self::IrrevocableTrust => "IRR",
            Self::Retirement => "CRA",
            Self::EmployeeBenefitPlan => "EBP",
            Self::Business => "BUS",
            Self::GovernmentInStateTime => "GOV1",
            Self::GovernmentInStateDemand => "GOV2",
            Self::GovernmentOutOfState => "GOV3",
            Self::MortgageServicing => "MSA",
            Self::InstitutionTrustee => "ANC",
            Self::PublicBond => "PBA",
            Self::AmericanIndianCustodian => "BIA",
        }
    }

    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.code() == code)
    }

    /// The trust capacities, whose owners name their eligible beneficiaries.
    #[must_use]
    pub const fn is_trust(self) -> bool {
        matches!(self, Self::RevocableTrust | Self::IrrevocableTrust)
    }
}

/// Deposit product category (Part 370 account file `DP_Prod_Cat`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum DepositProduct {
    /// `DDA`: demand deposit account.
    Demand = 1,
    /// `NOW`: negotiable order of withdrawal account.
    NegotiableOrder = 2,
    /// `MMDA`: money market deposit account.
    MoneyMarket = 3,
    /// `SAV`: other savings account.
    Savings = 4,
    /// `CD`: time deposit.
    TimeDeposit = 5,
}

impl DepositProduct {
    pub const ALL: [Self; 5] = [
        Self::Demand,
        Self::NegotiableOrder,
        Self::MoneyMarket,
        Self::Savings,
        Self::TimeDeposit,
    ];

    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.tag() == tag)
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Demand => "DDA",
            Self::NegotiableOrder => "NOW",
            Self::MoneyMarket => "MMDA",
            Self::Savings => "SAV",
            Self::TimeDeposit => "CD",
        }
    }

    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.code() == code)
    }
}

/// A participant's role on a deposit (Part 370 `AP_Participant_Type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum DepositRole {
    /// `OWN`: owner or co-owner.
    Owner = 1,
    /// `BEN`: trust or payable-on-death beneficiary.
    Beneficiary = 2,
    /// `AGT`: agent, custodian or fiduciary.
    Agent = 3,
    /// `TST`: trustee.
    Trustee = 4,
}

impl DepositRole {
    pub const ALL: [Self; 4] = [Self::Owner, Self::Beneficiary, Self::Agent, Self::Trustee];

    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.tag() == tag)
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Owner => "OWN",
            Self::Beneficiary => "BEN",
            Self::Agent => "AGT",
            Self::Trustee => "TST",
        }
    }

    /// The name an intent spells (`owner`, `beneficiary`, `agent`, `trustee`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Beneficiary => "beneficiary",
            Self::Agent => "agent",
            Self::Trustee => "trustee",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == name)
    }
}

/// One party's participation in a deposit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositParticipant {
    pub party: VId,
    pub role: DepositRole,
    /// An owner's share in basis points (`1..=10_000`); 0 for other roles.
    pub ownership_bps: u32,
    /// Unique eligible beneficiaries a trust owner names; 0 otherwise.
    pub beneficiary_count: u32,
}

/// Canonical body of `RecordDepositProfile` (`SchemaChange` `kind = 23`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositProfileSpec {
    /// The `Instrument { kind: Deposit }` this profile describes.
    pub instrument: VId,
    pub product: DepositProduct,
    pub capacity: DepositCapacity,
    /// The account's primary customer: one of its owners.
    pub primary_party: VId,
    /// A Liability leaf carrying this deposit's accrued interest, if the
    /// book accrues it apart from the deposit's own leaf.
    pub interest_account: Option<VId>,
    /// Sorted strictly ascending by `(party, role)`.
    pub participants: Vec<DepositParticipant>,
    pub valid_from: DateDay,
}

/// Why a profile is not a complete participant set.
fn whole_set(spec: &DepositProfileSpec) -> Result<(), &'static str> {
    if spec.participants.is_empty() {
        return Err("deposit_profile.participants");
    }
    let mut owners = 0_u32;
    let mut primary_owns = false;
    for p in &spec.participants {
        match p.role {
            DepositRole::Owner => {
                if p.ownership_bps == 0 || p.ownership_bps > DEPOSIT_WHOLE_BPS {
                    return Err("deposit_profile.ownership_bps");
                }
                owners = owners
                    .checked_add(p.ownership_bps)
                    .ok_or("deposit_profile.ownership_bps")?;
                if spec.capacity.is_trust() != (p.beneficiary_count > 0) {
                    return Err("deposit_profile.beneficiary_count");
                }
                primary_owns |= p.party == spec.primary_party;
            }
            DepositRole::Beneficiary | DepositRole::Agent | DepositRole::Trustee => {
                if p.ownership_bps != 0 {
                    return Err("deposit_profile.ownership_bps");
                }
                if p.beneficiary_count != 0 {
                    return Err("deposit_profile.beneficiary_count");
                }
            }
        }
    }
    if owners != DEPOSIT_WHOLE_BPS {
        return Err("deposit_profile.owner_shares");
    }
    if !primary_owns {
        return Err("deposit_profile.primary_party");
    }
    Ok(())
}

impl DepositProfileSpec {
    /// The first rule of the complete participant set this profile breaks,
    /// named by its field (`deposit_profile.owner_shares`, ...).
    pub fn check(&self) -> Result<(), &'static str> {
        if self
            .participants
            .windows(2)
            .any(|w| (w[0].party, w[0].role) >= (w[1].party, w[1].role))
        {
            return Err("deposit_profile.participants");
        }
        whole_set(self)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u128(self.instrument.0)
            .u8(self.product.tag())
            .u8(self.capacity.tag())
            .u128(self.primary_party.0)
            .opt(self.interest_account.as_ref(), |w, v| {
                w.u128(v.0);
            })
            .list(&self.participants, |w, p| {
                w.u128(p.party.0)
                    .u8(p.role.tag())
                    .u32(p.ownership_bps)
                    .u32(p.beneficiary_count);
            })
            .i32(self.valid_from.0);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let instrument = VId(r.u128("deposit_profile.instrument")?);
        let product_tag = r.u8("deposit_profile.product")?;
        let product = DepositProduct::from_tag(product_tag)
            .ok_or_else(|| r.bad_tag("deposit_profile.product", product_tag))?;
        let capacity_tag = r.u8("deposit_profile.capacity")?;
        let capacity = DepositCapacity::from_tag(capacity_tag)
            .ok_or_else(|| r.bad_tag("deposit_profile.capacity", capacity_tag))?;
        let primary_party = VId(r.u128("deposit_profile.primary_party")?);
        let interest_account = r.opt("deposit_profile.interest_account", |r| {
            Ok(VId(r.u128("deposit_profile.interest_account")?))
        })?;
        let participants = r.list(
            MAX_DEPOSIT_PARTICIPANTS,
            "deposit_profile.participants",
            |r| {
                let party = VId(r.u128("deposit_participant.party")?);
                let role_tag = r.u8("deposit_participant.role")?;
                let role = DepositRole::from_tag(role_tag)
                    .ok_or_else(|| r.bad_tag("deposit_participant.role", role_tag))?;
                Ok(DepositParticipant {
                    party,
                    role,
                    ownership_bps: r.u32("deposit_participant.ownership_bps")?,
                    beneficiary_count: r.u32("deposit_participant.beneficiary_count")?,
                })
            },
        )?;
        let valid_from = DateDay(r.i32("deposit_profile.valid_from")?);
        let spec = Self {
            instrument,
            product,
            capacity,
            primary_party,
            interest_account,
            participants,
            valid_from,
        };
        if let Err(field) = spec.check() {
            return Err(r.invalid(field));
        }
        r.finish()?;
        Ok(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(party: u128, bps: u32, beneficiaries: u32) -> DepositParticipant {
        DepositParticipant {
            party: VId(party),
            role: DepositRole::Owner,
            ownership_bps: bps,
            beneficiary_count: beneficiaries,
        }
    }

    fn joint() -> DepositProfileSpec {
        DepositProfileSpec {
            instrument: VId(70),
            product: DepositProduct::MoneyMarket,
            capacity: DepositCapacity::Joint,
            primary_party: VId(1),
            interest_account: Some(VId(80)),
            participants: vec![owner(1, 5_000, 0), owner(2, 5_000, 0)],
            valid_from: DateDay::from_ymd(2026, 1, 1).unwrap(),
        }
    }

    #[test]
    fn a_complete_profile_round_trips_and_its_codes_are_part_370s() {
        let spec = joint();
        let bytes = spec.encode().unwrap();
        assert_eq!(DepositProfileSpec::decode(&bytes).unwrap(), spec);
        assert!(crate::ReaControlOp::is_rea_schema_change_kind(
            SCHEMA_CHANGE_RECORD_DEPOSIT_PROFILE
        ));
        assert_eq!(
            crate::ReaControlOp::decode(SCHEMA_CHANGE_RECORD_DEPOSIT_PROFILE, &bytes).unwrap(),
            crate::ReaControlOp::RecordDepositProfile(spec)
        );
        for capacity in DepositCapacity::ALL {
            assert_eq!(DepositCapacity::from_tag(capacity.tag()), Some(capacity));
            assert_eq!(DepositCapacity::from_code(capacity.code()), Some(capacity));
        }
        let codes: Vec<_> = DepositCapacity::ALL.iter().map(|c| c.code()).collect();
        assert_eq!(
            codes,
            [
                "SGL", "JNT", "REV", "IRR", "CRA", "EBP", "BUS", "GOV1", "GOV2", "GOV3", "MSA",
                "ANC", "PBA", "BIA"
            ]
        );
        for product in DepositProduct::ALL {
            assert_eq!(DepositProduct::from_code(product.code()), Some(product));
        }
        for role in DepositRole::ALL {
            assert_eq!(DepositRole::from_name(role.name()), Some(role));
        }
        assert_eq!(DepositCapacity::from_tag(0), None);
        assert_eq!(DepositCapacity::from_tag(15), None);
    }

    /// Every rule of the complete participant set refuses at decode, naming
    /// the field: the stored bytes can never hold a partial owner set.
    #[test]
    fn an_incomplete_participant_set_is_refused_naming_its_rule() {
        let refused = |edit: &dyn Fn(&mut DepositProfileSpec), field: &str| {
            let mut spec = joint();
            edit(&mut spec);
            assert_eq!(spec.check(), Err(field), "{spec:?}");
            let bytes = spec.encode().unwrap();
            let error = DepositProfileSpec::decode(&bytes).unwrap_err().to_string();
            assert!(error.contains(field), "{error}");
        };
        refused(
            &|s| s.participants[1].ownership_bps = 4_999,
            "deposit_profile.owner_shares",
        );
        refused(
            &|s| s.participants[0].ownership_bps = 0,
            "deposit_profile.ownership_bps",
        );
        refused(&|s| s.participants.clear(), "deposit_profile.participants");
        refused(
            &|s| s.participants.swap(0, 1),
            "deposit_profile.participants",
        );
        refused(
            &|s| s.primary_party = VId(3),
            "deposit_profile.primary_party",
        );
        refused(
            &|s| s.participants[0].beneficiary_count = 2,
            "deposit_profile.beneficiary_count",
        );
        refused(
            &|s| {
                s.capacity = DepositCapacity::RevocableTrust;
            },
            "deposit_profile.beneficiary_count",
        );
        refused(
            &|s| {
                s.participants.push(DepositParticipant {
                    party: VId(9),
                    role: DepositRole::Beneficiary,
                    ownership_bps: 1,
                    beneficiary_count: 0,
                });
            },
            "deposit_profile.ownership_bps",
        );
        // A trust owner names its beneficiaries; a beneficiary row carries
        // neither a share nor a count.
        let mut trust = joint();
        trust.capacity = DepositCapacity::RevocableTrust;
        trust.participants = vec![
            owner(1, 10_000, 3),
            DepositParticipant {
                party: VId(4),
                role: DepositRole::Beneficiary,
                ownership_bps: 0,
                beneficiary_count: 0,
            },
        ];
        assert_eq!(trust.check(), Ok(()));
        let bytes = trust.encode().unwrap();
        assert_eq!(DepositProfileSpec::decode(&bytes).unwrap(), trust);
    }

    #[test]
    fn unknown_tags_and_trailing_bytes_are_refused() {
        let bytes = joint().encode().unwrap();
        let mut product = bytes.clone();
        product[16] = 9;
        assert!(DepositProfileSpec::decode(&product).is_err());
        let mut capacity = bytes.clone();
        capacity[17] = 0;
        assert!(DepositProfileSpec::decode(&capacity).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(DepositProfileSpec::decode(&trailing).is_err());
    }
}
