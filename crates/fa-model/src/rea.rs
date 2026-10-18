//! REA graph objects and relationship controls (bet A4, plan §4.1, §4.5, bead `fa-l2h`).
//!
//! Defines the canonical payloads for journaled `SchemaChange` controls (`kind = 5..=10`)
//! that create `Party`, `Instrument`, and `LegalEntity` vertices, bind `ExternalId`
//! vertices, update party identifiers (e.g. bank routing/account metadata), and record
//! valid-time `[valid_from, valid_to)` `OWNS`, `CONTROLS`, and `RELATED_TO` edges under
//! `registries/relationship_bases.toml`.

use fa_money::{Amount, ArithmeticBudget, Rate, RateError, UnitId};
use fa_time::DateDay;
use fgdb_delta_types::RelationId;
use fgdb_types::VId;

use crate::canon::{DecodeError, EncodeError, Reader, Writer, strictly_ascending};
use crate::entry::{EvidenceRef, ExternalId};
use crate::erasable::Erasable;
use crate::ids::{Oid, domain_digest};
use crate::limits::{
    MAX_DESCRIPTION_BYTES, MAX_EVIDENCE_PER_ENTRY, MAX_EXTERNAL_ID_BYTES, MAX_EXTERNAL_IDS,
    MAX_SYSTEM_BYTES,
};
use crate::symbols::relation;

pub const SCHEMA_CHANGE_CREATE_PARTY: u16 = 5;
pub const SCHEMA_CHANGE_CREATE_INSTRUMENT: u16 = 6;
pub const SCHEMA_CHANGE_CREATE_LEGAL_ENTITY: u16 = 7;
pub const SCHEMA_CHANGE_BIND_EXTERNAL_ID: u16 = 8;
pub const SCHEMA_CHANGE_RECORD_RELATIONSHIP: u16 = 9;
pub const SCHEMA_CHANGE_UPDATE_PARTY_IDENTIFIERS: u16 = 10;
pub const SCHEMA_CHANGE_RECORD_EVENT: u16 = 11;

pub const EVENT_DIGEST_DOMAIN: &[u8] = b"fa:event:v1";

pub const MAX_REA_CODE_BYTES: usize = 64;
pub const MAX_REA_NAME_BYTES: usize = 256;
pub const MAX_JURISDICTION_BYTES: usize = 64;
pub const MAX_PARTY_IDENTIFIERS: usize = 32;
pub const MAX_IDENTIFIER_KEY_BYTES: usize = 64;
pub const MAX_IDENTIFIER_VAL_BYTES: usize = 256;
pub const MAX_RELATIONSHIP_BASIS_BYTES: usize = 64;
pub const MAX_EVENT_PARTICIPANTS: usize = 32;
pub const MAX_EVENT_RESOURCES: usize = 32;
pub const MAX_EVENT_RESOURCE_LABEL_BYTES: usize = 64;

/// Role/kind of a `Party` vertex (plan §4.1 `Party`, §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PartyKind {
    Customer = 1,
    Vendor = 2,
    Employee = 3,
    Bank = 4,
    RelatedEntity = 5,
    BeneficialOwner = 6,
    Regulator = 7,
    Counterparty = 8,
}

impl PartyKind {
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::Customer,
            2 => Self::Vendor,
            3 => Self::Employee,
            4 => Self::Bank,
            5 => Self::RelatedEntity,
            6 => Self::BeneficialOwner,
            7 => Self::Regulator,
            8 => Self::Counterparty,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Customer => "Customer",
            Self::Vendor => "Vendor",
            Self::Employee => "Employee",
            Self::Bank => "Bank",
            Self::RelatedEntity => "RelatedEntity",
            Self::BeneficialOwner => "BeneficialOwner",
            Self::Regulator => "Regulator",
            Self::Counterparty => "Counterparty",
        }
    }
}

/// Kind of a financial or contractual `Instrument` vertex (plan §4.1 `Instrument`, §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum InstrumentKind {
    BankAccount = 1,
    CreditFacility = 2,
    Card = 3,
    Security = 4,
    Loan = 5,
    Lease = 6,
    Contract = 7,
    CustodyWallet = 8,
}

impl InstrumentKind {
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::BankAccount,
            2 => Self::CreditFacility,
            3 => Self::Card,
            4 => Self::Security,
            5 => Self::Loan,
            6 => Self::Lease,
            7 => Self::Contract,
            8 => Self::CustodyWallet,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BankAccount => "BankAccount",
            Self::CreditFacility => "CreditFacility",
            Self::Card => "Card",
            Self::Security => "Security",
            Self::Loan => "Loan",
            Self::Lease => "Lease",
            Self::Contract => "Contract",
            Self::CustodyWallet => "CustodyWallet",
        }
    }
}

const fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

/// Exact reduced rational ownership fraction `(num / den)` for `OWNS` edges
/// (plan §4.5, `registries/relationship_bases.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OwnershipPct {
    num: i128,
    den: u128,
}

impl OwnershipPct {
    /// Construct a reduced rational `num / den`. Returns `None` if `den == 0`
    /// or `num == i128::MIN`.
    #[must_use]
    pub const fn new(num: i128, den: u128) -> Option<Self> {
        if den == 0 || num == i128::MIN {
            return None;
        }
        if num == 0 {
            return Some(Self { num: 0, den: 1 });
        }
        let abs = num.unsigned_abs();
        let g = gcd_u128(abs, den);
        let rn = (abs / g) as i128;
        let signed = if num < 0 { -rn } else { rn };
        Some(Self {
            num: signed,
            den: den / g,
        })
    }

    #[must_use]
    pub const fn num(self) -> i128 {
        self.num
    }

    #[must_use]
    pub const fn den(self) -> u128 {
        self.den
    }

    /// Whether `self` lies in the legal half-open interval `(0, 1]`.
    #[must_use]
    pub const fn is_valid_pct(self) -> bool {
        self.num > 0 && (self.num as u128) <= self.den
    }

    /// Convert a non-negative `OwnershipPct` into a metered [`Rate`].
    pub fn to_rate(self, budget: &mut ArithmeticBudget<'_, impl Sized>) -> Result<Rate, RateError> {
        let num = u128::try_from(self.num).map_err(|_| RateError::Overflow)?;
        Rate::new(budget, num, self.den)
    }

    /// Multiply two non-negative `OwnershipPct` fractions with cross-cancellation.
    #[must_use]
    pub const fn checked_mul(self, rhs: Self) -> Option<Self> {
        if self.num < 0 || rhs.num < 0 {
            return None;
        }
        if self.num == 0 || rhs.num == 0 {
            return Some(Self { num: 0, den: 1 });
        }
        let a = self.num as u128;
        let b = self.den;
        let c = rhs.num as u128;
        let d = rhs.den;
        let g1 = gcd_u128(a, d);
        let g2 = gcd_u128(c, b);
        let Some(n) = (a / g1).checked_mul(c / g2) else {
            return None;
        };
        let Some(den) = (b / g2).checked_mul(d / g1) else {
            return None;
        };
        if n > (i128::MAX as u128) {
            return None;
        }
        Self::new(n as i128, den)
    }

    /// Add two non-negative `OwnershipPct` fractions in lowest terms.
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        if self.num < 0 || rhs.num < 0 {
            return None;
        }
        if self.num == 0 {
            return Some(rhs);
        }
        if rhs.num == 0 {
            return Some(self);
        }
        let a = self.num as u128;
        let b = self.den;
        let c = rhs.num as u128;
        let d = rhs.den;
        let g = gcd_u128(b, d);
        let bd_div_g = b / g;
        let Some(lcm) = bd_div_g.checked_mul(d) else {
            return None;
        };
        let Some(lhs) = a.checked_mul(d / g) else {
            return None;
        };
        let Some(rhs_scaled) = c.checked_mul(bd_div_g) else {
            return None;
        };
        let Some(sum) = lhs.checked_add(rhs_scaled) else {
            return None;
        };
        if sum > (i128::MAX as u128) {
            return None;
        }
        Self::new(sum as i128, lcm)
    }
}

/// Relationship edge kind between `Party` / `LegalEntity` vertices (plan §4.5,
/// `registries/relationship_bases.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationshipKind {
    /// Voting or beneficial ownership percentage as an exact rational `pct` in `(0, 1]`.
    Owns { pct: OwnershipPct },
    /// Control relationship (`majority_voting_control`, `variable_interest_primary_beneficiary`, `contractual_management`).
    Controls,
    /// Related-party relationship (`common_control`, `executive_officer_or_director`, etc.).
    RelatedTo,
}

impl RelationshipKind {
    #[must_use]
    pub const fn edge_kind_name(&self) -> &'static str {
        match self {
            Self::Owns { .. } => "OWNS",
            Self::Controls => "CONTROLS",
            Self::RelatedTo => "RELATED_TO",
        }
    }

    #[must_use]
    pub const fn relation_id(&self) -> RelationId {
        match self {
            Self::Owns { .. } => relation::OWNS,
            Self::Controls => relation::CONTROLS,
            Self::RelatedTo => relation::RELATED_TO,
        }
    }

    /// Whether `Owns.pct` lies in the legal half-open interval `(0, 1]`.
    #[must_use]
    pub const fn is_valid_pct(&self) -> bool {
        match self {
            Self::Owns { pct } => pct.is_valid_pct(),
            Self::Controls | Self::RelatedTo => true,
        }
    }
}

fn encode_external_ids(w: &mut Writer, ext_ids: &[ExternalId]) {
    w.list(ext_ids, |w, x| {
        w.str(&x.system);
        x.id.encode(w);
    });
}

fn decode_external_ids(r: &mut Reader<'_>) -> Result<Vec<ExternalId>, DecodeError> {
    let list = r.list(MAX_EXTERNAL_IDS, "rea.external_ids", |r| {
        Ok(ExternalId {
            system: r.str(MAX_SYSTEM_BYTES, "external_id.system")?.to_string(),
            id: Erasable::decode(r, MAX_EXTERNAL_ID_BYTES)?,
        })
    })?;
    for pair in list.windows(2) {
        let a = (&pair[0].system, pair[0].id.field_digest());
        let b = (&pair[1].system, pair[1].id.field_digest());
        if a >= b {
            return Err(r.unsorted("rea.external_ids"));
        }
    }
    Ok(list)
}

fn encode_identifiers(w: &mut Writer, identifiers: &[(String, Erasable<String>)]) {
    w.list(identifiers, |w, (k, v)| {
        w.str(k);
        v.encode(w);
    });
}

fn decode_identifiers(r: &mut Reader<'_>) -> Result<Vec<(String, Erasable<String>)>, DecodeError> {
    let list = r.list(MAX_PARTY_IDENTIFIERS, "party.identifiers", |r| {
        Ok((
            r.str(MAX_IDENTIFIER_KEY_BYTES, "party.identifier.key")?
                .to_string(),
            Erasable::decode(r, MAX_IDENTIFIER_VAL_BYTES)?,
        ))
    })?;
    for pair in list.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Err(r.unsorted("party.identifiers"));
        }
    }
    Ok(list)
}

/// Canonical specification for `CreateParty` (`SchemaChange` `kind = 5`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartySpec {
    pub code: String,
    pub kind: PartyKind,
    pub name: Erasable<String>,
    /// Sorted strictly ascending by key (e.g. `"bank_account"`, `"ein"`, `"iban"`, `"routing_aba"`).
    pub identifiers: Vec<(String, Erasable<String>)>,
    /// Sorted strictly ascending by `(system, id.field_digest)`.
    pub external_ids: Vec<ExternalId>,
}

impl PartySpec {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.str(&self.code).u8(self.kind.tag());
        self.name.encode(&mut w);
        encode_identifiers(&mut w, &self.identifiers);
        encode_external_ids(&mut w, &self.external_ids);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let code = r.str(MAX_REA_CODE_BYTES, "party.code")?.to_string();
        if code.is_empty() {
            return Err(r.invalid("party.code"));
        }
        let kind_tag = r.u8("party.kind")?;
        let kind =
            PartyKind::from_tag(kind_tag).ok_or_else(|| r.bad_tag("party.kind", kind_tag))?;
        let name = Erasable::decode(&mut r, MAX_REA_NAME_BYTES)?;
        let identifiers = decode_identifiers(&mut r)?;
        for (k, _) in &identifiers {
            if k.is_empty() {
                return Err(r.invalid("party.identifier.key"));
            }
        }
        let external_ids = decode_external_ids(&mut r)?;
        for ext in &external_ids {
            if ext.system.is_empty() {
                return Err(r.invalid("external_id.system"));
            }
        }
        r.finish()?;
        Ok(Self {
            code,
            kind,
            name,
            identifiers,
            external_ids,
        })
    }
}

/// Canonical specification for `CreateInstrument` (`SchemaChange` `kind = 6`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstrumentSpec {
    pub code: String,
    pub name: String,
    pub kind: InstrumentKind,
    pub unit: UnitId,
    /// The `Party` vertex where this instrument is held (`HELD_AT` edge).
    pub held_at_party: VId,
    /// The GL leaf `Account` vertex that mirrors this instrument (`MIRRORS` edge).
    pub mirrors_account: VId,
    /// Sorted strictly ascending by `(system, id.field_digest)`.
    pub external_ids: Vec<ExternalId>,
}

impl InstrumentSpec {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.str(&self.code)
            .str(&self.name)
            .u8(self.kind.tag())
            .u32(self.unit.0)
            .u128(self.held_at_party.0)
            .u128(self.mirrors_account.0);
        encode_external_ids(&mut w, &self.external_ids);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let code = r.str(MAX_REA_CODE_BYTES, "instrument.code")?.to_string();
        let name = r.str(MAX_REA_NAME_BYTES, "instrument.name")?.to_string();
        if code.is_empty() || name.is_empty() {
            return Err(r.invalid("instrument.code_or_name"));
        }
        let kind_tag = r.u8("instrument.kind")?;
        let kind = InstrumentKind::from_tag(kind_tag)
            .ok_or_else(|| r.bad_tag("instrument.kind", kind_tag))?;
        let unit = UnitId(r.u32("instrument.unit")?);
        let held_at_party = VId(r.u128("instrument.held_at_party")?);
        let mirrors_account = VId(r.u128("instrument.mirrors_account")?);
        let external_ids = decode_external_ids(&mut r)?;
        for ext in &external_ids {
            if ext.system.is_empty() {
                return Err(r.invalid("external_id.system"));
            }
        }
        r.finish()?;
        Ok(Self {
            code,
            name,
            kind,
            unit,
            held_at_party,
            mirrors_account,
            external_ids,
        })
    }
}

/// Canonical specification for `CreateLegalEntity` (`SchemaChange` `kind = 7`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalEntityFullSpec {
    pub code: String,
    pub name: String,
    pub jurisdiction: String,
    pub functional_unit: UnitId,
    pub formed: Option<DateDay>,
    pub dissolved: Option<DateDay>,
    /// Sorted strictly ascending by `(system, id.field_digest)`.
    pub external_ids: Vec<ExternalId>,
}

impl LegalEntityFullSpec {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.str(&self.code)
            .str(&self.name)
            .str(&self.jurisdiction)
            .u32(self.functional_unit.0)
            .opt(self.formed.as_ref(), |w, d| {
                w.i32(d.0);
            })
            .opt(self.dissolved.as_ref(), |w, d| {
                w.i32(d.0);
            });
        encode_external_ids(&mut w, &self.external_ids);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let code = r.str(32, "legal_entity.code")?.to_string();
        let name = r.str(MAX_REA_NAME_BYTES, "legal_entity.name")?.to_string();
        let jurisdiction = r
            .str(MAX_JURISDICTION_BYTES, "legal_entity.jurisdiction")?
            .to_string();
        if code.is_empty() || name.is_empty() || jurisdiction.is_empty() {
            return Err(r.invalid("legal_entity.fields"));
        }
        let functional_unit = UnitId(r.u32("legal_entity.functional_unit")?);
        let formed = r.opt("legal_entity.formed", |r| {
            Ok(DateDay(r.i32("legal_entity.formed")?))
        })?;
        let dissolved = r.opt("legal_entity.dissolved", |r| {
            Ok(DateDay(r.i32("legal_entity.dissolved")?))
        })?;
        if let (Some(f), Some(d)) = (formed, dissolved)
            && f >= d
        {
            return Err(r.invalid("legal_entity.dissolved"));
        }
        let external_ids = decode_external_ids(&mut r)?;
        for ext in &external_ids {
            if ext.system.is_empty() {
                return Err(r.invalid("external_id.system"));
            }
        }
        r.finish()?;
        Ok(Self {
            code,
            name,
            jurisdiction,
            functional_unit,
            formed,
            dissolved,
            external_ids,
        })
    }
}

/// Canonical specification for `BindExternalId` (`SchemaChange` `kind = 8`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalIdBinding {
    pub target_vid: VId,
    pub external_id: ExternalId,
}

impl ExternalIdBinding {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u128(self.target_vid.0).str(&self.external_id.system);
        self.external_id.id.encode(&mut w);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let target_vid = VId(r.u128("external_id.target_vid")?);
        let system = r.str(MAX_SYSTEM_BYTES, "external_id.system")?.to_string();
        if system.is_empty() {
            return Err(r.invalid("external_id.system"));
        }
        let id = Erasable::decode(&mut r, MAX_EXTERNAL_ID_BYTES)?;
        r.finish()?;
        Ok(Self {
            target_vid,
            external_id: ExternalId { system, id },
        })
    }
}

/// Canonical specification for `RecordRelationship` (`SchemaChange` `kind = 9`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationshipSpec {
    pub from: VId,
    pub to: VId,
    pub kind: RelationshipKind,
    pub basis: String,
    pub valid_from: DateDay,
    pub valid_to: Option<DateDay>,
}

impl RelationshipSpec {
    /// Whether this relationship edge is active on `day` (`[valid_from, valid_to)`).
    #[must_use]
    pub fn is_active_on(&self, day: DateDay) -> bool {
        day >= self.valid_from && self.valid_to.is_none_or(|to| day < to)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u128(self.from.0).u128(self.to.0);
        match self.kind {
            RelationshipKind::Owns { pct } => {
                w.u8(1).i128(pct.num()).u128(pct.den());
            }
            RelationshipKind::Controls => {
                w.u8(2);
            }
            RelationshipKind::RelatedTo => {
                w.u8(3);
            }
        }
        w.str(&self.basis)
            .i32(self.valid_from.0)
            .opt(self.valid_to.as_ref(), |w, d| {
                w.i32(d.0);
            });
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let from = VId(r.u128("relationship.from")?);
        let to = VId(r.u128("relationship.to")?);
        let kind = match r.u8("relationship.kind")? {
            1 => {
                let num = r.i128("relationship.pct_num")?;
                let den = r.u128("relationship.pct_den")?;
                let pct =
                    OwnershipPct::new(num, den).ok_or_else(|| r.invalid("relationship.pct"))?;
                RelationshipKind::Owns { pct }
            }
            2 => RelationshipKind::Controls,
            3 => RelationshipKind::RelatedTo,
            tag => return Err(r.bad_tag("relationship.kind", tag)),
        };
        if !kind.is_valid_pct() {
            return Err(r.invalid("relationship.pct_bounds"));
        }
        let basis = r
            .str(MAX_RELATIONSHIP_BASIS_BYTES, "relationship.basis")?
            .to_string();
        if basis.is_empty() {
            return Err(r.invalid("relationship.basis"));
        }
        let valid_from = DateDay(r.i32("relationship.valid_from")?);
        let valid_to = r.opt("relationship.valid_to", |r| {
            Ok(DateDay(r.i32("relationship.valid_to")?))
        })?;
        if let Some(to_day) = valid_to
            && valid_from >= to_day
        {
            return Err(r.invalid("relationship.valid_interval"));
        }
        r.finish()?;
        Ok(Self {
            from,
            to,
            kind,
            basis,
            valid_from,
            valid_to,
        })
    }
}

/// Canonical specification for `UpdatePartyIdentifiers` (`SchemaChange` `kind = 10`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyIdentifierUpdate {
    pub party_vid: VId,
    /// Sorted strictly ascending by key.
    pub identifiers: Vec<(String, Erasable<String>)>,
}

impl PartyIdentifierUpdate {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u128(self.party_vid.0);
        encode_identifiers(&mut w, &self.identifiers);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let party_vid = VId(r.u128("party_update.party_vid")?);
        let identifiers = decode_identifiers(&mut r)?;
        for (k, _) in &identifiers {
            if k.is_empty() {
                return Err(r.invalid("party_update.identifier.key"));
            }
        }
        r.finish()?;
        Ok(Self {
            party_vid,
            identifiers,
        })
    }
}

/// Kind of an REA economic `Event` vertex (plan §4.1 `Event`, §4.5, bead `fa-f3bo`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum EventKind {
    Sale = 1,
    Purchase = 2,
    Receipt = 3,
    Payment = 4,
    Shipment = 5,
    Return = 6,
    Accrual = 7,
    Depreciation = 8,
}

impl EventKind {
    pub const ALL: &[Self] = &[
        Self::Sale,
        Self::Purchase,
        Self::Receipt,
        Self::Payment,
        Self::Shipment,
        Self::Return,
        Self::Accrual,
        Self::Depreciation,
    ];

    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::Sale,
            2 => Self::Purchase,
            3 => Self::Receipt,
            4 => Self::Payment,
            5 => Self::Shipment,
            6 => Self::Return,
            7 => Self::Accrual,
            8 => Self::Depreciation,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sale => "sale",
            Self::Purchase => "purchase",
            Self::Receipt => "receipt",
            Self::Payment => "payment",
            Self::Shipment => "shipment",
            Self::Return => "return",
            Self::Accrual => "accrual",
            Self::Depreciation => "depreciation",
        }
    }

    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "sale" => Self::Sale,
            "purchase" => Self::Purchase,
            "receipt" => Self::Receipt,
            "payment" => Self::Payment,
            "shipment" => Self::Shipment,
            "return" => Self::Return,
            "accrual" => Self::Accrual,
            "depreciation" => Self::Depreciation,
            _ => return None,
        })
    }
}

/// Resource flow line on an REA `Event` (`label`, positive `amount`, optional `instrument` `VId`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventResource {
    pub label: String,
    pub amount: Amount,
    pub instrument: Option<VId>,
}

/// Canonical specification for `RecordEvent` (`SchemaChange` `kind = 11`, plan §4.1 `Event`, §4.5, bead `fa-f3bo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventSpec {
    pub code: String,
    pub kind: EventKind,
    pub occurred_on: DateDay,
    pub description: Erasable<String>,
    /// Sorted strictly ascending by `VId`.
    pub participants: Vec<VId>,
    pub resources: Vec<EventResource>,
    /// Sorted strictly ascending by `(document_oid, doc_commit, role)`. Must be non-empty.
    pub evidence: Vec<EvidenceRef>,
    /// Sorted strictly ascending by `(system, id.field_digest)`.
    pub external_ids: Vec<ExternalId>,
}

impl EventSpec {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.str(&self.code)
            .u8(self.kind.tag())
            .i32(self.occurred_on.0);
        self.description.encode(&mut w);
        w.list(&self.participants, |w, v| {
            w.u128(v.0);
        })
        .list(&self.resources, |w, r| {
            w.str(&r.label)
                .u32(r.amount.unit.0)
                .i128(r.amount.mantissa)
                .opt(r.instrument.as_ref(), |w, inst| {
                    w.u128(inst.0);
                });
        })
        .list(&self.evidence, |w, e| {
            w.fixed(&e.document_oid.0).fixed(&e.doc_commit).u8(e.role);
        });
        encode_external_ids(&mut w, &self.external_ids);
        w.finish()
    }

    /// `BLAKE3("fa:event:v1" ‖ len(canonical(spec)) ‖ canonical(spec))`.
    pub fn event_digest(&self) -> Result<[u8; 32], EncodeError> {
        let bytes = self.encode()?;
        Ok(domain_digest(EVENT_DIGEST_DOMAIN, &[&bytes]))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let code = r.str(MAX_REA_CODE_BYTES, "event.code")?.to_string();
        if code.is_empty() {
            return Err(r.invalid("event.code"));
        }
        let kind_tag = r.u8("event.kind")?;
        let kind =
            EventKind::from_tag(kind_tag).ok_or_else(|| r.bad_tag("event.kind", kind_tag))?;
        let occurred_on = DateDay(r.i32("event.occurred_on")?);
        let description = Erasable::decode(&mut r, MAX_DESCRIPTION_BYTES)?;
        let participants = r.list(MAX_EVENT_PARTICIPANTS, "event.participants", |r| {
            Ok(VId(r.u128("event.participant")?))
        })?;
        if !strictly_ascending(&participants, |v| *v) {
            return Err(r.unsorted("event.participants"));
        }
        let resources = r.list(MAX_EVENT_RESOURCES, "event.resources", |r| {
            let label = r
                .str(MAX_EVENT_RESOURCE_LABEL_BYTES, "event.resource.label")?
                .to_string();
            if label.is_empty() {
                return Err(r.invalid("event.resource.label"));
            }
            let unit = UnitId(r.u32("event.resource.unit")?);
            let mantissa = r.i128("event.resource.mantissa")?;
            if mantissa <= 0 {
                return Err(r.invalid("event.resource.mantissa"));
            }
            let instrument = r.opt("event.resource.instrument", |r| {
                Ok(VId(r.u128("event.resource.instrument")?))
            })?;
            Ok(EventResource {
                label,
                amount: Amount { unit, mantissa },
                instrument,
            })
        })?;
        let evidence = r.list(MAX_EVIDENCE_PER_ENTRY, "event.evidence", |r| {
            Ok(EvidenceRef {
                document_oid: Oid(r.fixed("event.evidence.document_oid")?),
                doc_commit: r.fixed("event.evidence.doc_commit")?,
                role: r.u8("event.evidence.role")?,
            })
        })?;
        if evidence.is_empty() {
            return Err(r.invalid("event.evidence"));
        }
        if !strictly_ascending(&evidence, |e| *e) {
            return Err(r.unsorted("event.evidence"));
        }
        let external_ids = decode_external_ids(&mut r)?;
        for ext in &external_ids {
            if ext.system.is_empty() {
                return Err(r.invalid("external_id.system"));
            }
        }
        r.finish()?;
        Ok(Self {
            code,
            kind,
            occurred_on,
            description,
            participants,
            resources,
            evidence,
            external_ids,
        })
    }
}

/// Decoded REA schema-change control operation (`kind = 5..=11`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReaControlOp {
    CreateParty(PartySpec),
    CreateInstrument(InstrumentSpec),
    CreateLegalEntity(LegalEntityFullSpec),
    BindExternalId(ExternalIdBinding),
    RecordRelationship(RelationshipSpec),
    UpdatePartyIdentifiers(PartyIdentifierUpdate),
    RecordEvent(EventSpec),
}

impl ReaControlOp {
    #[must_use]
    pub const fn is_rea_schema_change_kind(kind: u16) -> bool {
        matches!(kind, 5..=11)
    }

    pub fn decode(kind: u16, bytes: &[u8]) -> Result<Self, DecodeError> {
        match kind {
            SCHEMA_CHANGE_CREATE_PARTY => PartySpec::decode(bytes).map(Self::CreateParty),
            SCHEMA_CHANGE_CREATE_INSTRUMENT => {
                InstrumentSpec::decode(bytes).map(Self::CreateInstrument)
            }
            SCHEMA_CHANGE_CREATE_LEGAL_ENTITY => {
                LegalEntityFullSpec::decode(bytes).map(Self::CreateLegalEntity)
            }
            SCHEMA_CHANGE_BIND_EXTERNAL_ID => {
                ExternalIdBinding::decode(bytes).map(Self::BindExternalId)
            }
            SCHEMA_CHANGE_RECORD_RELATIONSHIP => {
                RelationshipSpec::decode(bytes).map(Self::RecordRelationship)
            }
            SCHEMA_CHANGE_UPDATE_PARTY_IDENTIFIERS => {
                PartyIdentifierUpdate::decode(bytes).map(Self::UpdatePartyIdentifiers)
            }
            SCHEMA_CHANGE_RECORD_EVENT => EventSpec::decode(bytes).map(Self::RecordEvent),
            _ => {
                let r = Reader::new(bytes);
                Err(r.invalid("rea.schema_change_kind"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SealKey;

    #[test]
    fn rea_specs_round_trip_canonically() {
        let key = SealKey([9u8; 32]);
        let name = Erasable::seal(&"Acme Corp".to_string(), None, &key, [1u8; 32], [2u8; 24]);
        let iban = Erasable::seal(
            &"DE89370400440532013000".to_string(),
            None,
            &key,
            [3u8; 32],
            [4u8; 24],
        );
        let ext_val = Erasable::seal(&"VEND-001".to_string(), None, &key, [5u8; 32], [6u8; 24]);

        let party = PartySpec {
            code: "VEND-ACME".to_string(),
            kind: PartyKind::Vendor,
            name,
            identifiers: vec![("iban".to_string(), iban)],
            external_ids: vec![ExternalId {
                system: "netsuite".to_string(),
                id: ext_val.clone(),
            }],
        };
        let encoded = party.encode().unwrap();
        let decoded = PartySpec::decode(&encoded).unwrap();
        assert_eq!(decoded, party);

        let rel = RelationshipSpec {
            from: VId(10),
            to: VId(20),
            kind: RelationshipKind::Owns {
                pct: OwnershipPct::new(3, 4).unwrap(),
            },
            basis: "equity_voting".to_string(),
            valid_from: DateDay::from_ymd(2026, 1, 1).unwrap(),
            valid_to: Some(DateDay::from_ymd(2026, 7, 1).unwrap()),
        };
        let rel_bytes = rel.encode().unwrap();
        assert_eq!(RelationshipSpec::decode(&rel_bytes).unwrap(), rel);
        assert!(rel.is_active_on(DateDay::from_ymd(2026, 3, 15).unwrap()));
        assert!(!rel.is_active_on(DateDay::from_ymd(2026, 7, 1).unwrap()));

        let desc = Erasable::seal(
            &"SaaS annual subscription invoice".to_string(),
            None,
            &key,
            [7u8; 32],
            [8u8; 24],
        );
        let ev = EventSpec {
            code: "EVT-SALE-001".to_string(),
            kind: EventKind::Sale,
            occurred_on: DateDay::from_ymd(2026, 3, 20).unwrap(),
            description: desc,
            participants: vec![VId(10), VId(20)],
            resources: vec![EventResource {
                label: "subscription_fee".to_string(),
                amount: Amount::new(UnitId(1), 120_000_00),
                instrument: Some(VId(30)),
            }],
            evidence: vec![EvidenceRef {
                document_oid: Oid([11u8; 32]),
                doc_commit: [12u8; 32],
                role: 1,
            }],
            external_ids: vec![ExternalId {
                system: "stripe".to_string(),
                id: ext_val,
            }],
        };
        let ev_bytes = ev.encode().unwrap();
        assert_eq!(EventSpec::decode(&ev_bytes).unwrap(), ev);
        assert_eq!(
            ReaControlOp::decode(SCHEMA_CHANGE_RECORD_EVENT, &ev_bytes).unwrap(),
            ReaControlOp::RecordEvent(ev)
        );
    }
}
