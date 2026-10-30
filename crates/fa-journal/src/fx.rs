//! Multi-currency FX valuation, rate documents, period-end revaluation, and
//! realized FX settlement (plan §5.2, §5.3, §6.4; bead `fa-s3c`;
//! `FA-INV-01.base`, `FA-INV-01.base-residual`, `FA-INV-01.realized-fx`).
//!
//! Every FX conversion names a registered law from `registries/fx_laws.toml`.
//! Laws that apply a quote cite content-addressed `Rate` documents (`kind = 11`,
//! `role = 3`) in the entry's provenance closure. The posting kernel recomputes the
//! functional-currency (`base_unit`) valuation inside the posting transaction
//! that witnesses the rate documents:
//! - Under `SpotClose` and `PeriodAverage`, each legal entity's legs are
//!   valued via [`fa_money::value_legs`] and any rounding residual is
//!   absorbed into the largest converted leg on the deficient side within
//!   that entity, within the law's exact bound (`FA-INV-01.base`,
//!   `FA-INV-01.base-residual`).
//! - Under `PeriodEndRevaluation`, a `Revaluation` entry adjusts functional
//!   carrying value at period close citing a `PeriodClose` rate document.
//! - Under `SettlementCarryingBasis`, realized FX on settlement posts through
//!   paired conversion account legs whose functional-currency (`base_amount`)
//!   debits and credits net to zero (`FA-INV-01.realized-fx`).
//! - Under `YearEndCloseCarrying`, closing transfers exact recorded native and
//!   functional balances to equity. Its saved source prefix supplies the
//!   carrying amounts; it introduces no rate or conversion residual.
//! - `TranslationCurrentRate` and `RemeasurementTemporal` remain readable in
//!   retained history, but their caller-input calculators do not establish a
//!   native posting basis. Fresh claims are refused until the kernel can
//!   reproduce their complete source populations and cumulative adjustments.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::Cx;
use fa_model::symbols::{label, property};
use fa_model::{
    BaseTotals, EntryClass, EntryPayload, EvidenceRef, Id128, LegPayload, Oid, Reader, Residual,
    SupersessionKind, Writer, domain_digest,
};
use fa_money::rate::{ArithmeticBudget, BudgetLimits};
use fa_money::valuation::{LegValue, ValuationError, value_legs};
use fa_money::{Amount, Rate, RoundingLaw, Side, UnitId, UnitRegistry};
use fa_registry::FxLaws;
use fa_time::{DateDay, PeriodDef};
use fgdb::{Database, VertexRow, WriteTxn};
use fgdb_types::{CommitSeq, VId};

use crate::evidence::{Document, DocumentRecord, Storage, doc_commit, document_oid, document_vid};
use crate::genesis::BookSpec;
use crate::refusal::{Outcome, Refusal, code, exit};

/// Registered `Document.kind` tag for `Rate` (`registries/evidence_policy.toml`).
pub const RATE_DOCUMENT_KIND: u8 = 11;
/// Registered `EvidenceRef.role` tag for `Rate` (`registries/evidence_policy.toml`).
pub const RATE_EVIDENCE_ROLE: u8 = 3;
/// Canonical wire header for `FxRateDocument` payloads.
pub const RATE_DOC_MAGIC: &[u8; 11] = b"FA-FX-RATE\0";
/// Current schema version for `FxRateDocument`.
pub const RATE_DOC_VERSION: u16 = 1;
/// Maximum byte length of `FxRateDocument::source`.
pub const MAX_RATE_SOURCE_BYTES: usize = 128;

const FX_LAW_DOMAIN: &[u8] = b"fa:fx-law:v1";

/// Closed identifier for the registered FX laws (`registries/fx_laws.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FxLawId {
    SpotClose = 1,
    PeriodEndRevaluation = 2,
    PeriodAverage = 3,
    SettlementCarryingBasis = 4,
    TranslationCurrentRate = 5,
    RemeasurementTemporal = 6,
    YearEndCloseCarrying = 8,
    PeriodEndItemRevaluation = 9,
    SettlementAllocatedCarrying = 10,
}

impl FxLawId {
    pub const ALL: [Self; 9] = [
        Self::SpotClose,
        Self::PeriodEndRevaluation,
        Self::PeriodAverage,
        Self::SettlementCarryingBasis,
        Self::TranslationCurrentRate,
        Self::RemeasurementTemporal,
        Self::YearEndCloseCarrying,
        Self::PeriodEndItemRevaluation,
        Self::SettlementAllocatedCarrying,
    ];

    #[must_use]
    pub const fn id(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn version(self) -> u16 {
        1
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SpotClose => "SpotClose",
            Self::PeriodEndRevaluation => "PeriodEndRevaluation",
            Self::PeriodAverage => "PeriodAverage",
            Self::SettlementCarryingBasis => "SettlementCarryingBasis",
            Self::TranslationCurrentRate => "TranslationCurrentRate",
            Self::RemeasurementTemporal => "RemeasurementTemporal",
            Self::YearEndCloseCarrying => "YearEndCloseCarrying",
            Self::PeriodEndItemRevaluation => "PeriodEndItemRevaluation",
            Self::SettlementAllocatedCarrying => "SettlementAllocatedCarrying",
        }
    }

    /// The quote purpose, or `None` when the law transfers recorded carrying
    /// amounts without applying a new rate.
    #[must_use]
    pub const fn required_purpose(self) -> Option<FxRatePurpose> {
        match self {
            Self::SpotClose => Some(FxRatePurpose::SpotClose),
            Self::PeriodEndRevaluation
            | Self::PeriodEndItemRevaluation
            | Self::TranslationCurrentRate
            | Self::RemeasurementTemporal => Some(FxRatePurpose::PeriodClose),
            Self::PeriodAverage => Some(FxRatePurpose::PeriodAverage),
            Self::SettlementCarryingBasis | Self::SettlementAllocatedCarrying => {
                Some(FxRatePurpose::Settlement)
            }
            Self::YearEndCloseCarrying => None,
        }
    }

    #[must_use]
    pub fn oid(self) -> Oid {
        fx_law_oid(self, self.version())
    }

    #[must_use]
    pub fn from_oid(oid: &Oid) -> Option<Self> {
        Self::ALL.into_iter().find(|law| law.oid() == *oid)
    }
}

/// Deterministic `Oid` for a registered `(FxLawId, version)` pair.
#[must_use]
pub fn fx_law_oid(law: FxLawId, version: u16) -> Oid {
    Oid(domain_digest(
        FX_LAW_DOMAIN,
        &[&law.id().to_le_bytes(), &version.to_le_bytes()],
    ))
}

/// Whether `oid` names a registered FX law in `registries/fx_laws.toml`.
#[must_use]
pub fn is_registered_fx_law_oid(oid: &Oid) -> bool {
    FxLawId::from_oid(oid).is_some()
}

/// Registered rate-document purpose (`registries/fx_laws.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FxRatePurpose {
    SpotClose = 1,
    PeriodClose = 2,
    PeriodAverage = 3,
    Settlement = 4,
}

impl FxRatePurpose {
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::SpotClose,
            2 => Self::PeriodClose,
            3 => Self::PeriodAverage,
            4 => Self::Settlement,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpotClose => "spot_close",
            Self::PeriodClose => "period_close",
            Self::PeriodAverage => "period_average",
            Self::Settlement => "settlement",
        }
    }
}

/// Exact conversion terms, separate from when and where a rate was observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FxRateTerms {
    pub base_unit: UnitId,
    pub quote_unit: UnitId,
    pub rate_num: u128,
    pub rate_den: u128,
    pub rounding: RoundingLaw,
}

/// Canonical content-addressed `Rate` document payload (plan §6.4).
///
/// Expresses the exact rational conversion rate `rate_num / rate_den` in
/// `base_unit` per `quote_unit` (foreign unit), reduced by `gcd(rate_num, rate_den) == 1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxRateDocument {
    pub base_unit: UnitId,
    pub quote_unit: UnitId,
    pub rate_num: u128,
    pub rate_den: u128,
    pub rounding: RoundingLaw,
    pub as_of: DateDay,
    pub retrieved_at_ns: u64,
    pub purpose: FxRatePurpose,
    pub source: String,
}

impl FxRateDocument {
    /// Construct a canonical `FxRateDocument`, reducing `(rate_num, rate_den)` to lowest terms.
    pub fn new(
        terms: FxRateTerms,
        as_of: DateDay,
        retrieved_at_ns: u64,
        purpose: FxRatePurpose,
        source: impl Into<String>,
    ) -> Result<Self, Refusal> {
        let FxRateTerms {
            base_unit,
            quote_unit,
            rate_num,
            rate_den,
            rounding,
        } = terms;
        let source = source.into();
        if base_unit == quote_unit {
            return Err(fx_structure(
                "FxRateDocument base_unit and quote_unit must be distinct currencies",
            ));
        }
        if rate_num == 0 || rate_den == 0 {
            return Err(fx_structure(
                "FxRateDocument rate numerator and denominator must both be positive",
            ));
        }
        if source.trim().is_empty() || source.len() > MAX_RATE_SOURCE_BYTES {
            return Err(fx_structure(
                "FxRateDocument source must be 1..=128 non-empty UTF-8 bytes",
            ));
        }
        let g = gcd_u128(rate_num, rate_den);
        Ok(Self {
            base_unit,
            quote_unit,
            rate_num: rate_num / g,
            rate_den: rate_den / g,
            rounding,
            as_of,
            retrieved_at_ns,
            purpose,
            source,
        })
    }

    /// Encode canonical bytes for storage in a `Document` of `kind = RATE_DOCUMENT_KIND`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        if self.base_unit == self.quote_unit
            || self.rate_num == 0
            || self.rate_den == 0
            || gcd_u128(self.rate_num, self.rate_den) != 1
            || self.source.trim().is_empty()
            || self.source.len() > MAX_RATE_SOURCE_BYTES
        {
            return Err(fx_structure(
                "FxRateDocument fields are not in canonical reduced form",
            ));
        }
        let mut w = Writer::new();
        w.fixed(RATE_DOC_MAGIC)
            .u16(RATE_DOC_VERSION)
            .u32(self.base_unit.0)
            .u32(self.quote_unit.0)
            .u128(self.rate_num)
            .u128(self.rate_den)
            .u16(self.rounding.id())
            .i32(self.as_of.0)
            .u64(self.retrieved_at_ns)
            .u8(self.purpose.tag())
            .str(&self.source);
        w.finish().map_err(fx_structure)
    }

    /// Decode and verify canonical `FxRateDocument` bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        let mut r = Reader::new(bytes);
        if r.fixed::<11>("fx_rate.magic").map_err(fx_structure)? != *RATE_DOC_MAGIC
            || r.u16("fx_rate.version").map_err(fx_structure)? != RATE_DOC_VERSION
        {
            return Err(fx_structure("unsupported FxRateDocument header or version"));
        }
        let base_unit = UnitId(r.u32("fx_rate.base_unit").map_err(fx_structure)?);
        let quote_unit = UnitId(r.u32("fx_rate.quote_unit").map_err(fx_structure)?);
        let rate_num = r.u128("fx_rate.rate_num").map_err(fx_structure)?;
        let rate_den = r.u128("fx_rate.rate_den").map_err(fx_structure)?;
        let rounding_id = r.u16("fx_rate.rounding").map_err(fx_structure)?;
        let rounding = RoundingLaw::from_id(rounding_id)
            .ok_or_else(|| fx_structure("unregistered rounding law id in FxRateDocument"))?;
        let as_of = DateDay(r.i32("fx_rate.as_of").map_err(fx_structure)?);
        let retrieved_at_ns = r.u64("fx_rate.retrieved_at_ns").map_err(fx_structure)?;
        let purpose_tag = r.u8("fx_rate.purpose").map_err(fx_structure)?;
        let purpose = FxRatePurpose::from_tag(purpose_tag)
            .ok_or_else(|| fx_structure("unregistered purpose tag in FxRateDocument"))?;
        let source = r
            .str(MAX_RATE_SOURCE_BYTES, "fx_rate.source")
            .map_err(fx_structure)?
            .to_string();
        r.finish().map_err(fx_structure)?;
        if base_unit == quote_unit
            || rate_num == 0
            || rate_den == 0
            || gcd_u128(rate_num, rate_den) != 1
            || source.trim().is_empty()
        {
            return Err(fx_structure("non-canonical FxRateDocument payload"));
        }
        let doc = Self {
            base_unit,
            quote_unit,
            rate_num,
            rate_den,
            rounding,
            as_of,
            retrieved_at_ns,
            purpose,
            source,
        };
        if doc.canonical_bytes()?.as_slice() != bytes {
            return Err(fx_structure(
                "FxRateDocument bytes do not round-trip canonically",
            ));
        }
        Ok(doc)
    }

    /// Build a journalable [`Document`] (`kind = RATE_DOCUMENT_KIND`) for this rate document.
    pub fn document(
        &self,
        book_id: Id128,
        retrieved_by: VId,
        grade: u8,
    ) -> Result<Document, Refusal> {
        Ok(Document {
            book_id,
            kind: RATE_DOCUMENT_KIND,
            mime: "application/vnd.franken.fx-rate.v1".to_string(),
            grade,
            retrieved_by,
            bytes: self.canonical_bytes()?,
        })
    }

    /// Public document commitment (`doc_commit`) for this rate document.
    pub fn doc_commit(&self) -> Result<[u8; 32], Refusal> {
        Ok(doc_commit(RATE_DOCUMENT_KIND, &self.canonical_bytes()?))
    }

    /// Book-scoped `Oid` for this rate document.
    pub fn oid(&self, book_id: Id128) -> Result<Oid, Refusal> {
        Ok(document_oid(book_id, &self.doc_commit()?))
    }

    /// `EvidenceRef` with `role = RATE_EVIDENCE_ROLE` for citing this rate document on an entry.
    pub fn evidence_ref(&self, book_id: Id128) -> Result<EvidenceRef, Refusal> {
        let commitment = self.doc_commit()?;
        Ok(EvidenceRef {
            document_oid: document_oid(book_id, &commitment),
            doc_commit: commitment,
            role: RATE_EVIDENCE_ROLE,
        })
    }

    /// Materialize the exact [`Rate`] under `budget`.
    pub fn to_rate(&self, budget: &mut ArithmeticBudget<'_, impl Sized>) -> Result<Rate, Refusal> {
        Rate::new(budget, self.rate_num, self.rate_den).map_err(fx_structure)
    }
}

/// Value a multi-currency proposal's legs into `spec.base_unit` under `law`
/// (`SpotClose` or `PeriodAverage`) using `rate_docs`, populating
/// `leg.base_amount`, `proposal.base_totals`, and `proposal.evidence`.
///
/// In a multi-entity book, valuation runs per legal entity so that any
/// rounding residual is absorbed strictly within its legal entity
/// (`FA-INV-01.base`, `FA-INV-01.base-residual`).
pub fn value_proposal(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    mut proposal: EntryPayload,
    spec: &BookSpec,
    units: &UnitRegistry,
    law: FxLawId,
    rate_docs: &[FxRateDocument],
) -> Result<EntryPayload, Refusal> {
    if !matches!(law, FxLawId::SpotClose | FxLawId::PeriodAverage) {
        return Err(fx_structure(
            "value_proposal supports SpotClose and PeriodAverage; use plan_revaluation or plan_realized_fx_settlement for the other laws",
        ));
    }
    if rate_docs.is_empty() {
        return Err(fx_structure(
            "FX valuation requires at least one FxRateDocument",
        ));
    }
    let leg_entities = crate::entity::leg_entities(spec, &proposal.legs).map_err(|e| match e {
        crate::entity::LegEntityError::OtherDimension => {
            fx_structure("unsupported non-entity dimension on leg")
        }
        crate::entity::LegEntityError::Refused(r) => r,
    })?;

    let computed = compute_entity_valuations(
        budget,
        &proposal.legs,
        &leg_entities,
        spec.base_unit,
        proposal.effective_date,
        units,
        law,
        rate_docs,
    )?;

    for (leg, base_amt) in proposal.legs.iter_mut().zip(computed.base_amounts) {
        leg.base_amount = Some(base_amt);
    }

    let mut rate_doc_oids = Vec::with_capacity(rate_docs.len());
    for doc in rate_docs {
        let ev = doc.evidence_ref(proposal.book_id)?;
        rate_doc_oids.push(ev.document_oid);
        if !proposal.evidence.contains(&ev) {
            proposal.evidence.push(ev);
        }
    }
    proposal.evidence.sort();
    proposal.evidence.dedup();
    rate_doc_oids.sort();
    rate_doc_oids.dedup();

    proposal.base_totals = Some(BaseTotals {
        unit_id: spec.base_unit.0,
        debits: computed.total_debits,
        credits: computed.total_credits,
        fx_law_oid: law.oid(),
        rate_doc_oids,
        residual: computed.residual,
    });
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).map_err(fx_structure)?;
    proposal.validate().map_err(fx_structure)?;
    Ok(proposal)
}

/// Plan a `Revaluation` entry (`EntryClass::REVALUATION`) under
/// [`FxLawId::PeriodEndRevaluation`] (plan §5.2, §6.4).
///
/// Revalues `foreign_balance` (positive magnitude on `balance_side` in
/// `close_rate_doc.quote_unit`) at `close_rate_doc` into `close_rate_doc.base_unit`
/// and posts the functional-currency carrying adjustment `(revalued_base - carrying_base_balance)`
/// between `revaluation_account` (valuation adjustment / multi-currency account)
/// and `unrealized_fx_account`, citing `close_rate_doc`.
#[allow(clippy::too_many_arguments)]
pub fn plan_revaluation(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    mut template: EntryPayload,
    revaluation_account: VId,
    balance_side: Side,
    foreign_balance: Amount,
    carrying_base_balance: Amount,
    unrealized_fx_account: VId,
    close_rate_doc: &FxRateDocument,
    dimensions: Vec<(u32, VId)>,
    units: &UnitRegistry,
) -> Result<EntryPayload, Refusal> {
    if template.class != EntryClass::REVALUATION
        || !template.legs.is_empty()
        || template.base_totals.is_some()
    {
        return Err(fx_structure(
            "plan_revaluation requires a Revaluation template with empty legs and no base_totals",
        ));
    }
    if close_rate_doc.purpose != FxRatePurpose::PeriodClose {
        return Err(fx_structure(
            "PeriodEndRevaluation requires an FxRateDocument with purpose = PeriodClose",
        ));
    }
    if close_rate_doc.as_of != template.effective_date {
        return Err(fx_structure(
            "PeriodEndRevaluation requires rate document as_of == entry effective_date",
        ));
    }
    if foreign_balance.unit != close_rate_doc.quote_unit || foreign_balance.mantissa <= 0 {
        return Err(fx_structure(
            "foreign_balance must be a positive amount in close_rate_doc.quote_unit",
        ));
    }
    if carrying_base_balance.unit != close_rate_doc.base_unit || carrying_base_balance.mantissa <= 0
    {
        return Err(fx_structure(
            "carrying_base_balance must be a positive amount in close_rate_doc.base_unit",
        ));
    }
    let rate = close_rate_doc.to_rate(budget)?;
    let revalued = foreign_balance
        .convert(
            budget,
            close_rate_doc.base_unit,
            &rate,
            close_rate_doc.rounding,
            units,
        )
        .map_err(fx_structure)?;
    let delta = revalued
        .mantissa
        .checked_sub(carrying_base_balance.mantissa)
        .ok_or_else(|| fx_structure("revaluation delta overflow"))?;
    if delta == 0 {
        return Err(fx_structure(
            "revalued functional amount equals carrying basis; zero-delta revaluation posts no entry",
        ));
    }
    let adj_mag = delta.abs();
    let adj_amt = Amount::new(close_rate_doc.base_unit, adj_mag);
    let (reval_leg_side, unrealized_side) = if delta > 0 {
        (balance_side, opposite(balance_side))
    } else {
        (opposite(balance_side), balance_side)
    };

    let mut leg0 = LegPayload::simple(reval_leg_side, revaluation_account, adj_amt);
    leg0.base_amount = Some(adj_amt);
    leg0.dimension_set = dimensions.clone();

    let mut leg1 = LegPayload::simple(unrealized_side, unrealized_fx_account, adj_amt);
    leg1.base_amount = Some(adj_amt);
    leg1.dimension_set = dimensions;

    let ev = close_rate_doc.evidence_ref(template.book_id)?;
    if !template.evidence.contains(&ev) {
        template.evidence.push(ev);
    }
    template.evidence.sort();
    template.evidence.dedup();

    template.legs = vec![leg0, leg1];
    template.unit_totals = EntryPayload::fold_unit_totals(&template.legs).map_err(fx_structure)?;
    template.base_totals = Some(BaseTotals {
        unit_id: close_rate_doc.base_unit.0,
        debits: adj_mag,
        credits: adj_mag,
        fx_law_oid: FxLawId::PeriodEndRevaluation.oid(),
        rate_doc_oids: vec![ev.document_oid],
        residual: None,
    });
    template.validate().map_err(fx_structure)?;
    Ok(template)
}

/// Plan a realized FX settlement entry under [`FxLawId::SettlementCarryingBasis`]
/// using paired conversion account postings (`FA-INV-01.realized-fx`, plan §5.2).
///
/// The entry relieves `foreign_amount` on `settled_account` (on `settled_side`,
/// e.g. `Side::Credit` to relieve a debit AR open item) at its `carrying_base_amount`,
/// pairs it through `conversion_account` in both `quote_unit` and `base_unit`
/// so `conversion_account` nets to zero in functional currency, posts the
/// settlement consideration `settlement_base` on `settlement_account`, and
/// posts any realized FX gain/loss on `realized_fx_account`.
#[allow(clippy::too_many_arguments)]
pub fn plan_realized_fx_settlement(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    mut template: EntryPayload,
    settled_account: VId,
    settled_side: Side,
    foreign_amount: Amount,
    carrying_base_amount: Amount,
    settlement_account: VId,
    conversion_account: VId,
    realized_fx_account: VId,
    settlement_rate_doc: &FxRateDocument,
    dimensions: Vec<(u32, VId)>,
    units: &UnitRegistry,
) -> Result<EntryPayload, Refusal> {
    if !template.legs.is_empty() || template.base_totals.is_some() {
        return Err(fx_structure(
            "plan_realized_fx_settlement requires a template with empty legs and no base_totals",
        ));
    }
    if settlement_rate_doc.purpose != FxRatePurpose::Settlement {
        return Err(fx_structure(
            "SettlementCarryingBasis requires an FxRateDocument with purpose = Settlement",
        ));
    }
    if foreign_amount.unit != settlement_rate_doc.quote_unit || foreign_amount.mantissa <= 0 {
        return Err(fx_structure(
            "foreign_amount must be a positive amount in settlement_rate_doc.quote_unit",
        ));
    }
    let base_unit = settlement_rate_doc.base_unit;
    if carrying_base_amount.unit != base_unit || carrying_base_amount.mantissa < 0 {
        return Err(fx_structure(
            "carrying_base_amount must be a nonnegative amount in settlement_rate_doc.base_unit",
        ));
    }
    if settled_account == conversion_account
        || settlement_account == conversion_account
        || realized_fx_account == conversion_account
    {
        return Err(fx_structure(
            "conversion_account must be distinct from settled, settlement, and realized FX accounts",
        ));
    }

    let rate = settlement_rate_doc.to_rate(budget)?;
    let settlement_base = foreign_amount
        .convert(
            budget,
            base_unit,
            &rate,
            settlement_rate_doc.rounding,
            units,
        )
        .map_err(fx_structure)?;
    if settlement_base.mantissa <= 0 {
        return Err(fx_structure(
            "converted settlement_base amount must be positive",
        ));
    }

    let opp_side = opposite(settled_side);

    // 1. Relieve settled foreign-currency item at carrying functional basis.
    let mut leg_settled = LegPayload::simple(settled_side, settled_account, foreign_amount);
    leg_settled.base_amount = Some(carrying_base_amount);
    leg_settled.dimension_set = dimensions.clone();

    // 2. Paired foreign-currency leg on conversion_account at carrying functional basis.
    let mut leg_conv_fx = LegPayload::simple(opp_side, conversion_account, foreign_amount);
    leg_conv_fx.base_amount = Some(carrying_base_amount);
    leg_conv_fx.dimension_set = dimensions.clone();

    let mut legs = vec![leg_settled, leg_conv_fx];
    // 3. Pair the carrying base amount on conversion_account when nonzero.
    // A rounded zero relief remains recorded on the two foreign legs; it
    // must not invent a zero native posting, which the model forbids.
    if carrying_base_amount.mantissa != 0 {
        let mut leg_conv_base =
            LegPayload::simple(settled_side, conversion_account, carrying_base_amount);
        leg_conv_base.base_amount = Some(carrying_base_amount);
        leg_conv_base.dimension_set = dimensions.clone();
        legs.push(leg_conv_base);
    }

    // 4. Settlement consideration leg on settlement_account in base_unit.
    let mut leg_settlement = LegPayload::simple(opp_side, settlement_account, settlement_base);
    leg_settlement.base_amount = Some(settlement_base);
    leg_settlement.dimension_set = dimensions.clone();

    legs.push(leg_settlement);

    // 5. Realized FX gain/loss leg when settlement_base != carrying_base_amount.
    let diff = settlement_base
        .mantissa
        .checked_sub(carrying_base_amount.mantissa)
        .ok_or_else(|| fx_structure("realized FX difference overflow"))?;
    if diff != 0 {
        let fx_amt = Amount::new(base_unit, diff.abs());
        // On `settled_side` we have `carrying_base_amount` (from leg_conv_base);
        // on `opp_side` we have `settlement_base` (from leg_settlement).
        // If `settlement_base > carrying_base_amount` (`diff > 0`), `settled_side`
        // needs `diff` to balance `opp_side`. Otherwise `opp_side` needs `|diff|`.
        let fx_side = if diff > 0 { settled_side } else { opp_side };
        let mut leg_fx = LegPayload::simple(fx_side, realized_fx_account, fx_amt);
        leg_fx.base_amount = Some(fx_amt);
        leg_fx.dimension_set = dimensions;
        legs.push(leg_fx);
    }

    let mut base_debits = 0i128;
    let mut base_credits = 0i128;
    for leg in &legs {
        let b = leg.base_amount.expect("all legs have base_amount");
        match leg.side {
            Side::Debit => {
                base_debits = base_debits
                    .checked_add(b.mantissa)
                    .ok_or_else(|| fx_structure("base_debits overflow"))?;
            }
            Side::Credit => {
                base_credits = base_credits
                    .checked_add(b.mantissa)
                    .ok_or_else(|| fx_structure("base_credits overflow"))?;
            }
        }
    }

    let ev = settlement_rate_doc.evidence_ref(template.book_id)?;
    if !template.evidence.contains(&ev) {
        template.evidence.push(ev);
    }
    template.evidence.sort();
    template.evidence.dedup();

    template.legs = legs;
    template.unit_totals = EntryPayload::fold_unit_totals(&template.legs).map_err(fx_structure)?;
    template.base_totals = Some(BaseTotals {
        unit_id: base_unit.0,
        debits: base_debits,
        credits: base_credits,
        fx_law_oid: FxLawId::SettlementCarryingBasis.oid(),
        rate_doc_oids: vec![ev.document_oid],
        residual: None,
    });
    template.validate().map_err(fx_structure)?;
    Ok(template)
}

/// Validated FX claim extracted at step 1d of `prepare_post`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FxClaim {
    pub law: FxLawId,
    pub rate_doc_oids: Vec<Oid>,
}

/// Admit a new FX effect after exact recorded-outcome recognition. A
/// registered law and balanced base amounts do not prove a translation or
/// remeasurement of the journal's complete source population. Keep this
/// restriction outside structural decoding and historical verification.
///
/// An exact Reversal introduces no new valuation: the posting pipeline
/// independently witnesses its ancestry and preserves the original claim.
pub(crate) fn admit_fresh_claim(proposal: &EntryPayload, claim: &FxClaim) -> Result<(), Refusal> {
    if proposal.class != EntryClass::REVERSAL
        && matches!(
            claim.law,
            FxLawId::TranslationCurrentRate | FxLawId::RemeasurementTemporal
        )
    {
        return Err(Refusal::new(
            code::CLASS_NOT_IMPLEMENTED,
            exit::REFUSAL,
            format!(
                "{} has no source-bound native posting law; caller-supplied balanced adjustments cannot establish its translation or remeasurement",
                claim.law.name(),
            ),
            "plan §12.4 (journal-derived translation, remeasurement and cumulative adjustments)",
            "retain the read-only calculation; native posting requires a kernel-derived translation or remeasurement basis, not a different entry class or a caller-supplied revaluation extension",
        ));
    }
    Ok(())
}

/// Step 1d of `prepare_post`: structural and entity-level balance checks on
/// `proposal.base_totals` and `leg.base_amount` before beginning a transaction.
pub(crate) fn admit_structure(
    proposal: &EntryPayload,
    spec: &BookSpec,
    leg_entities: &[Option<String>],
    units: &UnitRegistry,
) -> Result<Option<FxClaim>, Refusal> {
    let release_extension = proposal
        .extensions
        .iter()
        .any(|(tag, _)| *tag == fa_model::entry::FX_SETTLEMENT_VALUATION_EXTENSION);
    let release_law = proposal
        .base_totals
        .as_ref()
        .is_some_and(|total| total.fx_law_oid == FxLawId::SettlementAllocatedCarrying.oid());
    if release_extension != release_law {
        return Err(fx_structure(
            "SettlementAllocatedCarrying and its immutable valuation-release extension are required together",
        ));
    }
    let item_basis = proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::FX_REVALUATION_EXTENSION)
        .map(|(_, raw)| fa_model::FxRevaluationBasis::decode(raw))
        .transpose()
        .map_err(fx_structure)?
        .is_some_and(|basis| basis.item_allocation.is_some());
    let item_law = proposal
        .base_totals
        .as_ref()
        .is_some_and(|total| total.fx_law_oid == FxLawId::PeriodEndItemRevaluation.oid());
    if item_basis != item_law {
        return Err(fx_structure(
            "PeriodEndItemRevaluation and its immutable item-allocation basis are required together",
        ));
    }
    let Some(bt) = &proposal.base_totals else {
        if proposal.class == EntryClass::REVALUATION {
            return Err(not_implemented("Revaluation"));
        }
        if proposal.legs.iter().any(|l| l.base_amount.is_some()) {
            return Err(not_implemented("leg.base_amount"));
        }
        return Ok(None);
    };

    // Preserve exact FA-REF-102 behavior for unvalued base_totals or unregistered fx_law_oid.
    let Some(law) = FxLawId::from_oid(&bt.fx_law_oid) else {
        return Err(not_implemented("base_totals"));
    };
    if proposal.legs.iter().all(|l| l.base_amount.is_none()) {
        return Err(not_implemented("base_totals"));
    }

    // Verify embedded FxLaws registry agrees with FxLawId.
    let classes = fa_registry::EntryClasses::embedded().map_err(fx_structure)?;
    let registry = FxLaws::embedded(&classes).map_err(fx_structure)?;
    if !registry
        .laws
        .iter()
        .any(|r| r.id == law.id() && r.version == law.version())
    {
        return Err(not_implemented("base_totals"));
    }

    if proposal.class == EntryClass::REVALUATION
        && !matches!(
            law,
            FxLawId::PeriodEndRevaluation
                | FxLawId::PeriodEndItemRevaluation
                | FxLawId::TranslationCurrentRate
                | FxLawId::RemeasurementTemporal
        )
    {
        return Err(fx_structure(
            "a Revaluation entry must use PeriodEndRevaluation, TranslationCurrentRate, or RemeasurementTemporal",
        ));
    }
    if matches!(
        law,
        FxLawId::PeriodEndRevaluation | FxLawId::PeriodEndItemRevaluation
    ) && proposal.class != EntryClass::REVALUATION
    {
        return Err(fx_structure(
            "FxLawId::PeriodEndRevaluation is only admissible on a Revaluation entry",
        ));
    }
    if law == FxLawId::YearEndCloseCarrying
        && !matches!(proposal.class, EntryClass::CLOSING | EntryClass::REVERSAL)
    {
        return Err(fx_structure(
            "YearEndCloseCarrying is only admissible on a Closing or its exact Reversal",
        ));
    }

    if bt.unit_id != spec.base_unit.0 {
        return Err(fx_structure(format!(
            "base_totals.unit_id ({}) must equal the book's base_unit ({})",
            bt.unit_id, spec.base_unit.0
        )));
    }
    if law == FxLawId::YearEndCloseCarrying {
        if !bt.rate_doc_oids.is_empty() || bt.residual.is_some() {
            return Err(fx_structure(
                "YearEndCloseCarrying transfers recorded balances without Rate documents or a conversion residual",
            ));
        }
    } else if bt.rate_doc_oids.is_empty() {
        return Err(fx_structure(
            "base_totals.rate_doc_oids must cite at least one Rate document",
        ));
    }

    // Every rate_doc_oid in base_totals must be cited in proposal.evidence with role = RATE_EVIDENCE_ROLE.
    for oid in &bt.rate_doc_oids {
        let cited = proposal
            .evidence
            .iter()
            .any(|e| e.document_oid == *oid && e.role == RATE_EVIDENCE_ROLE);
        if !cited {
            return Err(Refusal::new(
                code::EVIDENCE_COMMIT,
                exit::REFUSAL,
                format!(
                    "base_totals rate document {} is not cited in entry.evidence with role Rate (3)",
                    crate::evidence::hex(&oid.0)
                ),
                "plan §5.2, §6.4, FA-INV-05 (rate documents in provenance closure)",
                "cite every rate_doc_oid in entry.evidence with role = Rate (3)",
            ));
        }
    }

    // Every leg carries its base amount, and base-unit legs stay at par.
    // A source-bound application may round to zero functional relief while
    // retaining a strictly positive foreign native amount. Its complete
    // shape and journal-derived relief are checked separately.
    let mut sum_debits = 0i128;
    let mut sum_credits = 0i128;
    let mut by_entity: BTreeMap<Option<String>, (i128, i128)> = BTreeMap::new();

    for (idx, (leg, entity)) in proposal.legs.iter().zip(leg_entities).enumerate() {
        let Some(base_amt) = leg.base_amount else {
            return Err(fx_structure(format!(
                "leg {idx} is missing base_amount while base_totals is present"
            )));
        };
        let zero_relief = matches!(
            law,
            FxLawId::SettlementCarryingBasis
                | FxLawId::SettlementAllocatedCarrying
                | FxLawId::YearEndCloseCarrying
        ) && leg.amount.unit != spec.base_unit
            && base_amt.mantissa == 0;
        if base_amt.unit != spec.base_unit
            || base_amt.mantissa < 0
            || (base_amt.mantissa == 0 && !zero_relief)
        {
            return Err(fx_structure(format!(
                "leg {idx} base_amount must be positive in the book's base_unit, except for recorded zero foreign carrying relief"
            )));
        }
        if leg.amount.unit == spec.base_unit && base_amt != leg.amount {
            return Err(Refusal::new(
                code::UNBALANCED,
                exit::REFUSAL,
                format!(
                    "leg {idx} is already in base_unit ({}) so its base_amount must equal its native amount at par",
                    spec.base_unit.0
                ),
                "plan §5.2, FA-INV-01.base (base-unit legs retain their 1:1 par amount)",
                "set leg.base_amount equal to leg.amount for legs in the book's base_unit",
            ));
        }
        let slot = by_entity.entry(entity.clone()).or_insert((0, 0));
        match leg.side {
            Side::Debit => {
                sum_debits = sum_debits
                    .checked_add(base_amt.mantissa)
                    .ok_or_else(|| fx_structure("base_amount debit sum overflow"))?;
                slot.0 = slot
                    .0
                    .checked_add(base_amt.mantissa)
                    .ok_or_else(|| fx_structure("entity base_amount debit sum overflow"))?;
            }
            Side::Credit => {
                sum_credits = sum_credits
                    .checked_add(base_amt.mantissa)
                    .ok_or_else(|| fx_structure("base_amount credit sum overflow"))?;
                slot.1 = slot
                    .1
                    .checked_add(base_amt.mantissa)
                    .ok_or_else(|| fx_structure("entity base_amount credit sum overflow"))?;
            }
        }
    }

    if bt.debits != sum_debits || bt.credits != sum_credits {
        return Err(fx_structure(
            "base_totals debits/credits do not match the sum of leg.base_amount across the entry",
        ));
    }
    if bt.debits != bt.credits {
        let show = |m: i128| {
            if units.get(spec.base_unit).is_some() {
                Amount::new(spec.base_unit, m).render(units)
            } else {
                format!("{m}")
            }
        };
        return Err(Refusal::new(
            code::UNBALANCED,
            exit::REFUSAL,
            format!(
                "base_totals debits {} != credits {} under FX law {}",
                show(bt.debits),
                show(bt.credits),
                law.name()
            ),
            "FA-INV-01 (`base`: base debits equal base credits under the named FX law)",
            "value the entry's legs under the registered FX law so base debits equal base credits",
        ));
    }

    for (entity, (ed, ec)) in &by_entity {
        if ed != ec {
            let entity_label = entity.as_deref().unwrap_or("<default>");
            return Err(Refusal::new(
                code::UNBALANCED,
                exit::REFUSAL,
                format!(
                    "entity `{entity_label}` base debits {ed} != base credits {ec} under FX law {}",
                    law.name()
                ),
                "FA-INV-01 (`base`: base debits equal base credits per legal entity in multi-entity books)",
                "value each legal entity's legs so base amounts balance within every legal entity",
            ));
        }
    }

    if let Some(res) = bt.residual {
        let idx = usize::from(res.leg_ordinal);
        if res.amount.unit != spec.base_unit || res.amount.mantissa <= 0 {
            return Err(fx_structure(
                "base_totals.residual.amount must be a positive amount in the book's base_unit",
            ));
        }
        if proposal.legs[idx].amount.unit == spec.base_unit {
            return Err(Refusal::new(
                code::UNBALANCED,
                exit::REFUSAL,
                format!(
                    "base_totals.residual targets leg {idx}, which is already in base_unit and cannot absorb a conversion residual"
                ),
                "FA-INV-01 (`base-residual`: only converted foreign-currency legs may absorb a valuation residual)",
                "absorb the valuation residual on the largest converted foreign-currency leg on the deficient side",
            ));
        }
    }

    Ok(Some(FxClaim {
        law,
        rate_doc_oids: bt.rate_doc_oids.clone(),
    }))
}

/// Verify the FX claim inside the posting transaction that witnesses the
/// cited `Rate` documents (`FA-INV-01.base`, `FA-INV-01.base-residual`,
/// `FA-INV-01.realized-fx`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_in_txn<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    spec: &BookSpec,
    period: &PeriodDef,
    units: &UnitRegistry,
    leg_entities: &[Option<String>],
    proposal: &EntryPayload,
    claim: &FxClaim,
    inherited_origin: Option<(&EntryPayload, &PeriodDef)>,
) -> Outcome<()> {
    // Only fresh postings reach this transaction check: prepare_post returns
    // exact recorded outcomes first. Keep current law admission here, outside
    // pure valuation and historical folds, so immutable history is unchanged.
    verify_claim(
        &mut |vid: VId| -> Result<Option<VertexRow>, crate::KernelError> {
            Ok(txn.vertex(db, vid)?)
        },
        spec,
        period,
        units,
        leg_entities,
        proposal,
        claim,
        inherited_origin,
        true,
    )
}

/// The FX claim of `proposal` against its cited `Rate` documents, each read
/// through `read`: a point read of the posting transaction, or of a recorded
/// snapshot when history is verified. `live` admits the law as a new posting
/// would (its registry row live and admitting the class); history is judged
/// under the row its entry named, whatever its status now.
#[allow(clippy::too_many_arguments)]
fn verify_claim(
    read: &mut dyn FnMut(VId) -> Result<Option<VertexRow>, crate::KernelError>,
    spec: &BookSpec,
    period: &PeriodDef,
    units: &UnitRegistry,
    leg_entities: &[Option<String>],
    proposal: &EntryPayload,
    claim: &FxClaim,
    inherited_origin: Option<(&EntryPayload, &PeriodDef)>,
    live: bool,
) -> Outcome<()> {
    // A Reversal's context is supplied only by post.rs after it has witnessed
    // and verified every exact side-swap back to the original valued entry.
    // Replay that original calculation, including its date, period, sides and
    // residual assignment. The current reversal was separately balanced and
    // must preserve those exact base amounts, law and Rate commitments.
    let (valuation, valuation_period) = inherited_origin.unwrap_or((proposal, period));
    let classes = fa_registry::EntryClasses::embedded()
        .map_err(|error| crate::KernelError::Corrupt(error.to_string()))?;
    let registry = FxLaws::embedded(&classes)
        .map_err(|error| crate::KernelError::Corrupt(error.to_string()))?;
    let Some(law) = registry.laws.iter().find(|law| {
        law.id == claim.law.id()
            && law.version == claim.law.version()
            && (!live || law.status == "live")
    }) else {
        return Ok(Err(fx_structure(format!(
            "FX law {} version {} is not {}",
            claim.law.name(),
            claim.law.version(),
            if live {
                "live for a new posting"
            } else {
                "registered"
            }
        ))));
    };
    let class = proposal.class.name().unwrap_or("unregistered");
    if live && !law.admitted_classes.iter().any(|allowed| allowed == class) {
        return Ok(Err(fx_structure(format!(
            "FX law {} version {} does not admit entry class {class} for a new posting",
            claim.law.name(),
            claim.law.version(),
        ))));
    }
    let rounding_law = matches!(claim.law, FxLawId::SpotClose | FxLawId::PeriodAverage)
        .then_some(law.rounding_law.as_str());
    let average_as_of = if claim.law == FxLawId::PeriodAverage {
        Some(valuation_period.end.pred()?)
    } else {
        None
    };
    let mut rate_docs = Vec::with_capacity(claim.rate_doc_oids.len());
    for oid in &claim.rate_doc_oids {
        let vid = document_vid(oid);
        let Some(row) = read(vid)? else {
            return Ok(Err(Refusal::new(
                code::EVIDENCE_UNKNOWN,
                exit::REFUSAL,
                format!(
                    "rate document {} is not held by this book",
                    crate::evidence::hex(&oid.0)
                ),
                "FA-INV-05 (rate documents must exist in the book)",
                "add the Rate document before posting the FX-valued entry",
            )));
        };
        if !row.labels.contains(&label::DOCUMENT) {
            return Ok(Err(Refusal::new(
                code::EVIDENCE_UNKNOWN,
                exit::REFUSAL,
                format!(
                    "rate document {} is not a Document vertex",
                    crate::evidence::hex(&oid.0)
                ),
                "FA-INV-05",
                "add the Rate document via add_document",
            )));
        }
        let payload = crate::rows::bytes(&row, property::FA_PAYLOAD, "document.payload")?;
        let record = DocumentRecord::decode(&payload)?;
        let citation = proposal
            .evidence
            .iter()
            .find(|evidence| evidence.document_oid == *oid && evidence.role == RATE_EVIDENCE_ROLE);
        if record.book_id != spec.book_id
            || record.oid() != *oid
            || row.vid != vid
            || document_vid(&record.oid()) != row.vid
            || citation.is_none_or(|evidence| evidence.doc_commit != record.doc_commit)
            || proposal.evidence.iter().any(|evidence| {
                evidence.document_oid == *oid
                    && evidence.role == RATE_EVIDENCE_ROLE
                    && evidence.doc_commit != record.doc_commit
            })
            || crate::rows::bytes(&row, property::FA_DIGEST, "rate document digest")?
                != record.doc_commit
            || crate::rows::bytes(&row, property::BOOK_ID, "rate document book")? != spec.book_id.0
            || crate::rows::text(&row, property::CODE, "rate document kind")? != "Rate"
        {
            return Ok(Err(Refusal::new(
                code::EVIDENCE_COMMIT,
                exit::REFUSAL,
                format!(
                    "rate document {} differs from its content identity, book, mirrors or Rate citation",
                    crate::evidence::hex(&oid.0)
                ),
                "FA-INV-05 (Rate identity and commitment are bound to the recorded valuation)",
                "restore the exact immutable Rate document and citation used for the valuation",
            )));
        }
        if record.kind != RATE_DOCUMENT_KIND {
            return Ok(Err(fx_structure(format!(
                "cited rate document {} has kind {}, expected Rate ({RATE_DOCUMENT_KIND})",
                crate::evidence::hex(&oid.0),
                record.kind
            ))));
        }
        let Storage::Inline(bytes) = &record.storage else {
            return Ok(Err(fx_structure(format!(
                "cited rate document {} must be stored inline",
                crate::evidence::hex(&oid.0)
            ))));
        };
        let decoded = match FxRateDocument::decode(bytes) {
            Ok(d) => d,
            Err(r) => return Ok(Err(r)),
        };
        if decoded.base_unit != spec.base_unit {
            return Ok(Err(fx_structure(format!(
                "rate document {} has base_unit {}, expected book base_unit {}",
                crate::evidence::hex(&oid.0),
                decoded.base_unit.0,
                spec.base_unit.0
            ))));
        }
        let purpose_ok = match claim.law {
            FxLawId::TranslationCurrentRate | FxLawId::RemeasurementTemporal => matches!(
                decoded.purpose,
                FxRatePurpose::PeriodClose
                    | FxRatePurpose::PeriodAverage
                    | FxRatePurpose::SpotClose
            ),
            other => Some(decoded.purpose) == other.required_purpose(),
        };
        if !purpose_ok {
            return Ok(Err(fx_structure(format!(
                "rate document {} has purpose `{}`, which is not admissible under FX law {}",
                crate::evidence::hex(&oid.0),
                decoded.purpose.as_str(),
                claim.law.name(),
            ))));
        }
        if let Some(expected) = rounding_law
            && decoded.rounding.name() != expected
        {
            return Ok(Err(fx_structure(format!(
                "rate document {} uses {} rounding; FX law {} requires {expected}",
                crate::evidence::hex(&oid.0),
                decoded.rounding.name(),
                claim.law.name(),
            ))));
        }
        if let Some(expected) = average_as_of
            && decoded.as_of != expected
        {
            return Ok(Err(fx_structure(format!(
                "PeriodAverage rate document {} as_of {} must equal posting period {}'s last included day {}",
                crate::evidence::hex(&oid.0),
                decoded.as_of.render(),
                valuation_period.code,
                expected.render(),
            ))));
        }
        rate_docs.push(decoded);
    }

    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);

    match claim.law {
        FxLawId::SpotClose | FxLawId::PeriodAverage => {
            let computed = match compute_entity_valuations(
                &mut budget,
                &valuation.legs,
                leg_entities,
                spec.base_unit,
                valuation.effective_date,
                units,
                claim.law,
                &rate_docs,
            ) {
                Ok(c) => c,
                Err(r) => return Ok(Err(r)),
            };
            let bt = proposal.base_totals.as_ref().expect("checked in admit");
            for (idx, (leg, expected_base)) in
                proposal.legs.iter().zip(&computed.base_amounts).enumerate()
            {
                if leg.base_amount != Some(*expected_base) {
                    return Ok(Err(Refusal::new(
                        code::UNBALANCED,
                        exit::REFUSAL,
                        format!(
                            "leg {idx} base_amount {:?} does not equal recomputed valuation {} under {}",
                            leg.base_amount,
                            expected_base.render(units),
                            claim.law.name()
                        ),
                        "FA-INV-01 (`base` and `base-residual`: kernel recomputes leg valuations and residual absorption from the cited Rate documents)",
                        "recompute the proposal's leg.base_amount and base_totals using value_proposal",
                    )));
                }
            }
            if bt.residual != computed.residual
                || bt.debits != computed.total_debits
                || bt.credits != computed.total_credits
            {
                return Ok(Err(Refusal::new(
                    code::UNBALANCED,
                    exit::REFUSAL,
                    format!(
                        "base_totals (debits={}, credits={}, residual={:?}) does not match recomputed valuation (debits={}, credits={}, residual={:?})",
                        bt.debits,
                        bt.credits,
                        bt.residual,
                        computed.total_debits,
                        computed.total_credits,
                        computed.residual
                    ),
                    "FA-INV-01 (`base-residual`: each representable valuation adjustment is recorded and absorbed within its entity, within the law's exact bound)",
                    "record the exact residual ordinal and amount computed by the FX law",
                )));
            }
        }
        FxLawId::PeriodEndRevaluation | FxLawId::PeriodEndItemRevaluation => {
            let bt = proposal.base_totals.as_ref().expect("checked in admit");
            if bt.residual.is_some() {
                return Ok(Err(fx_structure(
                    "PeriodEndRevaluation entries carry no base_totals.residual",
                )));
            }
            if rate_docs.iter().any(|d| d.as_of != proposal.effective_date) {
                return Ok(Err(fx_structure(
                    "PeriodEndRevaluation requires rate document as_of == entry effective_date",
                )));
            }
            if proposal
                .legs
                .iter()
                .any(|l| l.amount.unit != spec.base_unit || l.base_amount != Some(l.amount))
            {
                return Ok(Err(fx_structure(
                    "PeriodEndRevaluation legs must state the functional-currency carrying adjustment in base_unit",
                )));
            }
        }
        FxLawId::TranslationCurrentRate | FxLawId::RemeasurementTemporal => {
            // Only retained claims and their exact inherited reversals reach
            // this structural check. A reversal keeps the source date and
            // quote; it never requests a new translation on its own date.
            let bt = valuation.base_totals.as_ref().expect("checked in admit");
            if bt.residual.is_some() {
                return Ok(Err(fx_structure(format!(
                    "{} entries carry no base_totals.residual",
                    claim.law.name()
                ))));
            }
            if !rate_docs.iter().any(|d| {
                d.purpose == FxRatePurpose::PeriodClose && d.as_of == valuation.effective_date
            }) {
                return Ok(Err(fx_structure(format!(
                    "{} requires a PeriodClose rate document with as_of == entry effective_date",
                    claim.law.name()
                ))));
            }
            if valuation
                .legs
                .iter()
                .any(|l| l.amount.unit != spec.base_unit || l.base_amount != Some(l.amount))
            {
                return Ok(Err(fx_structure(format!(
                    "{} legs must state the translated/remeasured adjustment in base_unit",
                    claim.law.name()
                ))));
            }
        }
        FxLawId::SettlementCarryingBasis => {
            if let Err(r) = verify_realized_fx_settlement(
                &mut budget,
                valuation,
                spec,
                units,
                leg_entities,
                &rate_docs,
            ) {
                return Ok(Err(r));
            }
        }
        FxLawId::SettlementAllocatedCarrying => {
            if let Err(r) = crate::carrying::verify_allocated_fx_structure(
                &mut budget,
                valuation,
                spec,
                units,
                leg_entities,
                &rate_docs,
            ) {
                return Ok(Err(r));
            }
        }
        FxLawId::YearEndCloseCarrying => {
            // Closing's owner reproduces its saved source basis and the
            // precommit balances. A reversal reaches this point only with
            // an independently witnessed exact ancestry back to that close.
            // The separate target-class and period gates still decide if
            // it may publish; Closing currently corrects by incremental reclose.
            // No rate is invented to represent a transfer of carrying value.
            if valuation.class != EntryClass::CLOSING
                || !valuation
                    .extensions
                    .iter()
                    .any(|(tag, _)| *tag == fa_model::entry::YEAR_END_CLOSE_EXTENSION)
                || !claim.rate_doc_oids.is_empty()
                || valuation
                    .base_totals
                    .as_ref()
                    .is_none_or(|totals| totals.residual.is_some())
            {
                return Ok(Err(fx_structure(
                    "YearEndCloseCarrying requires a source-bound Closing or its exact inherited Reversal",
                )));
            }
        }
    }

    Ok(Ok(()))
}

/// One FX-valued entry whose recorded valuation does not recompute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxConversionDrift {
    pub entry: VId,
    pub recorded_at: CommitSeq,
    /// The FX law its base_totals name (`unregistered` when none does).
    pub law: String,
    pub problem: String,
}

/// `fa verify fx-conversion`: every FX-valued entry recorded at or before
/// `known_at`, recomputed (plan §6.4, §15.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxConversionVerification {
    pub known_at: CommitSeq,
    /// Valued entries checked, by FX law name.
    pub checked: BTreeMap<String, u64>,
    /// Entries whose valuation does not recompute, in recording order.
    pub drift: Vec<FxConversionDrift>,
}

impl FxConversionVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty()
    }
}

/// Recompute the functional valuation of every FX-valued entry recorded at
/// or before `at` (FA-INV-01 `base`, `base-residual`, `realized-fx`): its
/// structure and per-entity balance, then its legs, totals and residual from
/// the Rate documents it cites, read at `at`, under the registered law row it
/// names (live or not now: history keeps the law it was posted under). A
/// Reversal of a SpotClose or PeriodAverage valuation must be the exact
/// side-swap of the entry it reverses, which is checked on its own row.
/// Book interpretation also comes from `at`; current authority admission
/// remains the caller's responsibility. Read-only.
pub fn verify_fx_conversions<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: &fgdb_types::context::PurposeContexts,
    book: &crate::genesis::BookContext,
    at: CommitSeq,
) -> Result<FxConversionVerification, crate::KernelError> {
    let spec = book_spec_at(db, book, at)?;
    let mut out = FxConversionVerification {
        known_at: at,
        checked: BTreeMap::new(),
        drift: Vec::new(),
    };
    for row in db.vertices_at(at)? {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = crate::sweep::decode_entry(&row)?;
        let proposal = &entry.proposal;
        if proposal.base_totals.is_none() && proposal.legs.iter().all(|l| l.base_amount.is_none()) {
            continue;
        }
        let law = proposal
            .base_totals
            .as_ref()
            .and_then(|bt| FxLawId::from_oid(&bt.fx_law_oid))
            .map_or("unregistered", FxLawId::name)
            .to_string();
        *out.checked.entry(law.clone()).or_default() += 1;
        let mut verification = verify_recorded(db, &spec, &book.units, at, proposal)?;
        if verification.is_ok() && crate::carrying::is_source_bound(proposal) {
            let prior = CommitSeq(row.created_at.0.checked_sub(1).ok_or_else(|| {
                crate::KernelError::Corrupt("a settlement was recorded at sequence zero".into())
            })?);
            verification = crate::carrying::validate_post(db, cx, book, proposal, prior)?
                .map_err(|refusal| refusal.message);
        }
        if verification.is_ok()
            && let Some((_, raw)) = proposal
                .extensions
                .iter()
                .find(|(tag, _)| *tag == fa_model::entry::FX_REVALUATION_EXTENSION)
        {
            let basis = fa_model::FxRevaluationBasis::decode(raw)
                .map_err(|error| crate::KernelError::Corrupt(error.to_string()))?;
            if basis.item_allocation.is_some() {
                verification = cx
                    .query()
                    .with_restriction(|| {
                        crate::revaluation::verify_item_history(
                            db,
                            cx,
                            book,
                            basis.source_account,
                            at,
                        )
                    })?
                    .map_err(|refusal| refusal.message);
            }
        }
        if verification.is_ok()
            && proposal.class == EntryClass::CLOSING
            && proposal
                .base_totals
                .as_ref()
                .is_some_and(|totals| totals.fx_law_oid == FxLawId::YearEndCloseCarrying.oid())
            && !crate::closing::verify_recorded_carrying(
                db,
                cx,
                book,
                entry.entry_ref(row.vid),
                row.created_at,
            )?
        {
            verification = Err(
                "year-end close carrying amounts do not reproduce the saved source prefix and precommit balances"
                    .into(),
            );
        }
        if let Err(problem) = verification {
            out.drift.push(FxConversionDrift {
                entry: row.vid,
                recorded_at: row.created_at,
                law,
                problem,
            });
        }
    }
    out.drift.sort_by_key(|d| (d.recorded_at, d.entry.0));
    Ok(out)
}

/// FX interpretation and carrying relief share the selected historical root.
/// A later root cannot reinterpret a previously recorded valuation.
pub(crate) fn book_spec_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &crate::genesis::BookContext,
    at: CommitSeq,
) -> Result<BookSpec, crate::KernelError> {
    let root = db
        .vertex_at(crate::rows::book_root(), at)?
        .filter(|row| row.labels.contains(&label::BOOK))
        .ok_or_else(|| {
            crate::KernelError::Corrupt("FX book does not exist at the selected prefix".into())
        })?;
    let spec = BookSpec::decode(&crate::rows::bytes(
        &root,
        fa_model::symbols::property::FA_PAYLOAD,
        "FX book payload",
    )?)?;
    if spec.book_id != book.book_id || spec.calendar != book.calendar {
        return Err(crate::KernelError::Corrupt(
            "FX book context disagrees with the selected root".into(),
        ));
    }
    Ok(spec)
}

/// One recorded valued entry: `Err` names why its valuation does not
/// recompute.
fn verify_recorded<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    spec: &BookSpec,
    units: &UnitRegistry,
    at: CommitSeq,
    proposal: &EntryPayload,
) -> Result<Result<(), String>, crate::KernelError> {
    let leg_entities = match crate::entity::leg_entities(spec, &proposal.legs) {
        Ok(entities) => entities,
        Err(crate::entity::LegEntityError::Refused(r)) => return Ok(Err(r.message)),
        Err(crate::entity::LegEntityError::OtherDimension) => {
            return Ok(Err(
                "a leg carries a dimension other than the legal entity".into()
            ));
        }
    };
    let claim = match admit_structure(proposal, spec, &leg_entities, units) {
        Ok(Some(claim)) => claim,
        Ok(None) => return Ok(Err("base amounts without a registered FX claim".into())),
        Err(r) => return Ok(Err(r.message)),
    };
    let mut read =
        |vid: VId| -> Result<Option<VertexRow>, crate::KernelError> { Ok(db.vertex_at(vid, at)?) };
    if proposal.class == EntryClass::REVERSAL
        && matches!(
            claim.law,
            FxLawId::SpotClose
                | FxLawId::PeriodAverage
                | FxLawId::TranslationCurrentRate
                | FxLawId::RemeasurementTemporal
                | FxLawId::SettlementCarryingBasis
                | FxLawId::SettlementAllocatedCarrying
                | FxLawId::YearEndCloseCarrying
        )
    {
        let Some(target) = proposal
            .supersession
            .iter()
            .find(|s| s.kind == SupersessionKind::Reverses)
            .map(|s| s.target)
        else {
            return Ok(Err("a valued Reversal names no entry it reverses".into()));
        };
        let Some(row) = read(target.vid)? else {
            return Ok(Err(format!(
                "the reversed entry {:032x} is not recorded",
                target.vid.0
            )));
        };
        let original = crate::sweep::decode_entry(&row)?;
        if original.entry_ref(row.vid) != target
            || original.proposal.book_id != proposal.book_id
            || original.proposal.branch_id != proposal.branch_id
        {
            return Ok(Err(
                "a valued Reversal's target handle, book or branch differs from its recorded target"
                    .into(),
            ));
        }
        return Ok(
            if crate::post::exact_side_swap(&original.proposal, proposal) {
                Ok(())
            } else {
                Err(format!(
                    "not the exact side-swap of entry {:032x}: a reversal preserves the original valuation",
                    target.vid.0
                ))
            },
        );
    }
    let period = match entry_period(spec, proposal) {
        Ok(period) => period,
        Err(why) => return Ok(Err(why)),
    };
    Ok(
        match verify_claim(
            &mut read,
            spec,
            &period,
            units,
            &leg_entities,
            proposal,
            &claim,
            None,
            false,
        )? {
            Ok(()) => Ok(()),
            Err(r) => Err(r.message),
        },
    )
}

/// The period an entry was posted in, from the calendar declared at genesis
/// and its `effective_period` discriminator.
fn entry_period(spec: &BookSpec, proposal: &EntryPayload) -> Result<PeriodDef, String> {
    let date = proposal.effective_date;
    let periods = spec
        .calendar
        .fiscal_year_of(date)
        .and_then(|fy| spec.calendar.periods_for_year(fy))
        .map_err(|e| format!("effective date {}: {e}", date.render()))?;
    fa_time::resolve_period(
        &periods,
        date,
        proposal.effective_period.as_ref().map(|p| p.code.as_str()),
    )
    .cloned()
    .map_err(|e| format!("effective date {}: {e:?}", date.render()))
}

struct ComputedValuation {
    base_amounts: Vec<Amount>,
    total_debits: i128,
    total_credits: i128,
    residual: Option<Residual>,
}

#[allow(clippy::too_many_arguments)]
fn compute_entity_valuations(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    legs: &[LegPayload],
    leg_entities: &[Option<String>],
    base_unit: UnitId,
    effective_date: DateDay,
    units: &UnitRegistry,
    law: FxLawId,
    rate_docs: &[FxRateDocument],
) -> Result<ComputedValuation, Refusal> {
    let mut by_quote: BTreeMap<UnitId, &FxRateDocument> = BTreeMap::new();
    for doc in rate_docs {
        if doc.base_unit != base_unit {
            return Err(fx_structure(format!(
                "rate document base_unit {} does not match book base_unit {}",
                doc.base_unit.0, base_unit.0
            )));
        }
        if Some(doc.purpose) != law.required_purpose() {
            return Err(fx_structure(format!(
                "rate document purpose `{}` does not match law `{}`",
                doc.purpose.as_str(),
                law.name()
            )));
        }
        if law == FxLawId::SpotClose && doc.as_of != effective_date {
            return Err(fx_structure(format!(
                "SpotClose rate document as_of {} does not match entry effective_date {}",
                doc.as_of.render(),
                effective_date.render()
            )));
        }
        if by_quote.insert(doc.quote_unit, doc).is_some() {
            return Err(fx_structure(format!(
                "multiple rate documents supplied for quote_unit {}",
                doc.quote_unit.0
            )));
        }
    }

    // Partition leg indices by (entity, foreign_unit) so each entity's foreign currency is
    // valued independently by `fa_money::value_legs`, preserving within-entity residual absorption.
    let mut entity_groups: BTreeMap<Option<String>, Vec<usize>> = BTreeMap::new();
    for (idx, entity) in leg_entities.iter().enumerate() {
        entity_groups.entry(entity.clone()).or_default().push(idx);
    }

    let mut base_amounts = vec![Amount::new(base_unit, 0); legs.len()];
    let mut total_debits = 0i128;
    let mut total_credits = 0i128;
    let mut recorded_residual: Option<Residual> = None;

    for (_entity, indices) in entity_groups {
        // Group indices within this entity by foreign currency (base_unit legs stay at par).
        let mut foreign_units: BTreeMap<UnitId, Vec<usize>> = BTreeMap::new();
        for &idx in &indices {
            let u = legs[idx].amount.unit;
            if u == base_unit {
                base_amounts[idx] = legs[idx].amount;
                match legs[idx].side {
                    Side::Debit => {
                        total_debits = total_debits
                            .checked_add(legs[idx].amount.mantissa)
                            .ok_or_else(|| fx_structure("base debit overflow"))?;
                    }
                    Side::Credit => {
                        total_credits = total_credits
                            .checked_add(legs[idx].amount.mantissa)
                            .ok_or_else(|| fx_structure("base credit overflow"))?;
                    }
                }
            } else {
                foreign_units.entry(u).or_default().push(idx);
            }
        }

        for (f_unit, f_indices) in foreign_units {
            let Some(&doc) = by_quote.get(&f_unit) else {
                return Err(fx_structure(format!(
                    "no FxRateDocument supplied for foreign unit {}",
                    f_unit.0
                )));
            };
            let rate = doc.to_rate(budget)?;
            let sub_legs: Vec<LegValue> = f_indices
                .iter()
                .map(|&i| LegValue {
                    side: legs[i].side,
                    amount: legs[i].amount,
                })
                .collect();
            let val = value_legs(budget, &sub_legs, base_unit, &rate, doc.rounding, units)
                .map_err(valuation_refusal)?;
            for (&orig_idx, &b_amt) in f_indices.iter().zip(&val.base_amounts) {
                base_amounts[orig_idx] = b_amt;
            }
            total_debits = total_debits
                .checked_add(val.base_debits.mantissa)
                .ok_or_else(|| fx_structure("base debit overflow"))?;
            total_credits = total_credits
                .checked_add(val.base_credits.mantissa)
                .ok_or_else(|| fx_structure("base credit overflow"))?;

            if let Some((sub_target, adj)) = val.residual {
                if recorded_residual.is_some() {
                    return Err(Refusal::new(
                        code::UNBALANCED,
                        exit::REFUSAL,
                        "multiple entity/unit partitions produced non-zero FX rounding residuals in a single entry, which a single BaseTotals.residual cannot represent",
                        "FA-INV-01 (`base-residual`: each representable valuation adjustment is recorded and absorbed within its entity)",
                        "split the multi-entity FX entry into one entry per entity so each residual is recorded in its own BaseTotals",
                    ));
                }
                let orig_ordinal = u16::try_from(f_indices[sub_target])
                    .map_err(|_| fx_structure("leg ordinal exceeds u16"))?;
                recorded_residual = Some(Residual {
                    leg_ordinal: orig_ordinal,
                    amount: Amount::new(base_unit, adj),
                });
            }
        }
    }

    Ok(ComputedValuation {
        base_amounts,
        total_debits,
        total_credits,
        residual: recorded_residual,
    })
}

pub(crate) fn verify_realized_fx_settlement(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    proposal: &EntryPayload,
    spec: &BookSpec,
    units: &UnitRegistry,
    leg_entities: &[Option<String>],
    rate_docs: &[FxRateDocument],
) -> Result<(), Refusal> {
    let ranges = if proposal
        .legs
        .iter()
        .filter(|leg| !leg.settles.is_empty())
        .count()
        > 1
    {
        crate::carrying::settlement_ranges(proposal)?
    } else {
        std::iter::once(0..proposal.legs.len()).collect()
    };
    for range in ranges {
        verify_realized_fx_component(
            budget,
            proposal,
            spec,
            units,
            leg_entities,
            rate_docs,
            range,
        )?;
    }
    Ok(())
}

fn verify_realized_fx_component(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    proposal: &EntryPayload,
    spec: &BookSpec,
    units: &UnitRegistry,
    leg_entities: &[Option<String>],
    rate_docs: &[FxRateDocument],
    range: core::ops::Range<usize>,
) -> Result<(), Refusal> {
    let leg_entities = leg_entities
        .get(range.clone())
        .ok_or_else(|| fx_structure("FX component entity closure is incomplete"))?;
    if leg_entities
        .first()
        .is_some_and(|first| leg_entities.iter().any(|entity| entity != first))
    {
        return Err(fx_structure(
            "each FX component must balance within its own legal entity",
        ));
    }
    let legs = &proposal.legs[range];
    let bt = proposal.base_totals.as_ref().expect("checked in admit");
    if bt.residual.is_some() {
        return Err(fx_structure(
            "SettlementCarryingBasis entries use explicit realized FX legs, not base_totals.residual",
        ));
    }
    let [rate_doc] = rate_docs else {
        return Err(fx_structure(
            "SettlementCarryingBasis requires exactly one Settlement FxRateDocument",
        ));
    };
    if rate_doc.as_of > proposal.effective_date || rate_doc.rounding != RoundingLaw::HalfEven {
        return Err(fx_structure(
            "SettlementCarryingBasis requires HalfEven and a rate document as_of no later than the entry's effective_date",
        ));
    }
    let quote_unit = rate_doc.quote_unit;
    let base_unit = spec.base_unit;

    // Zero carrying relief omits the zero base conversion posting. The
    // remaining four ordered legs still record every native effect, pair
    // the foreign amount, and show the entire cash amount as realized FX.
    if legs
        .first()
        .is_some_and(|leg| leg.base_amount == Some(Amount::new(base_unit, 0)))
    {
        let [settled, conversion, cash, realized] = legs else {
            return Err(fx_structure(
                "zero carrying relief requires exactly four settlement legs",
            ));
        };
        let rate = rate_doc.to_rate(budget)?;
        let expected_cash = settled
            .amount
            .convert(budget, base_unit, &rate, RoundingLaw::HalfEven, units)
            .map_err(fx_structure)?;
        let distinct: BTreeSet<_> = legs.iter().map(|leg| leg.account_ref).collect();
        if distinct.len() != 4
            || settled.amount.unit != quote_unit
            || conversion.amount != settled.amount
            || conversion.side != opposite(settled.side)
            || conversion.base_amount != settled.base_amount
            || leg_entities[0] != leg_entities[1]
            || cash.side != conversion.side
            || cash.amount != expected_cash
            || cash.base_amount != Some(expected_cash)
            || realized.side != settled.side
            || realized.amount != expected_cash
            || realized.base_amount != Some(expected_cash)
        {
            return Err(fx_structure(
                "zero carrying relief does not reproduce its complete paired foreign, cash, and realized-FX effects",
            ));
        }
        return Ok(());
    }

    // Group legs by account to find the paired conversion account (`FA-INV-01.realized-fx`):
    // A conversion account must have one leg in `quote_unit` and one leg in `base_unit`
    // on opposite sides with identical `base_amount` (so its functional balance nets to zero).
    let mut by_account: BTreeMap<VId, Vec<(usize, &LegPayload)>> = BTreeMap::new();
    for (idx, leg) in legs.iter().enumerate() {
        by_account
            .entry(leg.account_ref)
            .or_default()
            .push((idx, leg));
    }

    let mut conversion_pair: Option<(VId, Side, Amount, Amount)> = None;
    for (&acct, acct_legs) in &by_account {
        if acct_legs.len() == 2 {
            let (i0, l0) = acct_legs[0];
            let (i1, l1) = acct_legs[1];
            let b0 = l0.base_amount.expect("checked in admit");
            let b1 = l1.base_amount.expect("checked in admit");
            if l0.side != l1.side
                && b0 == b1
                && leg_entities[i0] == leg_entities[i1]
                && ((l0.amount.unit == quote_unit
                    && l1.amount.unit == base_unit
                    && l1.amount == b1)
                    || (l1.amount.unit == quote_unit
                        && l0.amount.unit == base_unit
                        && l0.amount == b0))
            {
                let (fx_leg, _) = if l0.amount.unit == quote_unit {
                    (l0, l1)
                } else {
                    (l1, l0)
                };
                conversion_pair = Some((acct, fx_leg.side, fx_leg.amount, b0));
                break;
            }
        }
    }

    let Some((conv_acct, conv_fx_side, foreign_amt, carrying_base)) = conversion_pair else {
        return Err(Refusal::new(
            code::UNBALANCED,
            exit::REFUSAL,
            "SettlementCarryingBasis entry lacks paired conversion account postings (one quote_unit leg and one base_unit leg on opposite sides with equal functional base_amount)",
            "plan §5.2, FA-INV-01 (`realized-fx`: realized FX uses the paired postings of plan §5.2)",
            "construct the realized FX settlement via plan_realized_fx_settlement with a paired conversion account",
        ));
    };

    // Verify that the settled foreign-currency leg on the opposite side of `conv_fx_side`
    // carries `foreign_amt` and `base_amount == Some(carrying_base)`, and that the settlement
    // consideration leg in `base_unit` equals `foreign_amt` converted at `rate_doc`.
    let rate = rate_doc.to_rate(budget)?;
    let expected_settlement_base = foreign_amt
        .convert(budget, base_unit, &rate, rate_doc.rounding, units)
        .map_err(fx_structure)?;

    let settled_side = opposite(conv_fx_side);
    let has_settled_leg = legs.iter().any(|l| {
        l.account_ref != conv_acct
            && l.side == settled_side
            && l.amount == foreign_amt
            && l.base_amount == Some(carrying_base)
    });
    if !has_settled_leg {
        return Err(Refusal::new(
            code::UNBALANCED,
            exit::REFUSAL,
            "SettlementCarryingBasis entry is missing the settled foreign-currency leg matching the conversion account's foreign amount and carrying base amount",
            "plan §5.2, FA-INV-01 (`realized-fx`)",
            "ensure the settled foreign-currency leg carries the same foreign amount and carrying base amount as the conversion account",
        ));
    }

    let has_settlement_consideration_leg = legs.iter().any(|l| {
        l.account_ref != conv_acct
            && l.side == conv_fx_side
            && l.amount == expected_settlement_base
            && l.base_amount == Some(expected_settlement_base)
    });
    if !has_settlement_consideration_leg {
        return Err(Refusal::new(
            code::UNBALANCED,
            exit::REFUSAL,
            format!(
                "SettlementCarryingBasis entry has no settlement consideration leg matching the Rate document conversion ({})",
                expected_settlement_base.render(units)
            ),
            "plan §5.2, FA-INV-01 (`realized-fx`)",
            "value the settlement consideration leg at the cited Settlement FxRateDocument",
        ));
    }

    Ok(())
}

fn valuation_refusal(err: ValuationError) -> Refusal {
    match err {
        ValuationError::ResidualTooLarge { residual, bound } => Refusal::new(
            code::UNBALANCED,
            exit::REFUSAL,
            format!("FX valuation residual {residual} exceeds law bound {bound}"),
            "FA-INV-01 (`base-residual`: each representable valuation adjustment is within the law's exact bound)",
            "use a registered rounding law and rate document whose per-leg conversions stay within the residual bound",
        ),
        other => Refusal::new(
            code::UNBALANCED,
            exit::REFUSAL,
            format!("FX valuation refused: {other}"),
            "plan §5.2, FA-INV-01 (`base`, `base-residual`)",
            "ensure native legs balance per unit and entity before valuing into base_unit",
        ),
    }
}

fn not_implemented(what: &str) -> Refusal {
    Refusal::new(
        code::CLASS_NOT_IMPLEMENTED,
        exit::REFUSAL,
        format!("`{what}` is not implemented in this kernel slice"),
        "plan §5, §19 (workstream W2/W3)",
        "omit the field or wait for the slice that enforces its law (fa-p7r for FX, fa-bvx for dimensions, fa-cvi for supersession)",
    )
}

fn fx_structure(why: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        format!("fx: {why}"),
        "plan §5.2, §6.4, registries/fx_laws.toml",
        "supply canonical FxRateDocument evidence and base_totals matching the registered FX law",
    )
}

const fn opposite(side: Side) -> Side {
    match side {
        Side::Debit => Side::Credit,
        Side::Credit => Side::Debit,
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

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::{EntryOrigin, Erasable, SealKey};
    use fa_time::FiscalCalendar;

    fn carrying_close(base: i128) -> (BookSpec, UnitRegistry, EntryPayload) {
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let spec = BookSpec {
            book_id: Id128([35; 16]),
            name: "Exact carrying transfer".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("carrying-close", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let legs = [(Side::Debit, VId(1)), (Side::Credit, VId(2))]
            .into_iter()
            .map(|(side, account)| {
                let mut leg = LegPayload::simple(side, account, Amount::new(eur, 100));
                leg.base_amount = Some(Amount::new(usd, base));
                leg
            })
            .collect::<Vec<_>>();
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: spec.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::CLOSING,
            effective_date: DateDay::from_ymd(2026, 12, 31).unwrap(),
            document_date: None,
            description: Erasable::seal(
                &"Carry retained values".to_string(),
                None,
                &SealKey([36; 32]),
                [37; 32],
                [38; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: Some(BaseTotals {
                unit_id: usd.0,
                debits: base,
                credits: base,
                fx_law_oid: FxLawId::YearEndCloseCarrying.oid(),
                rate_doc_oids: Vec::new(),
                residual: None,
            }),
            idempotency_key: b"carrying-close".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([39; 32]),
                intent_kind: 1,
            },
            principal_ref: VId(7),
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        (spec, units, proposal)
    }

    #[test]
    fn carrying_close_law_admits_exact_and_zero_foreign_carrying_without_quotes() {
        assert_eq!(FxLawId::YearEndCloseCarrying.id(), 8);
        assert_eq!(FxLawId::YearEndCloseCarrying.required_purpose(), None);
        assert_eq!(
            FxLawId::from_oid(&FxLawId::YearEndCloseCarrying.oid()),
            Some(FxLawId::YearEndCloseCarrying),
        );
        for base in [0, 137] {
            let (spec, units, mut proposal) = carrying_close(base);
            for class in [EntryClass::CLOSING, EntryClass::REVERSAL] {
                proposal.class = class;
                let claim = admit_structure(&proposal, &spec, &[None, None], &units)
                    .unwrap()
                    .unwrap();
                assert_eq!(claim.law, FxLawId::YearEndCloseCarrying);
                assert!(claim.rate_doc_oids.is_empty());
            }
        }
    }

    #[test]
    fn carrying_close_law_refuses_quotes_residuals_classes_and_changed_base_par() {
        let (spec, units, proposal) = carrying_close(137);
        let refused = |bad: &EntryPayload| {
            assert!(admit_structure(bad, &spec, &[None, None], &units).is_err());
        };
        let mut quoted = proposal.clone();
        quoted.base_totals.as_mut().unwrap().rate_doc_oids = vec![Oid([9; 32])];
        refused(&quoted);
        let mut residual = proposal.clone();
        residual.base_totals.as_mut().unwrap().residual = Some(Residual {
            leg_ordinal: 0,
            amount: Amount::new(spec.base_unit, 1),
        });
        refused(&residual);
        for class in [
            EntryClass::ORIGINAL,
            EntryClass::ADJUSTING,
            EntryClass::REVALUATION,
        ] {
            let mut bad = proposal.clone();
            bad.class = class;
            refused(&bad);
        }
        let mut unvalued = proposal.clone();
        unvalued.legs[0].base_amount = None;
        refused(&unvalued);
        let mut unbalanced = proposal.clone();
        unbalanced.legs[0].base_amount.as_mut().unwrap().mantissa += 1;
        refused(&unbalanced);
        let mut nonpar = proposal;
        for leg in &mut nonpar.legs {
            leg.amount.unit = spec.base_unit;
        }
        refused(&nonpar);
        let (spec, units, mut zero) = carrying_close(0);
        for leg in &mut zero.legs {
            leg.amount.unit = spec.base_unit;
        }
        assert!(admit_structure(&zero, &spec, &[None, None], &units).is_err());
    }
}
