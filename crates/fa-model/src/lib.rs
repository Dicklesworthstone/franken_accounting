//! FrankenAccounting's durable model (plan §4, Appendix A).
//!
//! Everything here is a deterministic function of its inputs: no clock, no
//! entropy, no I/O. Entropy an object needs (an erasable field's salt and
//! nonce) is an explicit input supplied by the kernel under its `Cx`.
//!
//! Layout:
//! - [`canon`] — the canonical byte codec every durable object uses.
//! - [`symbols`] — the frozen label/property/relation table, as constants and
//!   as the substrate's `GraphSymbolResolver`.
//! - [`limits`] — the size bounds every decoder enforces before allocating.
//! - [`ids`] — `Id128`, `EntryRef`, `ApprovalRef`, `PeriodRef`, `TypedRef`,
//!   and the derived vertex identities of plan §4.9.
//! - [`erasable`] — field-level erasure: a digest that survives and bytes
//!   sealed under a subject key.
//! - [`entry`] — the `fa:entry:v1` payload, `ControlPayload`, `EntryOrigin`,
//!   the proposal and envelope digests, and structural validation.
//! - [`mirrors`] — the scalar properties an `Entry` and its derived `Leg`
//!   vertices carry for predicates and indexes (§4.2 storage form).

#![forbid(unsafe_code)]

pub mod access_event;
pub mod account;
pub mod asset_cost;
pub mod bank_csv;
pub mod canon;
pub mod closing;
pub mod deposit;
pub mod entry;
pub mod erasable;
pub mod ids;
pub mod limits;
pub mod lot_disposal;
pub mod mirrors;
pub mod obligation;
pub mod proportional;
pub mod rea;
pub mod revaluation;
pub mod symbols;
pub mod unit;
pub mod valuation;

pub use access_event::{AccessEvent, AccessRecord};
pub use account::AccountType;
pub use asset_cost::{AssetChargeBasis, AssetCostKind, AssetScheduleSpec};
pub use canon::{DecodeError, EncodeError, Reader, Writer};
pub use closing::YearEndCloseBasis;
pub use deposit::{
    DepositCapacity, DepositParticipant, DepositProduct, DepositProfileSpec, DepositRole,
};
pub use entry::{
    BaseTotals, ControlKind, ControlPayload, Disposition, Entry, EntryClass, EntryError,
    EntryOrigin, EntryPayload, EvidenceRef, ExternalId, IntakeSource, LegPayload, Pending,
    Residual, ScheduleTrigger, Settlement, Supersession, SupersessionKind, Tag, TagValue,
    UnitTotal,
};
pub use erasable::{Canonical, Erasable, EraseError, SealKey};
pub use ids::{
    ApprovalRef, DIMENSION_KINDS, DimensionKind, EntryRef, Id128, LEGAL_ENTITY_DIMENSION,
    LEGAL_ENTITY_DIMENSION_CODE, Oid, PARTY_DIMENSION, PARTY_DIMENSION_CODE, PeriodRef, TypedRef,
    access_event_vid, account_vid, bates_range_vid, dimension_kind, dimension_kind_of,
    dimension_value_vid, dimension_vid, domain_digest, draft_vid, engagement_vid, entity_value_vid,
    entry_vid, event_vid, external_id_vid, instrument_vid, intent_outcome_vid, legal_entity_vid,
    migration_entry_vid, migration_run_vid, party_value_vid, party_vid, period_vid, principal_vid,
    production_profile_vid, proposed_adjustment_vid, report_certificate_vid, restatement_case_vid,
    rule_name_vid, rule_version_vid, scenario_vid, statement_definition_vid,
    statement_issuance_vid, unit_vid,
};
pub use lot_disposal::{LotDisposalBasis, LotPolicy};
pub use mirrors::{MirrorError, entry_mirrors, leg_mirrors};
pub use proportional::ProportionalPostBasis;
pub use rea::{
    EventKind, EventResource, EventSpec, ExternalIdBinding, InstrumentKind, InstrumentSpec,
    LegalEntityFullSpec, OwnershipPct, PartyIdentifierUpdate, PartyKind, PartySpec, ReaControlOp,
    RelationshipKind, RelationshipSpec,
};
pub use revaluation::{
    FxItemRevaluationBasis, FxRevaluationBasis, FxRevaluationItem, FxSettlementValuationBasis,
    FxSettlementValuationRelease,
};
pub use symbols::SymbolTable;
pub use unit::UnitDefinition;
