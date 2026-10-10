//! The canonical immutable entry (plan §4.2, §4.6, Appendix A `fa:entry:v1`).
//!
//! One vertex carries the whole accounting fact: ordered legs inline, the
//! proposal every approval binds, and the envelope that commits it. Two
//! digests:
//!
//! - `proposal_digest = BLAKE3("fa:entry-proposal:v1" ‖ canonical(proposal))`
//!   over every field except the envelope fields (`plan_certificate_oid`,
//!   `approvals`) and the two digests;
//! - `entry_digest   = BLAKE3("fa:entry:v1" ‖ proposal_digest ‖ canonical(plan_certificate_oid) ‖ canonical(approvals))`,
//!   the committed envelope.
//!
//! The graph is acyclic by construction: the dry-run certificate is computed
//! over a plan that contains `proposal_digest`, so its oid can only live in
//! the envelope; approvals bind `proposal_digest`, never `entry_digest`.
//! Changing one leg changes `proposal_digest`, so an approval no longer binds
//! and the commit is refused (FA-INV-10).
//!
//! What this module checks is *structure*: bounds, class/leg shape, sorted
//! collections, consistent `unit_totals`, digest integrity. The accounting
//! laws (balance per unit, leaf-only, period admissibility, evidence minima)
//! belong to the kernel's laws step and are not re-derived here.

use core::fmt;

use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb_crypto::Hasher;
use fgdb_types::VId;

use crate::canon::{DecodeError, EncodeError, Reader, Writer, strictly_ascending};
use crate::erasable::{Canonical, Erasable};
use crate::ids::{ApprovalRef, EntryRef, Id128, Oid, PeriodRef, TypedRef};
use crate::limits::*;

pub const SCHEMA_MAJOR: u16 = 1;
pub const SCHEMA_MINOR: u16 = 0;
pub const PROPOSAL_DIGEST_DOMAIN: &[u8] = b"fa:entry-proposal:v1";
pub const ENTRY_DIGEST_DOMAIN: &[u8] = b"fa:entry:v1";

// ---------------------------------------------------------------------------
// Entry classes (registries/entry_classes.toml, compiled)
// ---------------------------------------------------------------------------

/// A registered entry class tag. The constants mirror
/// `registries/entry_classes.toml`; `code_classes_match_registry` is the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryClass(pub u16);

impl EntryClass {
    pub const ORIGINAL: Self = Self(1);
    pub const PENDING: Self = Self(2);
    pub const RESOLUTION: Self = Self(3);
    pub const REVERSAL: Self = Self(4);
    pub const REPLACEMENT: Self = Self(5);
    pub const RECLASSIFICATION: Self = Self(6);
    pub const ADJUSTING: Self = Self(7);
    pub const CLOSING: Self = Self(8);
    pub const ALLOCATION: Self = Self(9);
    pub const REVALUATION: Self = Self(10);
    pub const ELIMINATION: Self = Self(11);
    pub const MIGRATION: Self = Self(12);
    pub const REVISION: Self = Self(13);
    pub const RESTATEMENT: Self = Self(14);
    pub const PRIOR_PERIOD_ADJUSTMENT: Self = Self(15);
    pub const PERIOD_CONTROL: Self = Self(16);
    pub const SCHEMA_CONTROL: Self = Self(17);
    pub const POLICY_CONTROL: Self = Self(18);

    /// `(tag, name, is_control)` for every registered class.
    pub const ALL: &[(u16, &str, bool)] = &[
        (1, "Original", false),
        (2, "Pending", false),
        (3, "Resolution", false),
        (4, "Reversal", false),
        (5, "Replacement", false),
        (6, "Reclassification", false),
        (7, "Adjusting", false),
        (8, "Closing", false),
        (9, "Allocation", false),
        (10, "Revaluation", false),
        (11, "Elimination", false),
        (12, "Migration", false),
        (13, "Revision", false),
        (14, "Restatement", false),
        (15, "PriorPeriodAdjustment", false),
        (16, "PeriodControl", true),
        (17, "SchemaControl", true),
        (18, "PolicyControl", true),
    ];

    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        Self::ALL
            .iter()
            .find(|(t, _, _)| *t == self.0)
            .map(|(_, n, _)| *n)
    }

    #[must_use]
    pub fn is_registered(self) -> bool {
        self.name().is_some()
    }

    #[must_use]
    pub fn is_control(self) -> bool {
        Self::ALL.iter().any(|(t, _, c)| *t == self.0 && *c)
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|(_, n, _)| *n == name)
            .map(|(t, _, _)| Self(*t))
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryError {
    Decode(DecodeError),
    Encode(EncodeError),
    /// A structural rule the payload violates; `what` names the field and `why` the rule.
    Invalid {
        what: &'static str,
        why: &'static str,
    },
    /// `unit_totals` does not equal the fold over the legs.
    TotalsMismatch,
    /// A sum of leg mantissas overflowed `i128`.
    Overflow,
    /// A stored digest does not match its recomputation.
    DigestMismatch {
        which: &'static str,
    },
    /// The encoded payload exceeds `max_entry_bytes`.
    TooLarge {
        bytes: usize,
        max: usize,
    },
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "{e}"),
            Self::Encode(e) => write!(f, "{e}"),
            Self::Invalid { what, why } => write!(f, "`{what}`: {why}"),
            Self::TotalsMismatch => write!(f, "unit_totals do not equal the fold over the legs"),
            Self::Overflow => write!(f, "a sum of leg amounts overflowed"),
            Self::DigestMismatch { which } => write!(f, "{which} does not match its recomputation"),
            Self::TooLarge { bytes, max } => {
                write!(f, "payload is {bytes} bytes; max_entry_bytes is {max}")
            }
        }
    }
}

impl core::error::Error for EntryError {}

impl From<DecodeError> for EntryError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<EncodeError> for EntryError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

fn invalid(what: &'static str, why: &'static str) -> EntryError {
    EntryError::Invalid { what, why }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

fn encode_amount(w: &mut Writer, a: &Amount) {
    w.u32(a.unit.0).i128(a.mantissa);
}

fn decode_amount(r: &mut Reader<'_>) -> Result<Amount, DecodeError> {
    Ok(Amount::new(
        UnitId(r.u32("amount.unit")?),
        r.i128("amount.mantissa")?,
    ))
}

fn encode_oid(w: &mut Writer, o: &Oid) {
    w.fixed(&o.0);
}

fn decode_oid(r: &mut Reader<'_>, what: &'static str) -> Result<Oid, DecodeError> {
    Ok(Oid(r.fixed(what)?))
}

fn encode_day(w: &mut Writer, d: &DateDay) {
    w.i32(d.0);
}

fn decode_day(r: &mut Reader<'_>, what: &'static str) -> Result<DateDay, DecodeError> {
    Ok(DateDay(r.i32(what)?))
}

/// A settlement application target (plan §5.3 `settles`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    pub target: EntryRef,
    pub ordinal: u16,
    pub amount: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegPayload {
    pub side: Side,
    pub account_ref: VId,
    pub amount: Amount,
    pub base_amount: Option<Amount>,
    /// Sorted strictly by dimension id.
    pub dimension_set: Vec<(u32, VId)>,
    pub memo: Option<Erasable<String>>,
    pub settles: Vec<Settlement>,
}

impl LegPayload {
    #[must_use]
    pub fn simple(side: Side, account_ref: VId, amount: Amount) -> Self {
        Self {
            side,
            account_ref,
            amount,
            base_amount: None,
            dimension_set: Vec::new(),
            memo: None,
            settles: Vec::new(),
        }
    }

    fn encode(&self, w: &mut Writer) {
        w.u8(match self.side {
            Side::Debit => 0,
            Side::Credit => 1,
        })
        .u128(self.account_ref.0);
        encode_amount(w, &self.amount);
        w.opt(self.base_amount.as_ref(), encode_amount)
            .list(&self.dimension_set, |w, (d, v)| {
                w.u32(*d).u128(v.0);
            })
            .opt(self.memo.as_ref(), |w, m| m.encode(w))
            .list(&self.settles, |w, s| {
                s.target.encode(w);
                w.u16(s.ordinal);
                encode_amount(w, &s.amount);
            });
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let side = match r.u8("leg.side")? {
            0 => Side::Debit,
            1 => Side::Credit,
            t => return Err(r.bad_tag("leg.side", t)),
        };
        let account_ref = VId(r.u128("leg.account_ref")?);
        let amount = decode_amount(r)?;
        let base_amount = r.opt("leg.base_amount", decode_amount)?;
        let dimension_set = r.list(MAX_DIMENSIONS_PER_LEG, "leg.dimension_set", |r| {
            Ok((r.u32("dimension.id")?, VId(r.u128("dimension.value")?)))
        })?;
        if !strictly_ascending(&dimension_set, |(d, _)| *d) {
            return Err(r.unsorted("leg.dimension_set"));
        }
        let memo = r.opt("leg.memo", |r| Erasable::decode(r, MAX_MEMO_BYTES))?;
        let settles = r.list(MAX_SETTLES_PER_LEG, "leg.settles", |r| {
            Ok(Settlement {
                target: EntryRef::decode(r)?,
                ordinal: r.u16("settles.ordinal")?,
                amount: decode_amount(r)?,
            })
        })?;
        Ok(Self {
            side,
            account_ref,
            amount,
            base_amount,
            dimension_set,
            memo,
            settles,
        })
    }

    fn validate(&self) -> Result<(), EntryError> {
        if self.amount.mantissa < 0 {
            return Err(invalid(
                "leg.amount",
                "a leg mantissa is non-negative; swap the side instead",
            ));
        }
        if self.base_amount.is_some_and(|b| b.mantissa < 0) {
            return Err(invalid(
                "leg.base_amount",
                "a base mantissa is non-negative",
            ));
        }
        if self.dimension_set.len() > MAX_DIMENSIONS_PER_LEG
            || !strictly_ascending(&self.dimension_set, |(d, _)| *d)
        {
            return Err(invalid(
                "leg.dimension_set",
                "must be strictly ascending by dimension id and within max_dimensions_per_leg",
            ));
        }
        if self.settles.len() > MAX_SETTLES_PER_LEG {
            return Err(invalid("leg.settles", "exceeds max_settles_per_leg"));
        }
        if self.settles.iter().any(|s| s.amount.mantissa < 0) {
            return Err(invalid(
                "leg.settles",
                "a settlement amount is non-negative",
            ));
        }
        Ok(())
    }
}

/// Per-unit sums over the legs (redundant, verified).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitTotal {
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Residual {
    pub leg_ordinal: u16,
    pub amount: Amount,
}

/// Functional-currency totals under the entry's FX law (plan §5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseTotals {
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
    pub fx_law_oid: Oid,
    /// Sorted.
    pub rate_doc_oids: Vec<Oid>,
    pub residual: Option<Residual>,
}

/// Where the entry came from. The dry-run plan certificate is *not* here: it
/// is computed over `proposal_digest` and therefore binds in the envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryOrigin {
    Intent {
        intent_oid: Oid,
        intent_kind: u16,
    },
    Rule {
        rule_version_oid: Oid,
        event_ref: VId,
        inputs_digest: [u8; 32],
    },
    Migration {
        run_ref: VId,
        source_system: String,
        source_id: Erasable<String>,
        source_recorded_at_ns: Option<i64>,
        source_entered_by: Option<Erasable<String>>,
        source_approved_by: Option<Erasable<String>>,
        batch_oid: Oid,
    },
    Control {
        control_kind: u16,
        spec_body_digest: [u8; 32],
    },
    Sweep {
        sweep_kind: u8,
        tick_evidence_oid: Oid,
    },
}

impl EntryOrigin {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::Intent {
                intent_oid,
                intent_kind,
            } => {
                w.u8(0);
                encode_oid(w, intent_oid);
                w.u16(*intent_kind);
            }
            Self::Rule {
                rule_version_oid,
                event_ref,
                inputs_digest,
            } => {
                w.u8(1);
                encode_oid(w, rule_version_oid);
                w.u128(event_ref.0).fixed(inputs_digest);
            }
            Self::Migration {
                run_ref,
                source_system,
                source_id,
                source_recorded_at_ns,
                source_entered_by,
                source_approved_by,
                batch_oid,
            } => {
                w.u8(2).u128(run_ref.0).str(source_system);
                source_id.encode(w);
                w.opt(source_recorded_at_ns.as_ref(), |w, v| {
                    w.i64(*v);
                })
                .opt(source_entered_by.as_ref(), |w, e| e.encode(w))
                .opt(source_approved_by.as_ref(), |w, e| e.encode(w));
                encode_oid(w, batch_oid);
            }
            Self::Control {
                control_kind,
                spec_body_digest,
            } => {
                w.u8(3).u16(*control_kind).fixed(spec_body_digest);
            }
            Self::Sweep {
                sweep_kind,
                tick_evidence_oid,
            } => {
                w.u8(4).u8(*sweep_kind);
                encode_oid(w, tick_evidence_oid);
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(match r.u8("origin.tag")? {
            0 => Self::Intent {
                intent_oid: decode_oid(r, "origin.intent_oid")?,
                intent_kind: r.u16("origin.intent_kind")?,
            },
            1 => Self::Rule {
                rule_version_oid: decode_oid(r, "origin.rule_version_oid")?,
                event_ref: VId(r.u128("origin.event_ref")?),
                inputs_digest: r.fixed("origin.inputs_digest")?,
            },
            2 => Self::Migration {
                run_ref: VId(r.u128("origin.run_ref")?),
                source_system: r.str(MAX_SYSTEM_BYTES, "origin.source_system")?.to_string(),
                source_id: Erasable::decode(r, MAX_EXTERNAL_ID_BYTES)?,
                source_recorded_at_ns: r.opt("origin.source_recorded_at", |r| {
                    r.i64("origin.source_recorded_at")
                })?,
                source_entered_by: r.opt("origin.source_entered_by", |r| {
                    Erasable::decode(r, MAX_EXTERNAL_ID_BYTES)
                })?,
                source_approved_by: r.opt("origin.source_approved_by", |r| {
                    Erasable::decode(r, MAX_EXTERNAL_ID_BYTES)
                })?,
                batch_oid: decode_oid(r, "origin.batch_oid")?,
            },
            3 => Self::Control {
                control_kind: r.u16("origin.control_kind")?,
                spec_body_digest: r.fixed("origin.spec_body_digest")?,
            },
            4 => Self::Sweep {
                sweep_kind: r.u8("origin.sweep_kind")?,
                tick_evidence_oid: decode_oid(r, "origin.tick_evidence_oid")?,
            },
            t => return Err(r.bad_tag("origin.tag", t)),
        })
    }
}

/// Control records carry no legs; the payload says what changed (Appendix A).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlPayload {
    PeriodTransition {
        period_ref: PeriodRef,
        from: u8,
        to: u8,
        reason_code: u16,
        case_ref: Option<VId>,
    },
    SchemaChange {
        kind: u16,
        canonical_bytes: Vec<u8>,
    },
    PolicyActivation {
        policy_oid: Oid,
        effective_from: DateDay,
        effective_to: DateDay,
    },
    LifecycleTransition {
        object_ref: VId,
        from: u8,
        to: u8,
        proof_refs: Vec<TypedRef>,
        reason_code: u16,
    },
    TimeTick {
        observed_utc_ns: u64,
        source: u8,
        monotonic_ok: bool,
    },
    SweepCursor {
        sweep_kind: u8,
        last_pending_vid: VId,
        tick_ref: VId,
    },
    ScheduleCancelled {
        schedule_ref: VId,
        cause_ref: VId,
    },
    CapabilityEvent {
        commitment: [u8; 32],
        kind: u8,
        caveats_digest: [u8; 32],
    },
    HoldEvent {
        scope_digest: [u8; 32],
        authority_oid: Oid,
        kind: u8,
    },
    ErasureCut {
        subject_ref: VId,
        field_digests: Vec<[u8; 32]>,
    },
    MigrationControl {
        run_ref: VId,
        kind: u8,
        tie_out_digest: [u8; 32],
    },
}

impl ControlPayload {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::PeriodTransition {
                period_ref,
                from,
                to,
                reason_code,
                case_ref,
            } => {
                w.u8(0);
                period_ref.encode(w);
                w.u8(*from)
                    .u8(*to)
                    .u16(*reason_code)
                    .opt(case_ref.as_ref(), |w, v| {
                        w.u128(v.0);
                    });
            }
            Self::SchemaChange {
                kind,
                canonical_bytes,
            } => {
                w.u8(1).u16(*kind).bytes(canonical_bytes);
            }
            Self::PolicyActivation {
                policy_oid,
                effective_from,
                effective_to,
            } => {
                w.u8(2);
                encode_oid(w, policy_oid);
                encode_day(w, effective_from);
                encode_day(w, effective_to);
            }
            Self::LifecycleTransition {
                object_ref,
                from,
                to,
                proof_refs,
                reason_code,
            } => {
                w.u8(3)
                    .u128(object_ref.0)
                    .u8(*from)
                    .u8(*to)
                    .list(proof_refs, |w, p| p.encode(w))
                    .u16(*reason_code);
            }
            Self::TimeTick {
                observed_utc_ns,
                source,
                monotonic_ok,
            } => {
                w.u8(4)
                    .u64(*observed_utc_ns)
                    .u8(*source)
                    .bool(*monotonic_ok);
            }
            Self::SweepCursor {
                sweep_kind,
                last_pending_vid,
                tick_ref,
            } => {
                w.u8(5)
                    .u8(*sweep_kind)
                    .u128(last_pending_vid.0)
                    .u128(tick_ref.0);
            }
            Self::ScheduleCancelled {
                schedule_ref,
                cause_ref,
            } => {
                w.u8(6).u128(schedule_ref.0).u128(cause_ref.0);
            }
            Self::CapabilityEvent {
                commitment,
                kind,
                caveats_digest,
            } => {
                w.u8(7).fixed(commitment).u8(*kind).fixed(caveats_digest);
            }
            Self::HoldEvent {
                scope_digest,
                authority_oid,
                kind,
            } => {
                w.u8(8).fixed(scope_digest);
                encode_oid(w, authority_oid);
                w.u8(*kind);
            }
            Self::ErasureCut {
                subject_ref,
                field_digests,
            } => {
                w.u8(9).u128(subject_ref.0).list(field_digests, |w, d| {
                    w.fixed(d);
                });
            }
            Self::MigrationControl {
                run_ref,
                kind,
                tie_out_digest,
            } => {
                w.u8(10).u128(run_ref.0).u8(*kind).fixed(tie_out_digest);
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(match r.u8("control.tag")? {
            0 => Self::PeriodTransition {
                period_ref: PeriodRef::decode(r)?,
                from: r.u8("control.from")?,
                to: r.u8("control.to")?,
                reason_code: r.u16("control.reason_code")?,
                case_ref: r.opt("control.case_ref", |r| r.u128("control.case_ref").map(VId))?,
            },
            1 => Self::SchemaChange {
                kind: r.u16("control.kind")?,
                canonical_bytes: r
                    .bytes(MAX_SCHEMA_CHANGE_BYTES, "control.canonical_bytes")?
                    .to_vec(),
            },
            2 => Self::PolicyActivation {
                policy_oid: decode_oid(r, "control.policy_oid")?,
                effective_from: decode_day(r, "control.effective_from")?,
                effective_to: decode_day(r, "control.effective_to")?,
            },
            3 => Self::LifecycleTransition {
                object_ref: VId(r.u128("control.object_ref")?),
                from: r.u8("control.from")?,
                to: r.u8("control.to")?,
                proof_refs: r.list(MAX_PROOF_REFS, "control.proof_refs", TypedRef::decode)?,
                reason_code: r.u16("control.reason_code")?,
            },
            4 => Self::TimeTick {
                observed_utc_ns: r.u64("control.observed_utc_ns")?,
                source: r.u8("control.source")?,
                monotonic_ok: r.bool("control.monotonic_ok")?,
            },
            5 => Self::SweepCursor {
                sweep_kind: r.u8("control.sweep_kind")?,
                last_pending_vid: VId(r.u128("control.last_pending_vid")?),
                tick_ref: VId(r.u128("control.tick_ref")?),
            },
            6 => Self::ScheduleCancelled {
                schedule_ref: VId(r.u128("control.schedule_ref")?),
                cause_ref: VId(r.u128("control.cause_ref")?),
            },
            7 => Self::CapabilityEvent {
                commitment: r.fixed("control.commitment")?,
                kind: r.u8("control.kind")?,
                caveats_digest: r.fixed("control.caveats_digest")?,
            },
            8 => Self::HoldEvent {
                scope_digest: r.fixed("control.scope_digest")?,
                authority_oid: decode_oid(r, "control.authority_oid")?,
                kind: r.u8("control.kind")?,
            },
            9 => {
                let subject_ref = VId(r.u128("control.subject_ref")?);
                let field_digests = r.list(MAX_FIELD_DIGESTS, "control.field_digests", |r| {
                    r.fixed("control.field_digest")
                })?;
                if !strictly_ascending(&field_digests, |d| *d) {
                    return Err(r.unsorted("control.field_digests"));
                }
                Self::ErasureCut {
                    subject_ref,
                    field_digests,
                }
            }
            10 => Self::MigrationControl {
                run_ref: VId(r.u128("control.run_ref")?),
                kind: r.u8("control.kind")?,
                tie_out_digest: r.fixed("control.tie_out_digest")?,
            },
            t => return Err(r.bad_tag("control.tag", t)),
        })
    }

    fn validate(&self) -> Result<(), EntryError> {
        match self {
            Self::PeriodTransition { period_ref, .. } if !period_ref.within_bounds() => Err(
                invalid("control.period_ref", "exceeds max_period_ref_bytes"),
            ),
            Self::SchemaChange {
                canonical_bytes, ..
            } if canonical_bytes.len() > MAX_SCHEMA_CHANGE_BYTES => Err(invalid(
                "control.canonical_bytes",
                "exceeds max_schema_change_bytes",
            )),
            Self::LifecycleTransition { proof_refs, .. } if proof_refs.len() > MAX_PROOF_REFS => {
                Err(invalid("control.proof_refs", "exceeds max_proof_refs"))
            }
            Self::ErasureCut { field_digests, .. }
                if field_digests.len() > MAX_FIELD_DIGESTS
                    || !strictly_ascending(field_digests, |d| *d) =>
            {
                Err(invalid(
                    "control.field_digests",
                    "must be strictly ascending and within max_field_digests",
                ))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Disposition {
    Posts { posted_legs: Vec<LegPayload> },
    Voids,
    Expires { at_tick: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub timeout_ns: Option<u64>,
    pub resolution_of: Option<EntryRef>,
    pub disposition: Option<Disposition>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SupersessionKind {
    Reverses = 1,
    Replaces = 2,
    Reclassifies = 3,
    Revises = 4,
    Restates = 5,
    Resolves = 6,
}

impl SupersessionKind {
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Reverses,
            2 => Self::Replaces,
            3 => Self::Reclassifies,
            4 => Self::Revises,
            5 => Self::Restates,
            6 => Self::Resolves,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Supersession {
    pub target: EntryRef,
    pub kind: SupersessionKind,
    pub reason_code: u16,
}

/// A provenance-closure head: a document with its public commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceRef {
    pub document_oid: Oid,
    pub doc_commit: [u8; 32],
    pub role: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalId {
    pub system: String,
    pub id: Erasable<String>,
}

/// The storable scalar subset a tag may hold, under FrankenAccounting's own
/// codec so the durable format never tracks the substrate's scalar encoding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TagValue {
    Null,
    Bool(bool),
    Int(i64),
    Text(String),
    Bytes(Vec<u8>),
}

impl Canonical for TagValue {
    fn write_canonical(&self, w: &mut Writer) {
        match self {
            Self::Null => {
                w.u8(0);
            }
            Self::Bool(b) => {
                w.u8(1).bool(*b);
            }
            Self::Int(i) => {
                w.u8(2).i64(*i);
            }
            Self::Text(s) => {
                w.u8(3).str(s);
            }
            Self::Bytes(b) => {
                w.u8(4).bytes(b);
            }
        }
    }

    fn read_canonical(r: &mut Reader<'_>, max: usize) -> Result<Self, DecodeError> {
        Ok(match r.u8("tag.kind")? {
            0 => Self::Null,
            1 => Self::Bool(r.bool("tag.bool")?),
            2 => Self::Int(r.i64("tag.int")?),
            3 => Self::Text(r.str(max.min(MAX_TAG_TEXT_BYTES), "tag.text")?.to_string()),
            4 => Self::Bytes(r.bytes(max.min(MAX_TAG_BYTES_VALUE), "tag.bytes")?.to_vec()),
            t => return Err(r.bad_tag("tag.kind", t)),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    pub key: String,
    pub value: Erasable<TagValue>,
}

// ---------------------------------------------------------------------------
// The proposal
// ---------------------------------------------------------------------------

/// Every entry field except the envelope (`plan_certificate_oid`,
/// `approvals`) and the two digests: what an approval binds (plan §4.6
/// `EntryProposal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryPayload {
    pub schema_minor: u16,
    pub book_id: Id128,
    pub branch_id: Id128,
    pub class: EntryClass,
    pub effective_date: DateDay,
    pub document_date: Option<DateDay>,
    pub description: Erasable<String>,
    pub effective_period: Option<PeriodRef>,
    pub legs: Vec<LegPayload>,
    pub control: Option<ControlPayload>,
    /// Sorted by `unit_id`; equal to [`EntryPayload::fold_unit_totals`].
    pub unit_totals: Vec<UnitTotal>,
    pub base_totals: Option<BaseTotals>,
    pub idempotency_key: Vec<u8>,
    pub origin: EntryOrigin,
    pub principal_ref: VId,
    pub session_ref: Option<VId>,
    /// Sorted strictly by `(document_oid, doc_commit, role)`.
    pub evidence: Vec<EvidenceRef>,
    pub supersession: Vec<Supersession>,
    pub pending: Option<Pending>,
    /// Sorted strictly by `(system, id.field_digest)`.
    pub external_ids: Vec<ExternalId>,
    /// Sorted strictly by `key`.
    pub tags: Vec<Tag>,
}

impl EntryPayload {
    /// The per-unit debit and credit sums over `legs`, sorted by unit, with
    /// checked arithmetic.
    pub fn fold_unit_totals(legs: &[LegPayload]) -> Result<Vec<UnitTotal>, EntryError> {
        let mut totals: Vec<UnitTotal> = Vec::new();
        for leg in legs {
            let idx = match totals.binary_search_by_key(&leg.amount.unit.0, |t| t.unit_id) {
                Ok(i) => i,
                Err(i) => {
                    totals.insert(
                        i,
                        UnitTotal {
                            unit_id: leg.amount.unit.0,
                            debits: 0,
                            credits: 0,
                        },
                    );
                    i
                }
            };
            let t = &mut totals[idx];
            let slot = match leg.side {
                Side::Debit => &mut t.debits,
                Side::Credit => &mut t.credits,
            };
            *slot = slot
                .checked_add(leg.amount.mantissa)
                .ok_or(EntryError::Overflow)?;
        }
        Ok(totals)
    }

    /// Structural validation (not the accounting laws).
    pub fn validate(&self) -> Result<(), EntryError> {
        if !self.class.is_registered() {
            return Err(invalid("class", "not a registered entry class"));
        }
        if self.class.is_control() {
            if !self.legs.is_empty() {
                return Err(invalid("legs", "a control class carries no legs"));
            }
            match &self.control {
                None => {
                    return Err(invalid(
                        "control",
                        "a control class carries a control payload",
                    ));
                }
                Some(c) => c.validate()?,
            }
        } else {
            if self.control.is_some() {
                return Err(invalid(
                    "control",
                    "a posting class carries no control payload",
                ));
            }
            if self.legs.len() < 2 {
                return Err(invalid("legs", "a posting class has at least two legs"));
            }
            if self.legs.len() > MAX_LEGS_PER_ENTRY {
                return Err(invalid("legs", "exceeds max_legs_per_entry"));
            }
        }
        for leg in &self.legs {
            leg.validate()?;
        }
        if self.unit_totals != Self::fold_unit_totals(&self.legs)? {
            return Err(EntryError::TotalsMismatch);
        }
        if self.idempotency_key.is_empty() || self.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        {
            return Err(invalid(
                "idempotency_key",
                "1..=max_idempotency_key_bytes bytes",
            ));
        }
        if self
            .effective_period
            .as_ref()
            .is_some_and(|p| !p.within_bounds())
        {
            return Err(invalid("effective_period", "exceeds max_period_ref_bytes"));
        }
        if let Some(b) = &self.base_totals {
            if b.rate_doc_oids.len() > MAX_RATE_DOCS
                || !strictly_ascending(&b.rate_doc_oids, |o| *o)
            {
                return Err(invalid(
                    "base_totals.rate_doc_oids",
                    "must be strictly ascending and within max_rate_docs",
                ));
            }
            if b.residual
                .is_some_and(|r| usize::from(r.leg_ordinal) >= self.legs.len())
            {
                return Err(invalid(
                    "base_totals.residual",
                    "leg_ordinal names a leg that does not exist",
                ));
            }
        }
        if self.evidence.len() > MAX_EVIDENCE_PER_ENTRY
            || !strictly_ascending(&self.evidence, |e| *e)
        {
            return Err(invalid(
                "evidence",
                "must be strictly ascending and within max_evidence_per_entry",
            ));
        }
        if self.supersession.len() > MAX_SUPERSESSION_PER_ENTRY {
            return Err(invalid(
                "supersession",
                "exceeds max_supersession_per_entry",
            ));
        }
        if let Some(Pending {
            disposition: Some(Disposition::Posts { posted_legs }),
            ..
        }) = &self.pending
        {
            if posted_legs.len() > MAX_LEGS_PER_ENTRY {
                return Err(invalid("pending.disposition", "exceeds max_legs_per_entry"));
            }
            for leg in posted_legs {
                leg.validate()?;
            }
        }
        if self.external_ids.len() > MAX_EXTERNAL_IDS
            || self
                .external_ids
                .iter()
                .any(|x| x.system.len() > MAX_SYSTEM_BYTES)
            || !strictly_ascending(&self.external_ids, |x| {
                (x.system.clone(), x.id.field_digest())
            })
        {
            return Err(invalid(
                "external_ids",
                "must be strictly ascending by (system, id digest) and within bounds",
            ));
        }
        let tag_bytes: usize = self
            .tags
            .iter()
            .map(|t| t.key.len() + t.value.wire_len())
            .sum();
        if self.tags.len() > MAX_TAGS
            || tag_bytes > MAX_TAGS_BYTES
            || self
                .tags
                .iter()
                .any(|t| t.key.is_empty() || t.key.len() > MAX_TAG_KEY_BYTES)
            || !strictly_ascending(&self.tags, |t| t.key.clone())
        {
            return Err(invalid(
                "tags",
                "must be strictly ascending by key and within max_tags / max_tags_bytes",
            ));
        }
        Ok(())
    }

    fn encode_into(&self, w: &mut Writer) {
        w.u16(SCHEMA_MAJOR)
            .u16(self.schema_minor)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u16(self.class.0);
        encode_day(w, &self.effective_date);
        w.opt(self.document_date.as_ref(), encode_day);
        self.description.encode(w);
        w.opt(self.effective_period.as_ref(), |w, p| p.encode(w))
            .list(&self.legs, |w, l| l.encode(w))
            .opt(self.control.as_ref(), |w, c| c.encode(w))
            .list(&self.unit_totals, |w, t| {
                w.u32(t.unit_id).i128(t.debits).i128(t.credits);
            })
            .opt(self.base_totals.as_ref(), |w, b| {
                w.u32(b.unit_id).i128(b.debits).i128(b.credits);
                encode_oid(w, &b.fx_law_oid);
                w.list(&b.rate_doc_oids, encode_oid)
                    .opt(b.residual.as_ref(), |w, r| {
                        w.u16(r.leg_ordinal);
                        encode_amount(w, &r.amount);
                    });
            })
            .bytes(&self.idempotency_key);
        self.origin.encode(w);
        w.u128(self.principal_ref.0)
            .opt(self.session_ref.as_ref(), |w, v| {
                w.u128(v.0);
            })
            .list(&self.evidence, |w, e| {
                encode_oid(w, &e.document_oid);
                w.fixed(&e.doc_commit).u8(e.role);
            })
            .list(&self.supersession, |w, s| {
                s.target.encode(w);
                w.u8(s.kind as u8).u16(s.reason_code);
            })
            .opt(self.pending.as_ref(), |w, p| {
                w.opt(p.timeout_ns.as_ref(), |w, t| {
                    w.u64(*t);
                })
                .opt(p.resolution_of.as_ref(), |w, r| r.encode(w))
                .opt(p.disposition.as_ref(), |w, d| match d {
                    Disposition::Posts { posted_legs } => {
                        w.u8(0).list(posted_legs, |w, l| l.encode(w));
                    }
                    Disposition::Voids => {
                        w.u8(1);
                    }
                    Disposition::Expires { at_tick } => {
                        w.u8(2).u64(*at_tick);
                    }
                });
            })
            .list(&self.external_ids, |w, x| {
                w.str(&x.system);
                x.id.encode(w);
            })
            .list(&self.tags, |w, t| {
                w.str(&t.key);
                t.value.encode(w);
            });
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let major = r.u16("schema_major")?;
        if major != SCHEMA_MAJOR {
            return Err(r.invalid("schema_major"));
        }
        let schema_minor = r.u16("schema_minor")?;
        let book_id = Id128(r.fixed("book_id")?);
        let branch_id = Id128(r.fixed("branch_id")?);
        let class = EntryClass(r.u16("class")?);
        let effective_date = decode_day(r, "effective_date")?;
        let document_date = r.opt("document_date", |r| decode_day(r, "document_date"))?;
        let description = Erasable::decode(r, MAX_DESCRIPTION_BYTES)?;
        let effective_period = r.opt("effective_period", PeriodRef::decode)?;
        let legs = r.list(MAX_LEGS_PER_ENTRY, "legs", LegPayload::decode)?;
        let control = r.opt("control", ControlPayload::decode)?;
        let unit_totals = r.list(MAX_LEGS_PER_ENTRY, "unit_totals", |r| {
            Ok(UnitTotal {
                unit_id: r.u32("unit_totals.unit_id")?,
                debits: r.i128("unit_totals.debits")?,
                credits: r.i128("unit_totals.credits")?,
            })
        })?;
        let base_totals = r.opt("base_totals", |r| {
            Ok(BaseTotals {
                unit_id: r.u32("base_totals.unit_id")?,
                debits: r.i128("base_totals.debits")?,
                credits: r.i128("base_totals.credits")?,
                fx_law_oid: decode_oid(r, "base_totals.fx_law_oid")?,
                rate_doc_oids: r.list(MAX_RATE_DOCS, "base_totals.rate_doc_oids", |r| {
                    decode_oid(r, "base_totals.rate_doc_oid")
                })?,
                residual: r.opt("base_totals.residual", |r| {
                    Ok(Residual {
                        leg_ordinal: r.u16("residual.leg_ordinal")?,
                        amount: decode_amount(r)?,
                    })
                })?,
            })
        })?;
        let idempotency_key = r
            .bytes(MAX_IDEMPOTENCY_KEY_BYTES, "idempotency_key")?
            .to_vec();
        let origin = EntryOrigin::decode(r)?;
        let principal_ref = VId(r.u128("principal_ref")?);
        let session_ref = r.opt("session_ref", |r| r.u128("session_ref").map(VId))?;
        let evidence = r.list(MAX_EVIDENCE_PER_ENTRY, "evidence", |r| {
            Ok(EvidenceRef {
                document_oid: decode_oid(r, "evidence.document_oid")?,
                doc_commit: r.fixed("evidence.doc_commit")?,
                role: r.u8("evidence.role")?,
            })
        })?;
        let supersession = r.list(MAX_SUPERSESSION_PER_ENTRY, "supersession", |r| {
            let target = EntryRef::decode(r)?;
            let k = r.u8("supersession.kind")?;
            let kind =
                SupersessionKind::from_u8(k).ok_or_else(|| r.bad_tag("supersession.kind", k))?;
            Ok(Supersession {
                target,
                kind,
                reason_code: r.u16("supersession.reason_code")?,
            })
        })?;
        let pending = r.opt("pending", |r| {
            Ok(Pending {
                timeout_ns: r.opt("pending.timeout_ns", |r| r.u64("pending.timeout_ns"))?,
                resolution_of: r.opt("pending.resolution_of", EntryRef::decode)?,
                disposition: r.opt("pending.disposition", |r| {
                    Ok(match r.u8("disposition.tag")? {
                        0 => Disposition::Posts {
                            posted_legs: r.list(
                                MAX_LEGS_PER_ENTRY,
                                "disposition.posted_legs",
                                LegPayload::decode,
                            )?,
                        },
                        1 => Disposition::Voids,
                        2 => Disposition::Expires {
                            at_tick: r.u64("disposition.at_tick")?,
                        },
                        t => return Err(r.bad_tag("disposition.tag", t)),
                    })
                })?,
            })
        })?;
        let external_ids = r.list(MAX_EXTERNAL_IDS, "external_ids", |r| {
            Ok(ExternalId {
                system: r.str(MAX_SYSTEM_BYTES, "external_ids.system")?.to_string(),
                id: Erasable::decode(r, MAX_EXTERNAL_ID_BYTES)?,
            })
        })?;
        let tags = r.list(MAX_TAGS, "tags", |r| {
            Ok(Tag {
                key: r.str(MAX_TAG_KEY_BYTES, "tags.key")?.to_string(),
                value: Erasable::decode(r, MAX_TAG_BYTES_VALUE + 1)?,
            })
        })?;
        Ok(Self {
            schema_minor,
            book_id,
            branch_id,
            class,
            effective_date,
            document_date,
            description,
            effective_period,
            legs,
            control,
            unit_totals,
            base_totals,
            idempotency_key,
            origin,
            principal_ref,
            session_ref,
            evidence,
            supersession,
            pending,
            external_ids,
            tags,
        })
    }

    /// The canonical proposal bytes (validated first).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EntryError> {
        self.validate()?;
        let mut w = Writer::with_capacity(512);
        self.encode_into(&mut w);
        Ok(w.finish()?)
    }

    /// `BLAKE3("fa:entry-proposal:v1" ‖ canonical(proposal))`.
    pub fn proposal_digest(&self) -> Result<[u8; 32], EntryError> {
        Ok(proposal_digest_of(&self.canonical_bytes()?))
    }

    /// Bind the envelope — the dry-run plan certificate (if any) and the
    /// approval transcript — and produce the committed entry.
    pub fn seal(
        self,
        approvals: Vec<ApprovalRef>,
        plan_certificate: Option<Oid>,
    ) -> Result<Entry, EntryError> {
        let proposal_bytes = self.canonical_bytes()?;
        if approvals.len() > MAX_APPROVALS {
            return Err(invalid("approvals", "exceeds max_approvals"));
        }
        let proposal_digest = proposal_digest_of(&proposal_bytes);
        let envelope_bytes = encode_envelope(plan_certificate.as_ref(), &approvals)?;
        let entry_digest = entry_digest_of(&proposal_digest, &envelope_bytes);
        let total = proposal_bytes.len() + envelope_bytes.len() + 64;
        if total > MAX_ENTRY_BYTES {
            return Err(EntryError::TooLarge {
                bytes: total,
                max: MAX_ENTRY_BYTES,
            });
        }
        Ok(Entry {
            proposal: self,
            plan_certificate,
            approvals,
            proposal_digest,
            entry_digest,
        })
    }
}

fn proposal_digest_of(proposal_bytes: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(PROPOSAL_DIGEST_DOMAIN);
    h.update(proposal_bytes);
    h.finalize().0
}

fn entry_digest_of(proposal_digest: &[u8; 32], envelope_bytes: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(ENTRY_DIGEST_DOMAIN);
    h.update(proposal_digest);
    h.update(envelope_bytes);
    h.finalize().0
}

/// `opt(plan_certificate_oid) ‖ list(approvals)`.
fn encode_envelope(
    plan_certificate: Option<&Oid>,
    approvals: &[ApprovalRef],
) -> Result<Vec<u8>, EncodeError> {
    let mut w = Writer::with_capacity(1 + 32 + 4 + approvals.len() * 48);
    w.opt(plan_certificate, encode_oid)
        .list(approvals, |w, a| a.encode(w));
    w.finish()
}

// ---------------------------------------------------------------------------
// The committed envelope
// ---------------------------------------------------------------------------

/// `proposal ‖ opt(plan_certificate_oid) ‖ approvals ‖ proposal_digest ‖ entry_digest`
/// on the wire. Only [`EntryPayload::seal`] and [`Entry::decode`] construct
/// one, so the digests always match the fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub proposal: EntryPayload,
    /// The dry-run certificate this entry was committed under, if any
    /// (Appendix A construction order: it is built over `proposal_digest`).
    pub plan_certificate: Option<Oid>,
    pub approvals: Vec<ApprovalRef>,
    pub proposal_digest: [u8; 32],
    pub entry_digest: [u8; 32],
}

impl Entry {
    /// The `_fa_payload` bytes.
    pub fn encode(&self) -> Result<Vec<u8>, EntryError> {
        let mut bytes = self.proposal.canonical_bytes()?;
        bytes.extend_from_slice(&encode_envelope(
            self.plan_certificate.as_ref(),
            &self.approvals,
        )?);
        bytes.extend_from_slice(&self.proposal_digest);
        bytes.extend_from_slice(&self.entry_digest);
        Ok(bytes)
    }

    /// Decode and verify: structure, both digests, no trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, EntryError> {
        if bytes.len() > MAX_ENTRY_BYTES {
            return Err(EntryError::TooLarge {
                bytes: bytes.len(),
                max: MAX_ENTRY_BYTES,
            });
        }
        let mut r = Reader::new(bytes);
        let proposal = EntryPayload::decode_from(&mut r)?;
        let proposal_end = r.offset();
        let plan_certificate = r.opt("plan_certificate_oid", |r| {
            decode_oid(r, "plan_certificate_oid")
        })?;
        let approvals = r.list(MAX_APPROVALS, "approvals", ApprovalRef::decode)?;
        let envelope_end = r.offset();
        let proposal_digest: [u8; 32] = r.fixed("proposal_digest")?;
        let entry_digest: [u8; 32] = r.fixed("entry_digest")?;
        r.finish()?;
        proposal.validate()?;
        if proposal_digest_of(&bytes[..proposal_end]) != proposal_digest {
            return Err(EntryError::DigestMismatch {
                which: "proposal_digest",
            });
        }
        if entry_digest_of(&proposal_digest, &bytes[proposal_end..envelope_end]) != entry_digest {
            return Err(EntryError::DigestMismatch {
                which: "entry_digest",
            });
        }
        Ok(Self {
            proposal,
            plan_certificate,
            approvals,
            proposal_digest,
            entry_digest,
        })
    }

    #[must_use]
    pub fn entry_ref(&self, vid: VId) -> EntryRef {
        EntryRef {
            vid,
            entry_digest: self.entry_digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erasable::SealKey;

    const KEY: SealKey = SealKey([7; 32]);
    const USD: UnitId = UnitId(1);

    fn desc(s: &str) -> Erasable<String> {
        Erasable::seal(&s.to_string(), None, &KEY, [1; 32], [2; 24])
    }

    fn proposal(legs: Vec<LegPayload>) -> EntryPayload {
        let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
        EntryPayload {
            schema_minor: SCHEMA_MINOR,
            book_id: Id128([9; 16]),
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: DateDay(20_000),
            document_date: Some(DateDay(19_999)),
            description: desc("Office rent, March"),
            effective_period: None,
            legs,
            control: None,
            unit_totals,
            base_totals: None,
            idempotency_key: b"inv-1001".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: VId(77),
            session_ref: Some(VId(78)),
            evidence: vec![EvidenceRef {
                document_oid: Oid([3; 32]),
                doc_commit: [4; 32],
                role: 1,
            }],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            tags: vec![Tag {
                key: "cost_center".into(),
                value: Erasable::seal(&TagValue::Text("HQ".into()), None, &KEY, [5; 32], [6; 24]),
            }],
        }
    }

    fn two_legs() -> Vec<LegPayload> {
        vec![
            LegPayload::simple(Side::Debit, VId(1), Amount::new(USD, 120_000)),
            LegPayload::simple(Side::Credit, VId(2), Amount::new(USD, 120_000)),
        ]
    }

    #[test]
    fn code_classes_match_registry() {
        let reg = fa_registry::EntryClasses::embedded().unwrap();
        assert_eq!(reg.rows.len(), EntryClass::ALL.len());
        for row in &reg.rows {
            let c = EntryClass::from_name(&row.name).expect("class in code");
            assert_eq!(c.0, row.tag, "{}", row.name);
            assert_eq!(
                c.is_control(),
                row.kind == fa_registry::ClassKind::Control,
                "{}",
                row.name
            );
        }
    }

    #[test]
    fn envelope_round_trips_and_verifies() {
        let entry = proposal(two_legs())
            .seal(vec![], Some(Oid([2; 32])))
            .unwrap();
        let bytes = entry.encode().unwrap();
        let back = Entry::decode(&bytes).unwrap();
        assert_eq!(back, entry);
        assert_eq!(back.encode().unwrap(), bytes);
        assert_eq!(back.plan_certificate, Some(Oid([2; 32])));
        assert_eq!(
            back.proposal.description.open(&KEY, 1024).unwrap(),
            "Office rent, March"
        );
        assert_eq!(
            back.proposal.tags[0].value.open(&KEY, 1024).unwrap(),
            TagValue::Text("HQ".into())
        );
        assert_eq!(
            back.proposal.unit_totals,
            vec![UnitTotal {
                unit_id: 1,
                debits: 120_000,
                credits: 120_000
            }]
        );
    }

    /// fa-syy's negative: one changed leg changes `proposal_digest`, so any
    /// approval over the old digest no longer binds.
    #[test]
    fn changing_one_leg_changes_the_proposal_digest() {
        let a = proposal(two_legs()).proposal_digest().unwrap();
        let mut legs = two_legs();
        legs[0].amount.mantissa += 1;
        legs[1].amount.mantissa += 1;
        let mut p = proposal(legs);
        p.unit_totals = EntryPayload::fold_unit_totals(&p.legs).unwrap();
        assert_ne!(a, p.proposal_digest().unwrap());
    }

    /// The acyclic construction order: the plan certificate and the approvals
    /// change the envelope digest, never the proposal digest they are built
    /// from.
    #[test]
    fn envelope_fields_change_the_entry_digest_but_not_the_proposal_digest() {
        let p = proposal(two_legs());
        let e0 = p.clone().seal(vec![], None).unwrap();
        let e_cert = p.clone().seal(vec![], Some(Oid([2; 32]))).unwrap();
        let e_appr = p
            .seal(
                vec![ApprovalRef {
                    approval_vid: VId(500),
                    approved_digest: e0.proposal_digest,
                }],
                None,
            )
            .unwrap();
        assert_eq!(e0.proposal_digest, e_cert.proposal_digest);
        assert_eq!(e0.proposal_digest, e_appr.proposal_digest);
        assert_ne!(e0.entry_digest, e_cert.entry_digest);
        assert_ne!(e0.entry_digest, e_appr.entry_digest);
        assert_ne!(e_cert.entry_digest, e_appr.entry_digest);
        assert_eq!(
            Entry::decode(&e_appr.encode().unwrap())
                .unwrap()
                .approvals
                .len(),
            1
        );
    }

    #[test]
    fn tampered_bytes_are_refused() {
        let entry = proposal(two_legs())
            .seal(vec![], Some(Oid([2; 32])))
            .unwrap();
        let bytes = entry.encode().unwrap();
        // Every byte before the digests is covered by one of them.
        for i in 0..bytes.len() - 64 {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            assert!(
                Entry::decode(&t).is_err(),
                "byte {i} flipped and still decoded"
            );
        }
        // The stored entry_digest is checked too.
        let mut t = bytes.clone();
        let n = t.len();
        t[n - 1] ^= 1;
        assert_eq!(
            Entry::decode(&t).unwrap_err(),
            EntryError::DigestMismatch {
                which: "entry_digest"
            }
        );
        // Trailing bytes are refused.
        let mut t = bytes;
        t.push(0);
        assert!(matches!(
            Entry::decode(&t).unwrap_err(),
            EntryError::Decode(_)
        ));
    }

    #[test]
    fn structural_rules_are_enforced() {
        let one_leg = proposal(vec![LegPayload::simple(
            Side::Debit,
            VId(1),
            Amount::new(USD, 5),
        )]);
        assert_eq!(
            one_leg.validate().unwrap_err(),
            EntryError::Invalid {
                what: "legs",
                why: "a posting class has at least two legs"
            }
        );

        let mut neg = proposal(two_legs());
        neg.legs[0].amount.mantissa = -1;
        neg.unit_totals = vec![];
        assert!(matches!(
            neg.validate().unwrap_err(),
            EntryError::Invalid {
                what: "leg.amount",
                ..
            }
        ));

        let mut totals = proposal(two_legs());
        totals.unit_totals[0].debits += 1;
        assert_eq!(totals.validate().unwrap_err(), EntryError::TotalsMismatch);

        let mut key = proposal(two_legs());
        key.idempotency_key.clear();
        assert!(matches!(
            key.validate().unwrap_err(),
            EntryError::Invalid {
                what: "idempotency_key",
                ..
            }
        ));

        let mut unregistered = proposal(two_legs());
        unregistered.class = EntryClass(999);
        assert!(matches!(
            unregistered.validate().unwrap_err(),
            EntryError::Invalid { what: "class", .. }
        ));

        let mut control_with_legs = proposal(two_legs());
        control_with_legs.class = EntryClass::PERIOD_CONTROL;
        assert!(matches!(
            control_with_legs.validate().unwrap_err(),
            EntryError::Invalid { what: "legs", .. }
        ));

        let mut unsorted_tags = proposal(two_legs());
        unsorted_tags.tags.push(Tag {
            key: "aaa".into(),
            value: Erasable::seal(&TagValue::Null, None, &KEY, [0; 32], [0; 24]),
        });
        assert!(matches!(
            unsorted_tags.validate().unwrap_err(),
            EntryError::Invalid { what: "tags", .. }
        ));

        let big: Vec<LegPayload> = (0..MAX_LEGS_PER_ENTRY + 1)
            .map(|i| LegPayload::simple(Side::Debit, VId(i as u128), Amount::new(USD, 1)))
            .collect();
        assert!(matches!(
            proposal(big).validate().unwrap_err(),
            EntryError::Invalid { what: "legs", .. }
        ));
    }

    #[test]
    fn overflowing_leg_sums_are_refused_not_wrapped() {
        let legs = vec![
            LegPayload::simple(Side::Debit, VId(1), Amount::new(USD, i128::MAX)),
            LegPayload::simple(Side::Debit, VId(2), Amount::new(USD, 1)),
        ];
        assert_eq!(
            EntryPayload::fold_unit_totals(&legs).unwrap_err(),
            EntryError::Overflow
        );
    }

    /// fa-bvx: a control record has `legs = []` and a `ControlPayload`, and
    /// every control variant round-trips.
    #[test]
    fn control_records_round_trip() {
        let variants = vec![
            ControlPayload::PeriodTransition {
                period_ref: PeriodRef {
                    calendar: "cal".into(),
                    code: "FY2026-P03".into(),
                },
                from: 1,
                to: 2,
                reason_code: 7,
                case_ref: Some(VId(3)),
            },
            ControlPayload::SchemaChange {
                kind: 2,
                canonical_bytes: vec![1, 2, 3],
            },
            ControlPayload::PolicyActivation {
                policy_oid: Oid([1; 32]),
                effective_from: DateDay(1),
                effective_to: DateDay(400),
            },
            ControlPayload::LifecycleTransition {
                object_ref: VId(4),
                from: 0,
                to: 1,
                proof_refs: vec![TypedRef::Vertex(VId(5)), TypedRef::Object(Oid([6; 32]))],
                reason_code: 1,
            },
            ControlPayload::TimeTick {
                observed_utc_ns: 1_700_000_000_000_000_000,
                source: 0,
                monotonic_ok: true,
            },
            ControlPayload::SweepCursor {
                sweep_kind: 1,
                last_pending_vid: VId(8),
                tick_ref: VId(9),
            },
            ControlPayload::ScheduleCancelled {
                schedule_ref: VId(10),
                cause_ref: VId(11),
            },
            ControlPayload::CapabilityEvent {
                commitment: [12; 32],
                kind: 1,
                caveats_digest: [13; 32],
            },
            ControlPayload::HoldEvent {
                scope_digest: [14; 32],
                authority_oid: Oid([15; 32]),
                kind: 0,
            },
            ControlPayload::ErasureCut {
                subject_ref: VId(16),
                field_digests: vec![[1; 32], [2; 32]],
            },
            ControlPayload::MigrationControl {
                run_ref: VId(17),
                kind: 2,
                tie_out_digest: [18; 32],
            },
        ];
        for control in variants {
            let mut p = proposal(vec![]);
            p.class = EntryClass::PERIOD_CONTROL;
            p.control = Some(control.clone());
            p.unit_totals = vec![];
            let e = p.seal(vec![], None).unwrap();
            let back = Entry::decode(&e.encode().unwrap()).unwrap();
            assert_eq!(back.proposal.control, Some(control));
            assert!(back.proposal.legs.is_empty());
        }
        // A control class without a payload is refused.
        let mut p = proposal(vec![]);
        p.class = EntryClass::POLICY_CONTROL;
        p.unit_totals = vec![];
        assert!(matches!(
            p.validate().unwrap_err(),
            EntryError::Invalid {
                what: "control",
                ..
            }
        ));
    }

    #[test]
    fn origins_pending_and_supersession_round_trip() {
        let mut p = proposal(two_legs());
        p.class = EntryClass::RESOLUTION;
        p.origin = EntryOrigin::Migration {
            run_ref: VId(1),
            source_system: "QuickBooks".into(),
            source_id: Erasable::seal(&"JE-77".to_string(), None, &KEY, [1; 32], [1; 24]),
            source_recorded_at_ns: Some(42),
            source_entered_by: Some(Erasable::seal(
                &"clerk".to_string(),
                Some(VId(2)),
                &KEY,
                [2; 32],
                [2; 24],
            )),
            source_approved_by: None,
            batch_oid: Oid([9; 32]),
        };
        p.pending = Some(Pending {
            timeout_ns: Some(5),
            resolution_of: Some(EntryRef {
                vid: VId(3),
                entry_digest: [3; 32],
            }),
            disposition: Some(Disposition::Posts {
                posted_legs: two_legs(),
            }),
        });
        p.supersession = vec![Supersession {
            target: EntryRef {
                vid: VId(4),
                entry_digest: [4; 32],
            },
            kind: SupersessionKind::Resolves,
            reason_code: 2,
        }];
        p.base_totals = Some(BaseTotals {
            unit_id: 1,
            debits: 120_000,
            credits: 120_000,
            fx_law_oid: Oid([5; 32]),
            rate_doc_oids: vec![Oid([1; 32]), Oid([2; 32])],
            residual: Some(Residual {
                leg_ordinal: 1,
                amount: Amount::new(USD, 1),
            }),
        });
        p.external_ids = vec![ExternalId {
            system: "bank".into(),
            id: Erasable::seal(&"TXN-9".to_string(), None, &KEY, [8; 32], [8; 24]),
        }];
        p.effective_period = Some(PeriodRef {
            calendar: "cal".into(),
            code: "FY2026-A1".into(),
        });
        let e = p.seal(vec![], None).unwrap();
        let back = Entry::decode(&e.encode().unwrap()).unwrap();
        assert_eq!(back, e);
        for v in [
            EntryOrigin::Rule {
                rule_version_oid: Oid([1; 32]),
                event_ref: VId(2),
                inputs_digest: [3; 32],
            },
            EntryOrigin::Control {
                control_kind: 4,
                spec_body_digest: [5; 32],
            },
            EntryOrigin::Sweep {
                sweep_kind: 1,
                tick_evidence_oid: Oid([6; 32]),
            },
        ] {
            let mut p = proposal(two_legs());
            p.origin = v.clone();
            let e = p.seal(vec![], None).unwrap();
            assert_eq!(
                Entry::decode(&e.encode().unwrap()).unwrap().proposal.origin,
                v
            );
        }
    }

    /// Golden vector: the digests of a fixed proposal are pinned so a codec
    /// change that moves bytes fails here before it reaches a book.
    #[test]
    fn digest_golden_vector() {
        let e = proposal(two_legs()).seal(vec![], None).unwrap();
        let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(e.proposal_digest), "GOLDEN_PROPOSAL");
        assert_eq!(hex(e.entry_digest), "GOLDEN_ENTRY");
    }
}
