//! Cash-flow solvency with authenticated obligation and commitment maturity
//! schedules (plan §11.6, `FA-EVID-L53`, bead `fa-5dpd`).
//!
//! Version 2 of `solvency.cash_flow_test` folded posted liability entries by
//! their booking `effective_date`, treating every liability booked on or before
//! `as_of + horizon_days` as maturing inside the horizon and computing
//! `horizon_end` with `horizon_days as i32` + `saturating_add`.
//!
//! This module provides:
//! 1. Checked civil-day horizon arithmetic (`checked_horizon_end`) with no
//!    narrowing cast or saturation (`horizon_days == 0`, `u32::MAX`, and civil
//!    date extrema overflowing `i32::MAX` are refused with typed parameter
//!    errors).
//! 2. A versioned, canonically encoded `AuthenticatedObligationSchedule`
//!    (`fa:solvency-obligation-schedule:v1`) and per-entry inline maturity
//!    extension (`fa:obligation-maturity:v1`) carrying contractual installment
//!    maturity dates, exact outstanding amounts, settlement targets, off-ledger
//!    commitments, expected inflows, and document `EvidenceRef`s.
//! 3. Schedule completeness verification against the snapshot's open liability
//!    legs at `as_of`: every open liability leg in scope must be accounted for
//!    exactly once, live settlements (`leg.settles`) are applied once in
//!    deterministic order without double-counting, `PENDING` entries do not
//!    relieve obligations, and obligations maturing strictly after
//!    `horizon_end` remain in `deferred_obligations` rather than
//!    `maturing_obligations`.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::genesis::{BookContext, UnitPolicy};
use fa_model::{AccountType, EncodeError, EntryClass, EvidenceRef, Id128, Oid, Writer};
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::amount::{
    amount_difference, amount_magnitude, amount_negated, amount_scaled_bps, amount_sum, signed_leg,
};
use crate::jet::finding;
use crate::{Cite, Finding, LanternError, MAX_CITES, Meter, Severity, Snapshot, Statistic};

/// Domain tag for canonical `AuthenticatedObligationSchedule` bytes.
pub const OBLIGATION_SCHEDULE_DOMAIN: &[u8] = b"fa:solvency-obligation-schedule:v1";

/// Domain tag for per-unit cash-flow solvency certificate closure digests.
pub const SOLVENCY_CLOSURE_DOMAIN: &[u8] = b"fa:solvency-cash-flow-closure:v1";

/// Entry extension 33, `fa:obligation-maturity:v1`: the per-entry inline
/// obligation maturity terms, registered and validated by fa-model.
pub const OBLIGATION_MATURITY_EXT_TAG: u16 = fa_model::entry::OBLIGATION_MATURITY_EXTENSION;

/// Domain tag for canonical `AuthenticatedValuationSchedule` bytes (`fa-8j3g`).
pub const VALUATION_SCHEDULE_DOMAIN: &[u8] = b"fa:solvency-valuation-schedule:v1";

/// Domain tag for per-unit balance-sheet solvency certificate closure digests (`fa-8j3g`).
pub const BALANCE_SHEET_CLOSURE_DOMAIN: &[u8] = b"fa:solvency-balance-sheet-closure:v1";

/// Entry extension 34, `fa:valuation-adjustment:v1`: per-entry inline
/// valuation adjustments, registered and validated by fa-model (`fa-8j3g`).
pub const VALUATION_ADJUSTMENT_EXT_TAG: u16 = fa_model::entry::VALUATION_ADJUSTMENT_EXTENSION;

/// Current schema version of `AuthenticatedObligationSchedule` and `AuthenticatedValuationSchedule`.
pub const SCHEDULE_SCHEMA_VERSION: u16 = 1;

/// Compute `as_of + horizon_days` using checked civil-day arithmetic with no
/// narrowing cast or saturation (`fa-5dpd`).
pub fn checked_horizon_end(
    procedure: &str,
    as_of: DateDay,
    horizon_days: u32,
) -> Result<DateDay, LanternError> {
    if horizon_days == 0 {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "horizon_days".into(),
            message: "must be >= 1".into(),
        });
    }
    let delta = i32::try_from(horizon_days).map_err(|_| LanternError::Parameter {
        procedure: procedure.into(),
        name: "horizon_days".into(),
        message: format!("horizon_days {horizon_days} exceeds civil-day i32::MAX bound"),
    })?;
    let end_days = as_of
        .0
        .checked_add(delta)
        .ok_or_else(|| LanternError::Parameter {
            procedure: procedure.into(),
            name: "horizon_days".into(),
            message: format!(
                "as_of day {} + horizon_days {horizon_days} overflows civil-day range",
                as_of.0
            ),
        })?;
    Ok(DateDay(end_days))
}

/// The inline terms' types and codec live in fa-model, where the kernel
/// validates them against the legs before an entry carrying them posts.
pub use fa_model::obligation::{InlineObligationTerms, ObligationInstallment, ObligationStatus};

/// One authenticated obligation row in an [`AuthenticatedObligationSchedule`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledObligation {
    pub entry: VId,
    pub ordinal: u16,
    pub account: VId,
    pub unit: UnitId,
    pub entity: Option<VId>,
    pub status: ObligationStatus,
    /// Contractual installments before or after `as_of`. Live settlements are
    /// applied once in chronological installment order (`due_date` ascending)
    /// when `installments` represent the original schedule, or `installments`
    /// may already equal the exact remaining open amount at `as_of`.
    pub installments: Vec<ObligationInstallment>,
    pub evidence_refs: Vec<EvidenceRef>,
}

/// A declared commitment (off-ledger or linked to an existing liability leg).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredCommitment {
    pub commitment_id: String,
    pub due_date: DateDay,
    pub amount: Amount,
    pub entity: Option<VId>,
    /// When `Some((entry, ordinal))`, this commitment represents the scheduled
    /// payment of an already-booked liability leg and is never counted a second
    /// time on top of that liability leg.
    pub settles_entry: Option<(VId, u16)>,
    pub evidence_refs: Vec<EvidenceRef>,
}

/// A declared expected cash inflow within the horizon, tracked separately from
/// `liquid_cash` at `as_of`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedInflow {
    pub inflow_id: String,
    pub due_date: DateDay,
    pub amount: Amount,
    pub entity: Option<VId>,
    pub evidence_refs: Vec<EvidenceRef>,
}

/// Versioned, authenticated obligation and commitment schedule bound to a
/// snapshot coordinate (`book_id`, `known_at`, `as_of`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedObligationSchedule {
    pub schema_version: u16,
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub as_of: DateDay,
    pub unit_filter: Option<UnitId>,
    pub entity_filter: Option<VId>,
    pub obligations: Vec<ScheduledObligation>,
    pub commitments: Vec<DeclaredCommitment>,
    pub expected_inflows: Vec<ExpectedInflow>,
}

impl AuthenticatedObligationSchedule {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u16(self.schema_version)
            .fixed(&self.book_id.0)
            .u64(self.known_at.0)
            .i32(self.as_of.0)
            .opt(self.unit_filter.as_ref(), |w, u| {
                w.u32(u.0);
            })
            .opt(self.entity_filter.as_ref(), |w, e| {
                w.u128(e.0);
            })
            .list(&self.obligations, |w, ob| {
                w.u128(ob.entry.0)
                    .u16(ob.ordinal)
                    .u128(ob.account.0)
                    .u32(ob.unit.0)
                    .opt(ob.entity.as_ref(), |w, e| {
                        w.u128(e.0);
                    })
                    .u8(ob.status.tag());
                if let ObligationStatus::Disputed { reason_code } = ob.status {
                    w.u16(reason_code);
                }
                w.list(&ob.installments, |w, inst| {
                    w.i32(inst.due_date.0).i128(inst.amount);
                })
                .list(&ob.evidence_refs, |w, ev| {
                    w.fixed(&ev.document_oid.0)
                        .fixed(&ev.doc_commit)
                        .u8(ev.role);
                });
            })
            .list(&self.commitments, |w, c| {
                w.str(&c.commitment_id)
                    .i32(c.due_date.0)
                    .u32(c.amount.unit.0)
                    .i128(c.amount.mantissa)
                    .opt(c.entity.as_ref(), |w, e| {
                        w.u128(e.0);
                    })
                    .opt(c.settles_entry.as_ref(), |w, (entry, ord)| {
                        w.u128(entry.0).u16(*ord);
                    })
                    .list(&c.evidence_refs, |w, ev| {
                        w.fixed(&ev.document_oid.0)
                            .fixed(&ev.doc_commit)
                            .u8(ev.role);
                    });
            })
            .list(&self.expected_inflows, |w, inf| {
                w.str(&inf.inflow_id)
                    .i32(inf.due_date.0)
                    .u32(inf.amount.unit.0)
                    .i128(inf.amount.mantissa)
                    .opt(inf.entity.as_ref(), |w, e| {
                        w.u128(e.0);
                    })
                    .list(&inf.evidence_refs, |w, ev| {
                        w.fixed(&ev.document_oid.0)
                            .fixed(&ev.doc_commit)
                            .u8(ev.role);
                    });
            });
        w.finish()
    }

    pub fn schedule_digest(&self) -> Result<[u8; 32], EncodeError> {
        let bytes = self.encode()?;
        let mut h = Hasher::new();
        h.update(OBLIGATION_SCHEDULE_DOMAIN);
        h.update(&bytes);
        Ok(h.finalize().0)
    }
}

/// Per-(unit, optional entity) cash-flow solvency evaluation result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitCashFlowSolvency {
    pub unit_id: u32,
    pub entity: Option<VId>,
    pub as_of: DateDay,
    pub horizon_days: u32,
    pub horizon_end: DateDay,
    pub liquid_cash: i128,
    pub expected_inflows: i128,
    pub maturing_obligations: i128,
    pub maturing_commitments: i128,
    pub deferred_obligations: i128,
    pub disputed_obligations: i128,
    pub shortfall: i128,
    pub surplus: i128,
    pub selected_obligations: Vec<(VId, u16, DateDay, i128)>,
    pub closure_documents: Vec<Oid>,
    pub certificate_digest: [u8; 32],
}

impl UnitCashFlowSolvency {
    #[must_use]
    pub fn log_line(&self) -> String {
        let mut hex = String::with_capacity(64);
        for b in &self.certificate_digest {
            use core::fmt::Write as _;
            let _ = write!(&mut hex, "{b:02x}");
        }
        format!(
            "solvency_cash_flow unit={} entity={:?} as_of={} horizon_days={} horizon_end={} liquid_cash={} expected_inflows={} maturing_obligations={} maturing_commitments={} deferred_obligations={} disputed_obligations={} shortfall={} certificate_digest={hex}",
            self.unit_id,
            self.entity.map(|v| v.0),
            self.as_of,
            self.horizon_days,
            self.horizon_end,
            self.liquid_cash,
            self.expected_inflows,
            self.maturing_obligations,
            self.maturing_commitments,
            self.deferred_obligations,
            self.disputed_obligations,
            self.shortfall,
        )
    }
}

/// Complete result of evaluating cash-flow solvency over a snapshot and
/// authenticated maturity schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowSolvencyReport {
    pub as_of: DateDay,
    pub horizon_days: u32,
    pub horizon_end: DateDay,
    pub schedule_digest: [u8; 32],
    pub units: BTreeMap<(u32, Option<VId>), UnitCashFlowSolvency>,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug)]
struct OpenLiabilityLeg {
    account: VId,
    unit: UnitId,
    entity: Option<VId>,
    original: i128,
    settled: i128,
    open: i128,
}

fn validate_evidence_refs(
    procedure: &str,
    snapshot: &Snapshot,
    what: &str,
    refs: &[EvidenceRef],
) -> Result<Vec<Oid>, LanternError> {
    if refs.is_empty() {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "evidence_refs".into(),
            message: format!("{what} requires at least one authenticating EvidenceRef"),
        });
    }
    let mut oids = Vec::with_capacity(refs.len());
    for ev in refs {
        if !snapshot.documents.is_empty() && !snapshot.documents.contains_key(&ev.document_oid) {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "evidence_refs".into(),
                message: format!(
                    "{what} cites document {:02x?} not present in snapshot at known_at {}",
                    &ev.document_oid.0[..4],
                    snapshot.coordinate.known_at.0
                ),
            });
        }
        oids.push(ev.document_oid);
    }
    Ok(oids)
}

/// Extract an `AuthenticatedObligationSchedule` from inline
/// `fa:obligation-maturity:v1` entry extensions when present on the snapshot.
pub fn schedule_from_inline_extensions(
    procedure: &str,
    snapshot: &Snapshot,
    as_of: DateDay,
) -> Result<Option<AuthenticatedObligationSchedule>, LanternError> {
    let mut any_inline = false;
    let mut obligations = Vec::new();
    let live = snapshot.live_postings_through(Some(as_of))?;
    let scope = crate::projection::entity_scope(live.iter().flat_map(|e| &e.entry.proposal.legs))?;

    for e in &live {
        for (tag, bytes) in &e.entry.proposal.extensions {
            if *tag != OBLIGATION_MATURITY_EXT_TAG {
                continue;
            }
            let decoded = InlineObligationTerms::decode_list(bytes)?;
            for item in decoded {
                let idx = usize::from(item.ordinal);
                let Some(leg) = e.entry.proposal.legs.get(idx) else {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "obligation_schedule".into(),
                        message: format!(
                            "inline maturity on entry {:032x} names missing leg ordinal {}",
                            e.vid.0, item.ordinal
                        ),
                    });
                };
                // Debit maturity v2 describes a counterparty's obligation to
                // this book. It is neither our liability nor an authenticated
                // forecast inflow for this solvency procedure.
                if leg.side != Side::Credit {
                    continue;
                }
                any_inline = true;
                let entity = crate::projection::scoped_entity(&scope, leg)?;
                let mut evidence_refs = e.entry.proposal.evidence.clone();
                if evidence_refs.is_empty() {
                    evidence_refs.push(EvidenceRef {
                        document_oid: Oid(e.entry.entry_digest),
                        doc_commit: e.entry.entry_digest,
                        role: 1,
                    });
                }
                obligations.push(ScheduledObligation {
                    entry: e.vid,
                    ordinal: item.ordinal,
                    account: leg.account_ref,
                    unit: leg.amount.unit,
                    entity,
                    status: item.status,
                    installments: item.installments,
                    evidence_refs,
                });
            }
        }
    }

    if !any_inline {
        return Ok(None);
    }

    Ok(Some(AuthenticatedObligationSchedule {
        schema_version: SCHEDULE_SCHEMA_VERSION,
        book_id: snapshot.coordinate.book_id,
        known_at: snapshot.coordinate.known_at,
        as_of,
        unit_filter: None,
        entity_filter: None,
        obligations,
        commitments: Vec::new(),
        expected_inflows: Vec::new(),
    }))
}

/// Evaluate cash-flow solvency against an authenticated obligation/commitment
/// maturity schedule (`fa-5dpd`).
pub fn evaluate_cash_flow_solvency(
    procedure: &str,
    snapshot: &Snapshot,
    book: &BookContext,
    horizon_days: u32,
    schedule: &AuthenticatedObligationSchedule,
    work: &mut Meter<'_>,
) -> Result<CashFlowSolvencyReport, LanternError> {
    if schedule.schema_version != SCHEDULE_SCHEMA_VERSION {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "schema_version".into(),
            message: format!(
                "unsupported obligation schedule schema_version {} (expected {})",
                schedule.schema_version, SCHEDULE_SCHEMA_VERSION
            ),
        });
    }
    let mut all_live = snapshot.live_postings()?;
    all_live.sort_by_key(|e| e.vid);
    let as_of = snapshot.coordinate.effective_through.unwrap_or_else(|| {
        all_live
            .iter()
            .map(|e| e.entry.proposal.effective_date)
            .max()
            .unwrap_or(DateDay(0))
    });
    if schedule.book_id != snapshot.coordinate.book_id {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "book_id".into(),
            message: "obligation schedule book_id does not match snapshot book_id".into(),
        });
    }
    if schedule.known_at != snapshot.coordinate.known_at {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "known_at".into(),
            message: format!(
                "obligation schedule known_at {} does not match snapshot known_at {}",
                schedule.known_at.0, snapshot.coordinate.known_at.0
            ),
        });
    }
    if schedule.as_of != as_of {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "as_of".into(),
            message: format!(
                "obligation schedule as_of {} does not match snapshot effective date {}",
                schedule.as_of, as_of
            ),
        });
    }

    let horizon_end = checked_horizon_end(procedure, as_of, horizon_days)?;
    let cash_accounts = snapshot.role_population(procedure)?;
    let scope =
        crate::projection::entity_scope(all_live.iter().flat_map(|e| &e.entry.proposal.legs))?;

    // 1. Fold liquid cash at `as_of` and collect booked liability credit legs
    // at `as_of`, plus live settlement applications (`leg.settles`) from
    // non-PENDING entries effective through `horizon_end`.
    let mut cash_by_scope: BTreeMap<(u32, Option<VId>), i128> = BTreeMap::new();
    let mut scope_accounts: BTreeMap<(u32, Option<VId>), BTreeSet<VId>> = BTreeMap::new();
    let mut scope_entries: BTreeMap<(u32, Option<VId>), BTreeSet<VId>> = BTreeMap::new();
    let mut liability_legs: BTreeMap<(VId, u16), OpenLiabilityLeg> = BTreeMap::new();
    let mut seen_settlement_edges: BTreeSet<(VId, usize, VId, u16)> = BTreeSet::new();
    let mut pending_settlements: Vec<(VId, u16, UnitId, i128)> = Vec::new();
    let mut population = 0u64;

    for e in &all_live {
        work.entry()?;
        // SnapshotEntry::posts() already excludes EntryClass::PENDING, but guard
        // explicitly so a pending reservation never relieves an obligation.
        if e.entry.proposal.class == EntryClass::PENDING {
            continue;
        }
        let eff = e.entry.proposal.effective_date;
        for (idx, leg) in e.entry.proposal.legs.iter().enumerate() {
            work.leg()?;
            let ordinal = u16::try_from(idx).map_err(|_| LanternError::Parameter {
                procedure: procedure.into(),
                name: "ordinal".into(),
                message: "leg index exceeds u16::MAX".into(),
            })?;
            let entity = crate::projection::scoped_entity(&scope, leg)?;
            if let Some(filter_u) = schedule.unit_filter
                && leg.amount.unit != filter_u
            {
                continue;
            }
            if let Some(filter_e) = schedule.entity_filter
                && entity != Some(filter_e)
            {
                continue;
            }
            let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                continue;
            };
            let at = AccountType(acct.account_type);
            let signed = signed_leg(leg.side, leg.amount.mantissa)?;
            let key = (leg.amount.unit.0, entity);

            if eff <= as_of && cash_accounts.contains(&leg.account_ref) {
                population = population.saturating_add(1);
                let cell = cash_by_scope.entry(key).or_default();
                *cell = cell
                    .checked_add(signed)
                    .ok_or(LanternError::Overflow("cash_flow_test cash fold"))?;
                scope_accounts
                    .entry(key)
                    .or_default()
                    .insert(leg.account_ref);
                scope_entries.entry(key).or_default().insert(e.vid);
            } else if at == AccountType::LIABILITY {
                if eff <= as_of && leg.side == Side::Credit {
                    population = population.saturating_add(1);
                    let mag = amount_magnitude(leg.amount.mantissa, "liability credit")?;
                    if mag > 0 {
                        liability_legs.insert(
                            (e.vid, ordinal),
                            OpenLiabilityLeg {
                                account: leg.account_ref,
                                unit: leg.amount.unit,
                                entity,
                                original: mag,
                                settled: 0,
                                open: mag,
                            },
                        );
                        scope_accounts
                            .entry(key)
                            .or_default()
                            .insert(leg.account_ref);
                        scope_entries.entry(key).or_default().insert(e.vid);
                    }
                } else if eff <= horizon_end && leg.side == Side::Debit {
                    // Collect explicit settlement links (`leg.settles`) so each
                    // payment is applied once to its target obligation.
                    for s in &leg.settles {
                        let edge_key = (e.vid, idx, s.target.vid, s.ordinal);
                        if !seen_settlement_edges.insert(edge_key) {
                            return Err(LanternError::Parameter {
                                procedure: procedure.into(),
                                name: "settlements".into(),
                                message: format!(
                                    "duplicate settlement link in entry {:032x} targeting ({:032x}, {})",
                                    e.vid.0, s.target.vid.0, s.ordinal
                                ),
                            });
                        }
                        let take = amount_magnitude(s.amount.mantissa, "settlement amount")?;
                        pending_settlements.push((s.target.vid, s.ordinal, s.amount.unit, take));
                        scope_entries.entry(key).or_default().insert(e.vid);
                    }
                }
            }
        }
    }

    // Apply each live settlement exactly once against its target liability leg.
    for (target_vid, target_ord, settle_unit, take) in pending_settlements {
        work.compare(1)?;
        let Some(target) = liability_legs.get_mut(&(target_vid, target_ord)) else {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "settlements".into(),
                message: format!(
                    "settlement targets unknown or out-of-scope liability leg ({:032x}, {target_ord})",
                    target_vid.0
                ),
            });
        };
        if target.unit != settle_unit {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "settlements".into(),
                message: format!(
                    "settlement unit {} does not match liability leg ({:032x}, {target_ord}) unit {}",
                    settle_unit.0, target_vid.0, target.unit.0
                ),
            });
        }
        let new_settled = amount_sum(target.settled, take, "liability settled sum")?;
        if new_settled > target.original {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "settlements".into(),
                message: format!(
                    "settlements {new_settled} exceed original liability {} on ({:032x}, {target_ord})",
                    target.original, target_vid.0
                ),
            });
        }
        target.settled = new_settled;
        target.open = amount_difference(target.original, new_settled, "liability open amount")?;
    }

    // 2. Validate `schedule.obligations` completeness and uniqueness against
    // open liability legs at `as_of`.
    let mut scheduled_by_leg: BTreeMap<(VId, u16), &ScheduledObligation> = BTreeMap::new();
    for ob in &schedule.obligations {
        work.compare(1)?;
        if let Some(filter_u) = schedule.unit_filter
            && ob.unit != filter_u
        {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "obligations".into(),
                message: format!(
                    "scheduled obligation ({:032x}, {}) has unit {} outside unit_filter {}",
                    ob.entry.0, ob.ordinal, ob.unit.0, filter_u.0
                ),
            });
        }
        if let Some(filter_e) = schedule.entity_filter
            && ob.entity != Some(filter_e)
        {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "obligations".into(),
                message: format!(
                    "scheduled obligation ({:032x}, {}) entity {:?} is outside entity_filter {:?}",
                    ob.entry.0, ob.ordinal, ob.entity, filter_e
                ),
            });
        }
        if scheduled_by_leg
            .insert((ob.entry, ob.ordinal), ob)
            .is_some()
        {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "obligations".into(),
                message: format!(
                    "duplicate scheduled obligation for leg ({:032x}, {})",
                    ob.entry.0, ob.ordinal
                ),
            });
        }
    }

    // Every open liability leg (`open > 0`) must appear in `scheduled_by_leg`.
    for (&leg_key, open_leg) in &liability_legs {
        if open_leg.open > 0 && !scheduled_by_leg.contains_key(&leg_key) {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "obligations".into(),
                message: format!(
                    "incomplete obligation schedule: open liability leg ({:032x}, {}) with remaining amount {} is omitted",
                    leg_key.0.0, leg_key.1, open_leg.open
                ),
            });
        }
    }

    #[derive(Default)]
    struct ScopeAccum {
        maturing_obligations: i128,
        deferred_obligations: i128,
        disputed_obligations: i128,
        maturing_commitments: i128,
        expected_inflows: i128,
        selected_obligations: Vec<(VId, u16, DateDay, i128)>,
        docs: BTreeSet<Oid>,
    }

    let mut accum_by_scope: BTreeMap<(u32, Option<VId>), ScopeAccum> = BTreeMap::new();

    for (&(entry_vid, ordinal), ob) in &scheduled_by_leg {
        work.compare(1)?;
        let Some(open_leg) = liability_legs.get(&(entry_vid, ordinal)) else {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "obligations".into(),
                message: format!(
                    "scheduled obligation ({:032x}, {ordinal}) does not match any liability leg at as_of",
                    entry_vid.0
                ),
            });
        };
        if ob.account != open_leg.account
            || ob.unit != open_leg.unit
            || ob.entity != open_leg.entity
        {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "obligations".into(),
                message: format!(
                    "scheduled obligation ({:032x}, {ordinal}) metadata (account/unit/entity) mismatches booked leg",
                    entry_vid.0
                ),
            });
        }
        let doc_oids = validate_evidence_refs(
            procedure,
            snapshot,
            "scheduled obligation",
            &ob.evidence_refs,
        )?;
        let key = (ob.unit.0, ob.entity);
        let acc = accum_by_scope.entry(key).or_default();
        acc.docs.extend(doc_oids);

        if open_leg.open == 0 {
            continue;
        }

        match ob.status {
            ObligationStatus::MissingMaturity => {
                return Err(LanternError::Parameter {
                    procedure: procedure.into(),
                    name: "obligations".into(),
                    message: format!(
                        "obligation ({:032x}, {ordinal}) has MissingMaturity; cash-flow solvency refuses to assume missing maturity is immediately due",
                        entry_vid.0
                    ),
                });
            }
            ObligationStatus::Disputed { .. } => {
                acc.disputed_obligations = amount_sum(
                    acc.disputed_obligations,
                    open_leg.open,
                    "disputed obligations sum",
                )?;
            }
            ObligationStatus::Contractual => {
                if ob.installments.is_empty() {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "installments".into(),
                        message: format!(
                            "contractual obligation ({:032x}, {ordinal}) has empty installments",
                            entry_vid.0
                        ),
                    });
                }
                let mut sorted_inst = ob.installments.clone();
                sorted_inst.sort_by_key(|i| i.due_date);
                let mut inst_total = 0i128;
                for inst in &sorted_inst {
                    if inst.amount <= 0 {
                        return Err(LanternError::Parameter {
                            procedure: procedure.into(),
                            name: "installments".into(),
                            message: "installment amount must be > 0".into(),
                        });
                    }
                    inst_total = amount_sum(inst_total, inst.amount, "installment sum")?;
                }

                // Installments may state either the original schedule (`inst_total == open_leg.original`,
                // from which `open_leg.settled` is relieved once in chronological order) or the exact
                // remaining schedule at `as_of` (`inst_total == open_leg.open`). Any other sum is refused.
                let mut to_relieve = if inst_total == open_leg.open {
                    0i128
                } else if inst_total == open_leg.original {
                    open_leg.settled
                } else {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "installments".into(),
                        message: format!(
                            "obligation ({:032x}, {ordinal}) installments sum to {inst_total}, matching neither open {} nor original {}",
                            entry_vid.0, open_leg.open, open_leg.original
                        ),
                    });
                };

                for inst in sorted_inst {
                    let relieved = to_relieve.min(inst.amount);
                    to_relieve = amount_difference(to_relieve, relieved, "installment relief")?;
                    let remaining =
                        amount_difference(inst.amount, relieved, "installment remaining")?;
                    if remaining == 0 {
                        continue;
                    }
                    if inst.due_date <= horizon_end {
                        acc.maturing_obligations = amount_sum(
                            acc.maturing_obligations,
                            remaining,
                            "maturing obligations sum",
                        )?;
                        acc.selected_obligations.push((
                            entry_vid,
                            ordinal,
                            inst.due_date,
                            remaining,
                        ));
                    } else {
                        acc.deferred_obligations = amount_sum(
                            acc.deferred_obligations,
                            remaining,
                            "deferred obligations sum",
                        )?;
                    }
                }
            }
        }
    }

    // 3. Process declared commitments (each counted once; commitments linked via
    // `settles_entry` to an already-scheduled liability leg do not double-count).
    let mut seen_commitments: BTreeSet<&str> = BTreeSet::new();
    let mut seen_settled_legs: BTreeSet<(VId, u16)> = BTreeSet::new();
    for c in &schedule.commitments {
        work.compare(1)?;
        if c.commitment_id.trim().is_empty() || !seen_commitments.insert(c.commitment_id.as_str()) {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "commitments".into(),
                message: format!("empty or duplicate commitment_id `{}`", c.commitment_id),
            });
        }
        if c.amount.mantissa <= 0 {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "commitments".into(),
                message: format!("commitment `{}` amount must be > 0", c.commitment_id),
            });
        }
        if let Some(filter_u) = schedule.unit_filter
            && c.amount.unit != filter_u
        {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "commitments".into(),
                message: format!(
                    "commitment `{}` unit {} is outside unit_filter {}",
                    c.commitment_id, c.amount.unit.0, filter_u.0
                ),
            });
        }
        if let Some(filter_e) = schedule.entity_filter
            && c.entity != Some(filter_e)
        {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "commitments".into(),
                message: format!(
                    "commitment `{}` entity {:?} is outside entity_filter {:?}",
                    c.commitment_id, c.entity, filter_e
                ),
            });
        }
        let doc_oids =
            validate_evidence_refs(procedure, snapshot, "declared commitment", &c.evidence_refs)?;
        let key = (c.amount.unit.0, c.entity);
        let acc = accum_by_scope.entry(key).or_default();
        acc.docs.extend(doc_oids);

        if let Some(target_leg) = c.settles_entry {
            if !seen_settled_legs.insert(target_leg) {
                return Err(LanternError::Parameter {
                    procedure: procedure.into(),
                    name: "commitments".into(),
                    message: format!(
                        "multiple commitments target the same liability leg ({:032x}, {})",
                        target_leg.0.0, target_leg.1
                    ),
                });
            }
            if scheduled_by_leg.contains_key(&target_leg) {
                // Already counted via the scheduled liability leg's remaining
                // installments; do not double-count.
                continue;
            }
        }
        if c.due_date <= horizon_end {
            acc.maturing_commitments = amount_sum(
                acc.maturing_commitments,
                c.amount.mantissa,
                "maturing commitments sum",
            )?;
        }
    }

    // 4. Process expected inflows (tracked separately from `liquid_cash`).
    let mut seen_inflows: BTreeSet<&str> = BTreeSet::new();
    for inf in &schedule.expected_inflows {
        work.compare(1)?;
        if inf.inflow_id.trim().is_empty() || !seen_inflows.insert(inf.inflow_id.as_str()) {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "expected_inflows".into(),
                message: format!("empty or duplicate inflow_id `{}`", inf.inflow_id),
            });
        }
        if inf.amount.mantissa <= 0 {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "expected_inflows".into(),
                message: format!("expected inflow `{}` amount must be > 0", inf.inflow_id),
            });
        }
        let doc_oids =
            validate_evidence_refs(procedure, snapshot, "expected inflow", &inf.evidence_refs)?;
        let key = (inf.amount.unit.0, inf.entity);
        let acc = accum_by_scope.entry(key).or_default();
        acc.docs.extend(doc_oids);
        if inf.due_date >= as_of && inf.due_date <= horizon_end {
            acc.expected_inflows = amount_sum(
                acc.expected_inflows,
                inf.amount.mantissa,
                "expected inflows sum",
            )?;
        }
    }

    let schedule_digest = schedule.schedule_digest()?;
    let mut all_scopes: BTreeSet<(u32, Option<VId>)> = BTreeSet::new();
    all_scopes.extend(cash_by_scope.keys().copied());
    all_scopes.extend(accum_by_scope.keys().copied());

    let mut units = BTreeMap::new();
    let mut findings = Vec::new();

    for key @ (unit_id, entity) in all_scopes {
        work.compare(1)?;
        let raw_cash = cash_by_scope.get(&key).copied().unwrap_or(0);
        let liquid_cash = raw_cash.max(0);
        let acc = accum_by_scope.remove(&key).unwrap_or_default();
        let total_due = amount_sum(
            acc.maturing_obligations,
            acc.maturing_commitments,
            "total maturing obligations and commitments",
        )?;
        let total_liquidity = amount_sum(
            liquid_cash,
            acc.expected_inflows,
            "total liquidity and inflows",
        )?;
        let (shortfall, surplus) = if total_due > total_liquidity {
            (
                amount_difference(total_due, total_liquidity, "cash_flow shortfall")?,
                0,
            )
        } else {
            (
                0,
                amount_difference(total_liquidity, total_due, "cash_flow surplus")?,
            )
        };

        let closure_documents: Vec<Oid> = acc.docs.into_iter().collect();
        let certificate_digest = {
            let mut w = Writer::new();
            w.fixed(&schedule_digest)
                .fixed(&snapshot.inputs_digest)
                .u32(unit_id)
                .opt(entity.as_ref(), |w, e| {
                    w.u128(e.0);
                })
                .i32(as_of.0)
                .u32(horizon_days)
                .i32(horizon_end.0)
                .i128(liquid_cash)
                .i128(acc.expected_inflows)
                .i128(acc.maturing_obligations)
                .i128(acc.maturing_commitments)
                .i128(acc.deferred_obligations)
                .i128(acc.disputed_obligations)
                .i128(shortfall)
                .i128(surplus);
            let bytes = w.finish()?;
            let mut h = Hasher::new();
            h.update(SOLVENCY_CLOSURE_DOMAIN);
            h.update(&bytes);
            h.finalize().0
        };

        if shortfall > 0 {
            let mut cites: Vec<Cite> = scope_accounts
                .remove(&key)
                .unwrap_or_default()
                .into_iter()
                .map(Cite::Account)
                .collect();
            if let Some(entries) = scope_entries.remove(&key) {
                for evid in entries {
                    if cites.len() < MAX_CITES {
                        cites.push(Cite::Entry(evid));
                    }
                }
            }
            for doc_oid in &closure_documents {
                if cites.len() < MAX_CITES {
                    cites.push(Cite::Document(*doc_oid));
                }
            }
            let scale = crate::unit_scale(book, unit_id)?;
            findings.push(finding(
                procedure,
                Severity::High,
                Statistic {
                    name: "cash_flow_shortfall".into(),
                    value: shortfall,
                    scale,
                    population: population.max(1),
                },
                cites,
                format!(
                    "unit {unit_id} cash-flow insolvent over {horizon_days}-day horizon ({as_of}..={horizon_end}): liquid_cash={liquid_cash}, expected_inflows={}, maturing_obligations={}, maturing_commitments={}, deferred_obligations={}, disputed_obligations={}, shortfall={shortfall} (maturity_basis=authenticated_schedule)",
                    acc.expected_inflows,
                    acc.maturing_obligations,
                    acc.maturing_commitments,
                    acc.deferred_obligations,
                    acc.disputed_obligations,
                ),
            ));
        }

        units.insert(
            key,
            UnitCashFlowSolvency {
                unit_id,
                entity,
                as_of,
                horizon_days,
                horizon_end,
                liquid_cash,
                expected_inflows: acc.expected_inflows,
                maturing_obligations: acc.maturing_obligations,
                maturing_commitments: acc.maturing_commitments,
                deferred_obligations: acc.deferred_obligations,
                disputed_obligations: acc.disputed_obligations,
                shortfall,
                surplus,
                selected_obligations: acc.selected_obligations,
                closure_documents,
                certificate_digest,
            },
        );
    }

    Ok(CashFlowSolvencyReport {
        as_of,
        horizon_days,
        horizon_end,
        schedule_digest,
        units,
        findings,
    })
}

/// Unscheduled fallback used only when no authenticated maturity schedule or
/// inline `fa:obligation-maturity:v1` terms are supplied. Explicitly labels the
/// finding `maturity_basis=unscheduled_book_liability_screen` so missing
/// maturity is never presented as a contractual maturity-schedule conclusion.
pub(crate) fn run_unscheduled_book_screen(
    procedure: &str,
    snapshot: &Snapshot,
    book: &BookContext,
    horizon_days: u32,
    work: &mut Meter<'_>,
) -> Result<Vec<Finding>, LanternError> {
    let cash = snapshot.role_population(procedure)?;
    let mut all_live = snapshot.live_postings()?;
    all_live.sort_by_key(|e| e.vid);
    let ref_date = snapshot.coordinate.effective_through.unwrap_or_else(|| {
        all_live
            .iter()
            .map(|e| e.entry.proposal.effective_date)
            .max()
            .unwrap_or(DateDay(0))
    });
    let horizon_end = checked_horizon_end(procedure, ref_date, horizon_days)?;

    let mut cash_net: BTreeMap<(VId, u32), i128> = BTreeMap::new();
    let mut liab_net: BTreeMap<(VId, u32), i128> = BTreeMap::new();
    let mut unit_accts: BTreeMap<u32, BTreeSet<VId>> = BTreeMap::new();
    let mut unit_entries: BTreeMap<u32, BTreeSet<VId>> = BTreeMap::new();
    let mut population = 0u64;

    for e in &all_live {
        work.entry()?;
        let eff = e.entry.proposal.effective_date;
        if eff > horizon_end {
            continue;
        }
        for leg in &e.entry.proposal.legs {
            work.leg()?;
            let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                continue;
            };
            let at = AccountType(acct.account_type);
            let signed = signed_leg(leg.side, leg.amount.mantissa)?;
            if eff <= ref_date && cash.contains(&leg.account_ref) {
                population = population.saturating_add(1);
                let c = cash_net
                    .entry((leg.account_ref, leg.amount.unit.0))
                    .or_default();
                *c = c
                    .checked_add(signed)
                    .ok_or(LanternError::Overflow("cash_flow_test cash fold"))?;
                unit_accts
                    .entry(leg.amount.unit.0)
                    .or_default()
                    .insert(leg.account_ref);
                unit_entries
                    .entry(leg.amount.unit.0)
                    .or_default()
                    .insert(e.vid);
            } else if at == AccountType::LIABILITY {
                population = population.saturating_add(1);
                let l = liab_net
                    .entry((leg.account_ref, leg.amount.unit.0))
                    .or_default();
                *l = l
                    .checked_add(signed)
                    .ok_or(LanternError::Overflow("cash_flow_test liability fold"))?;
                unit_accts
                    .entry(leg.amount.unit.0)
                    .or_default()
                    .insert(leg.account_ref);
                unit_entries
                    .entry(leg.amount.unit.0)
                    .or_default()
                    .insert(e.vid);
            }
        }
    }

    let mut units: BTreeSet<u32> = BTreeSet::new();
    for &(_, u) in cash_net.keys().chain(liab_net.keys()) {
        units.insert(u);
    }

    let mut out = Vec::new();
    for unit_id in units {
        work.compare(1)?;
        let mut liquid_cash = 0i128;
        for (&(_, u), &net) in &cash_net {
            if u == unit_id && net > 0 {
                liquid_cash = liquid_cash
                    .checked_add(net)
                    .ok_or(LanternError::Overflow("cash_flow_test liquid_cash sum"))?;
            }
        }
        let mut maturing_obligations = 0i128;
        for (&(_, u), &net) in &liab_net {
            if u == unit_id && net < 0 {
                maturing_obligations = maturing_obligations
                    .checked_add(amount_negated(net, "cash_flow_test obligation")?)
                    .ok_or(LanternError::Overflow("cash_flow_test obligations sum"))?;
            }
        }
        if maturing_obligations > liquid_cash {
            let shortfall = maturing_obligations
                .checked_sub(liquid_cash)
                .ok_or(LanternError::Overflow("cash_flow_test shortfall"))?;
            let mut cites: Vec<Cite> = unit_accts
                .remove(&unit_id)
                .unwrap_or_default()
                .into_iter()
                .map(Cite::Account)
                .collect();
            if let Some(entries) = unit_entries.remove(&unit_id) {
                for evid in entries {
                    if cites.len() < MAX_CITES {
                        cites.push(Cite::Entry(evid));
                    }
                }
            }
            let scale = crate::unit_scale(book, unit_id)?;
            out.push(finding(
                procedure,
                Severity::High,
                Statistic {
                    name: "cash_flow_shortfall".into(),
                    value: shortfall,
                    scale,
                    population: population.max(1),
                },
                cites,
                format!(
                    "unit {unit_id} cash-flow insolvent over {horizon_days}-day horizon: liquid_cash={liquid_cash}, maturing_obligations={maturing_obligations}, shortfall={shortfall} (maturity_basis=unscheduled_book_liability_screen; no authenticated maturity schedule declared)"
                ),
            ));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Balance-sheet solvency valuation inputs (plan §11.6, FA-EVID-L52, fa-8j3g)
// ---------------------------------------------------------------------------

/// The valuation inputs' types and codec live in fa-model, where the kernel
/// validates extension 34 before an entry carrying it posts (`fa-8j3g`).
pub use fa_model::valuation::{
    InlineValuationTerms, ValuationApplicabilityLaw, ValuationBasisLaw, ValuationSubject,
};

/// One typed, attributable, dated valuation input in an [`AuthenticatedValuationSchedule`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredValuationInput {
    pub valuation_id: String,
    pub subject: ValuationSubject,
    pub entity: Option<VId>,
    pub unit: UnitId,
    pub basis_law: ValuationBasisLaw,
    pub applicability: ValuationApplicabilityLaw,
    pub signed_amount: i128,
    pub recorded_at: CommitSeq,
    pub authority: VId,
    pub supersedes: Option<String>,
    pub evidence_refs: Vec<EvidenceRef>,
}

/// Versioned, authenticated valuation adjustment schedule bound to a snapshot
/// coordinate (`book_id`, `known_at`, `as_of`) and caller scope (`fa-8j3g`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedValuationSchedule {
    pub schema_version: u16,
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub as_of: DateDay,
    pub caller_principal: VId,
    pub unit_filter: Option<UnitId>,
    pub entity_filter: Option<VId>,
    pub valuations: Vec<DeclaredValuationInput>,
}

impl AuthenticatedValuationSchedule {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u16(self.schema_version)
            .fixed(&self.book_id.0)
            .u64(self.known_at.0)
            .i32(self.as_of.0)
            .u128(self.caller_principal.0)
            .opt(self.unit_filter.as_ref(), |w, u| {
                w.u32(u.0);
            })
            .opt(self.entity_filter.as_ref(), |w, e| {
                w.u128(e.0);
            })
            .list(&self.valuations, |w, v| {
                w.str(&v.valuation_id).u8(v.subject.tag());
                match v.subject {
                    ValuationSubject::Account(acct) => {
                        w.u128(acct.0);
                    }
                    ValuationSubject::Instrument {
                        instrument,
                        carrying_account,
                    } => {
                        w.u128(instrument.0).u128(carrying_account.0);
                    }
                }
                w.opt(v.entity.as_ref(), |w, e| {
                    w.u128(e.0);
                })
                .u32(v.unit.0)
                .u8(v.basis_law.tag())
                .u8(v.applicability.tag());
                match v.applicability {
                    ValuationApplicabilityLaw::ExactAsOf { effective_date } => {
                        w.i32(effective_date.0);
                    }
                    ValuationApplicabilityLaw::EffectiveWindow {
                        effective_from,
                        effective_through,
                    } => {
                        w.i32(effective_from.0).i32(effective_through.0);
                    }
                }
                w.i128(v.signed_amount)
                    .u64(v.recorded_at.0)
                    .u128(v.authority.0)
                    .opt(v.supersedes.as_ref(), |w, s| {
                        w.str(s);
                    })
                    .list(&v.evidence_refs, |w, ev| {
                        w.fixed(&ev.document_oid.0)
                            .fixed(&ev.doc_commit)
                            .u8(ev.role);
                    });
            });
        w.finish()
    }

    pub fn schedule_digest(&self) -> Result<[u8; 32], EncodeError> {
        let bytes = self.encode()?;
        let mut h = Hasher::new();
        h.update(VALUATION_SCHEDULE_DOMAIN);
        h.update(&bytes);
        Ok(h.finalize().0)
    }
}

/// Exact audit record of an applied valuation input retained in the solvency report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedValuationRecord {
    pub valuation_id: String,
    pub subject: ValuationSubject,
    pub carrying_account: VId,
    pub unit_id: u32,
    pub entity: Option<VId>,
    pub basis_law: ValuationBasisLaw,
    pub applicability: ValuationApplicabilityLaw,
    pub book_signed_basis: i128,
    pub valued_signed_basis: i128,
    pub effective_delta: i128,
    pub recorded_at: CommitSeq,
    pub authority: VId,
    pub superseded_ids: Vec<String>,
    pub evidence_documents: Vec<Oid>,
}

/// Per-(unit, optional entity) balance-sheet solvency evaluation result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitBalanceSheetSolvency {
    pub unit_id: u32,
    pub entity: Option<VId>,
    pub as_of: DateDay,
    pub haircut_bps: i64,
    pub book_asset_basis: i128,
    pub valued_asset_basis: i128,
    pub adjusted_assets: i128,
    pub book_liabilities: i128,
    pub valued_liabilities: i128,
    pub deficit: i128,
    pub surplus: i128,
    pub applied_valuations: Vec<AppliedValuationRecord>,
    pub closure_documents: Vec<Oid>,
    pub certificate_digest: [u8; 32],
}

impl UnitBalanceSheetSolvency {
    #[must_use]
    pub fn log_line(&self) -> String {
        let mut hex = String::with_capacity(64);
        for b in &self.certificate_digest {
            use core::fmt::Write as _;
            let _ = write!(&mut hex, "{b:02x}");
        }
        let ids: Vec<&str> = self
            .applied_valuations
            .iter()
            .map(|v| v.valuation_id.as_str())
            .collect();
        format!(
            "solvency_balance_sheet unit={} entity={:?} as_of={} haircut_bps={} book_asset_basis={} valued_asset_basis={} adjusted_assets={} book_liabilities={} valued_liabilities={} deficit={} surplus={} valuations={:?} certificate_digest={hex}",
            self.unit_id,
            self.entity.map(|v| v.0),
            self.as_of,
            self.haircut_bps,
            self.book_asset_basis,
            self.valued_asset_basis,
            self.adjusted_assets,
            self.book_liabilities,
            self.valued_liabilities,
            self.deficit,
            self.surplus,
            ids,
        )
    }
}

/// Complete result of evaluating balance-sheet solvency over a snapshot and
/// authenticated valuation schedule (`fa-8j3g`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceSheetSolvencyReport {
    pub as_of: DateDay,
    pub haircut_bps: i64,
    pub schedule_digest: [u8; 32],
    pub units: BTreeMap<(u32, Option<VId>), UnitBalanceSheetSolvency>,
    pub findings: Vec<Finding>,
}

/// Extract an `AuthenticatedValuationSchedule` from inline
/// `fa:solvency-valuation:v1` entry extensions when present on the snapshot.
pub fn valuation_schedule_from_inline_extensions(
    procedure: &str,
    snapshot: &Snapshot,
) -> Result<Option<AuthenticatedValuationSchedule>, LanternError> {
    let mut any_inline = false;
    let mut valuations = Vec::new();
    let mut all_live = snapshot.live_postings()?;
    all_live.sort_by_key(|e| (e.recorded_at, e.vid));
    let as_of = snapshot.coordinate.effective_through.unwrap_or_else(|| {
        all_live
            .iter()
            .map(|e| e.entry.proposal.effective_date)
            .max()
            .unwrap_or(DateDay(0))
    });
    let mut caller_principal = VId(1);

    for e in &all_live {
        for (tag, bytes) in &e.entry.proposal.extensions {
            if *tag != VALUATION_ADJUSTMENT_EXT_TAG {
                continue;
            }
            any_inline = true;
            caller_principal = e.entry.proposal.principal_ref;
            let decoded = InlineValuationTerms::decode_list(bytes)?;
            let mut evidence_refs = e.entry.proposal.evidence.clone();
            if evidence_refs.is_empty() {
                evidence_refs.push(EvidenceRef {
                    document_oid: Oid(e.entry.entry_digest),
                    doc_commit: e.entry.entry_digest,
                    role: 1,
                });
            }
            for item in decoded {
                if item.valuation_id.trim().is_empty() {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "valuation_id".into(),
                        message: "inline valuation_id must be non-empty".into(),
                    });
                }
                valuations.push(DeclaredValuationInput {
                    valuation_id: item.valuation_id,
                    subject: item.subject,
                    entity: item.entity,
                    unit: item.unit,
                    basis_law: item.basis_law,
                    applicability: item.applicability,
                    signed_amount: item.signed_amount,
                    recorded_at: e.recorded_at,
                    authority: e.entry.proposal.principal_ref,
                    supersedes: item.supersedes,
                    evidence_refs: evidence_refs.clone(),
                });
            }
        }
    }

    if !any_inline {
        return Ok(None);
    }

    Ok(Some(AuthenticatedValuationSchedule {
        schema_version: SCHEDULE_SCHEMA_VERSION,
        book_id: snapshot.coordinate.book_id,
        known_at: snapshot.coordinate.known_at,
        as_of,
        caller_principal,
        unit_filter: None,
        entity_filter: None,
        valuations,
    }))
}

/// Evaluate balance-sheet solvency over signed book bases and explicit dated,
/// authenticated valuation adjustments (`fa-8j3g`).
///
/// Ordinary `RegisterEquals` attestations in `snapshot.attestations` are
/// reconciliation records and are never consulted or substituted for balances.
pub fn evaluate_balance_sheet_solvency(
    procedure: &str,
    snapshot: &Snapshot,
    book: &BookContext,
    haircut_bps: i128,
    schedule: &AuthenticatedValuationSchedule,
    work: &mut Meter<'_>,
) -> Result<BalanceSheetSolvencyReport, LanternError> {
    if !(0..=10_000).contains(&haircut_bps) {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "fair_value_haircut_bps".into(),
            message: "must be in 0..=10000".into(),
        });
    }
    let haircut_bps_i64 = i64::try_from(haircut_bps).map_err(|_| LanternError::Parameter {
        procedure: procedure.into(),
        name: "fair_value_haircut_bps".into(),
        message: "must fit in i64".into(),
    })?;
    if schedule.schema_version != SCHEDULE_SCHEMA_VERSION {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "schema_version".into(),
            message: format!(
                "unsupported valuation schedule schema_version {} (expected {})",
                schedule.schema_version, SCHEDULE_SCHEMA_VERSION
            ),
        });
    }
    if schedule.caller_principal == VId(0) {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "caller_principal".into(),
            message: "caller scope must be authenticated before reading protected solvency inputs"
                .into(),
        });
    }
    if schedule.book_id != snapshot.coordinate.book_id {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "book_id".into(),
            message: "valuation schedule book_id does not match snapshot book_id".into(),
        });
    }
    if schedule.known_at != snapshot.coordinate.known_at {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "known_at".into(),
            message: format!(
                "valuation schedule known_at {} does not match snapshot known_at {}",
                schedule.known_at.0, snapshot.coordinate.known_at.0
            ),
        });
    }

    let mut all_live = snapshot.live_postings()?;
    all_live.sort_by_key(|e| e.vid);
    let as_of = snapshot.coordinate.effective_through.unwrap_or_else(|| {
        all_live
            .iter()
            .map(|e| e.entry.proposal.effective_date)
            .max()
            .unwrap_or(DateDay(0))
    });
    if schedule.as_of != as_of {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "as_of".into(),
            message: format!(
                "valuation schedule as_of {} does not match snapshot effective date {}",
                schedule.as_of, as_of
            ),
        });
    }

    // 1. Authenticate and validate all declared valuation inputs before folding
    // protected account state.
    let mut by_id: BTreeMap<&str, (usize, VId, Vec<Oid>)> = BTreeMap::new();
    for (idx, v) in schedule.valuations.iter().enumerate() {
        work.compare(1)?;
        if v.valuation_id.trim().is_empty() {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "valuation_id".into(),
                message: "valuation_id must be non-empty".into(),
            });
        }
        if v.authority == VId(0) {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "authority".into(),
                message: format!(
                    "valuation `{}` is missing authorizing principal",
                    v.valuation_id
                ),
            });
        }
        if v.recorded_at > snapshot.coordinate.known_at {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "recorded_at".into(),
                message: format!(
                    "late-recorded valuation input `{}` recorded_at {} exceeds snapshot known_at {}",
                    v.valuation_id, v.recorded_at.0, snapshot.coordinate.known_at.0
                ),
            });
        }
        if let Some(filter_u) = schedule.unit_filter
            && v.unit != filter_u
        {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "unit".into(),
                message: format!(
                    "valuation `{}` unit {} is outside unit_filter {}",
                    v.valuation_id, v.unit.0, filter_u.0
                ),
            });
        }
        if let Some(filter_e) = schedule.entity_filter
            && v.entity != Some(filter_e)
        {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "entity".into(),
                message: format!(
                    "valuation `{}` entity {:?} is outside caller entity_filter {:?}",
                    v.valuation_id, v.entity, filter_e
                ),
            });
        }

        let carrying_account = match v.subject {
            ValuationSubject::Account(acct_vid) => acct_vid,
            ValuationSubject::Instrument {
                instrument,
                carrying_account,
            } => {
                let Some(inst) = snapshot.rea.instruments.get(&instrument) else {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "subject".into(),
                        message: format!(
                            "wrong-subject valuation `{}`: unknown instrument {:032x}",
                            v.valuation_id, instrument.0
                        ),
                    });
                };
                if inst.mirrors_account != carrying_account {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "subject".into(),
                        message: format!(
                            "wrong-subject valuation `{}`: instrument `{}` mirrors account {:032x}, not {:032x}",
                            v.valuation_id, inst.code, inst.mirrors_account.0, carrying_account.0
                        ),
                    });
                }
                if inst.unit != v.unit {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "unit".into(),
                        message: format!(
                            "wrong-unit valuation `{}`: unit {} mismatches instrument `{}` unit {}",
                            v.valuation_id, v.unit.0, inst.code, inst.unit.0
                        ),
                    });
                }
                carrying_account
            }
        };

        let Some(acct) = snapshot.accounts.get(&carrying_account) else {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "subject".into(),
                message: format!(
                    "wrong-subject valuation `{}`: account {:032x} does not exist in snapshot",
                    v.valuation_id, carrying_account.0
                ),
            });
        };
        let at = AccountType(acct.account_type);
        if !acct.is_leaf || !matches!(at, AccountType::ASSET | AccountType::LIABILITY) {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "subject".into(),
                message: format!(
                    "wrong-subject valuation `{}`: account `{}` must be a leaf Asset or Liability account",
                    v.valuation_id, acct.code
                ),
            });
        }
        if let UnitPolicy::Single(expected_unit) = acct.unit_policy
            && expected_unit != v.unit
        {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "unit".into(),
                message: format!(
                    "wrong-unit valuation `{}`: unit {} mismatches account `{}` unit {}",
                    v.valuation_id, v.unit.0, acct.code, expected_unit.0
                ),
            });
        }

        let doc_oids =
            validate_evidence_refs(procedure, snapshot, "valuation input", &v.evidence_refs)?;
        if by_id
            .insert(v.valuation_id.as_str(), (idx, carrying_account, doc_oids))
            .is_some()
        {
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "valuation_id".into(),
                message: format!("duplicate valuation_id `{}`", v.valuation_id),
            });
        }
    }

    // 2. Validate supersession chains and deterministic conflict precedence.
    let mut superseded_by: BTreeMap<&str, &str> = BTreeMap::new();
    for v in &schedule.valuations {
        if let Some(prior_id) = &v.supersedes {
            if prior_id == &v.valuation_id {
                return Err(LanternError::Parameter {
                    procedure: procedure.into(),
                    name: "supersedes".into(),
                    message: format!("valuation `{}` cannot supersede itself", v.valuation_id),
                });
            }
            let Some(&(prior_idx, prior_acct, _)) = by_id.get(prior_id.as_str()) else {
                return Err(LanternError::Parameter {
                    procedure: procedure.into(),
                    name: "supersedes".into(),
                    message: format!(
                        "valuation `{}` supersedes unknown valuation_id `{prior_id}`",
                        v.valuation_id
                    ),
                });
            };
            let prior_v = &schedule.valuations[prior_idx];
            let curr_acct = v.subject.carrying_account();
            if prior_acct != curr_acct || prior_v.unit != v.unit || prior_v.entity != v.entity {
                return Err(LanternError::Parameter {
                    procedure: procedure.into(),
                    name: "supersedes".into(),
                    message: format!(
                        "valuation `{}` cannot supersede `{prior_id}` across different carrying account, unit, or entity",
                        v.valuation_id
                    ),
                });
            }
            if prior_v.recorded_at > v.recorded_at {
                return Err(LanternError::Parameter {
                    procedure: procedure.into(),
                    name: "supersedes".into(),
                    message: format!(
                        "valuation `{}` (recorded_at {}) cannot supersede later-recorded `{prior_id}` (recorded_at {})",
                        v.valuation_id, v.recorded_at.0, prior_v.recorded_at.0
                    ),
                });
            }
            if superseded_by
                .insert(prior_id.as_str(), v.valuation_id.as_str())
                .is_some()
            {
                return Err(LanternError::Parameter {
                    procedure: procedure.into(),
                    name: "conflict".into(),
                    message: format!(
                        "conflicting valuations supersede the same prior valuation `{prior_id}`"
                    ),
                });
            }
        }
    }

    // Check for supersession cycles and collect active (unsuperseded) valuations.
    type ActiveValuationEntry = (usize, Vec<String>, Vec<Oid>);
    let mut active_by_target: BTreeMap<(VId, u32, Option<VId>), ActiveValuationEntry> =
        BTreeMap::new();
    for (idx, v) in schedule.valuations.iter().enumerate() {
        // Walk forward in `superseded_by` to detect any cycle.
        let mut cursor = v.valuation_id.as_str();
        let mut hops = 0usize;
        while let Some(&next) = superseded_by.get(cursor) {
            hops = hops.saturating_add(1);
            if hops > schedule.valuations.len() {
                return Err(LanternError::Parameter {
                    procedure: procedure.into(),
                    name: "supersedes".into(),
                    message: "cycle detected in valuation supersession chain".into(),
                });
            }
            cursor = next;
        }
        if superseded_by.contains_key(v.valuation_id.as_str()) {
            continue;
        }

        // Active valuation must be applicable at `as_of` under its declared law;
        // stale or future-effective valuations are never silently re-dated or applied.
        match v.applicability {
            ValuationApplicabilityLaw::ExactAsOf { effective_date } => {
                if effective_date > as_of {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "applicability".into(),
                        message: format!(
                            "future-effective valuation input `{}` (effective {effective_date} > as_of {as_of})",
                            v.valuation_id
                        ),
                    });
                }
                if effective_date < as_of {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "applicability".into(),
                        message: format!(
                            "stale ExactAsOf valuation input `{}` (effective {effective_date} < as_of {as_of}); no blanket re-dating",
                            v.valuation_id
                        ),
                    });
                }
            }
            ValuationApplicabilityLaw::EffectiveWindow {
                effective_from,
                effective_through,
            } => {
                if effective_from > effective_through {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "applicability".into(),
                        message: format!(
                            "valuation `{}` has invalid window {effective_from}..={effective_through}",
                            v.valuation_id
                        ),
                    });
                }
                if effective_from > as_of {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "applicability".into(),
                        message: format!(
                            "future-effective valuation input `{}` (effective_from {effective_from} > as_of {as_of})",
                            v.valuation_id
                        ),
                    });
                }
                if effective_through < as_of {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "applicability".into(),
                        message: format!(
                            "stale EffectiveWindow valuation input `{}` (effective_through {effective_through} < as_of {as_of})",
                            v.valuation_id
                        ),
                    });
                }
            }
        }

        let (_, carrying_account, ref docs) = by_id[v.valuation_id.as_str()];
        let target_key = (carrying_account, v.unit.0, v.entity);
        if let Some((prev_idx, _, _)) = active_by_target.get(&target_key) {
            let prev_v = &schedule.valuations[*prev_idx];
            let msg = if prev_v.subject.tag() != v.subject.tag() {
                format!(
                    "conflicting valuation inputs `{}` and `{}`: double application to both account and instrument on carrying account {:032x}",
                    prev_v.valuation_id, v.valuation_id, carrying_account.0
                )
            } else {
                format!(
                    "conflicting unsuperseded valuation inputs `{}` and `{}` for carrying account {:032x}",
                    prev_v.valuation_id, v.valuation_id, carrying_account.0
                )
            };
            return Err(LanternError::Parameter {
                procedure: procedure.into(),
                name: "conflict".into(),
                message: msg,
            });
        }

        // Collect the chain of superseded IDs and all their authenticating documents.
        let mut chain_ids = Vec::new();
        let mut chain_docs: BTreeSet<Oid> = docs.iter().copied().collect();
        let mut walk = v.supersedes.as_deref();
        while let Some(pid) = walk {
            chain_ids.push(pid.to_string());
            let (pidx, _, ref pdocs) = by_id[pid];
            chain_docs.extend(pdocs.iter().copied());
            walk = schedule.valuations[pidx].supersedes.as_deref();
        }
        active_by_target.insert(
            target_key,
            (idx, chain_ids, chain_docs.into_iter().collect()),
        );
    }

    // 3. Fold posted book balances through `as_of` (ignoring any `RegisterEquals`
    // reconciliation assertions in `snapshot.attestations`).
    let mut live_through = snapshot.live_postings_through(Some(as_of))?;
    live_through.sort_by_key(|e| e.vid);
    let scope =
        crate::projection::entity_scope(live_through.iter().flat_map(|e| &e.entry.proposal.legs))?;

    let mut acct_net: BTreeMap<(VId, u32, Option<VId>), i128> = BTreeMap::new();
    let mut scope_entries: BTreeMap<(u32, Option<VId>), (BTreeSet<VId>, u64)> = BTreeMap::new();

    for e in &live_through {
        work.entry()?;
        let has_inline_val = e
            .entry
            .proposal
            .extensions
            .iter()
            .any(|(t, _)| *t == VALUATION_ADJUSTMENT_EXT_TAG);
        for leg in &e.entry.proposal.legs {
            work.leg()?;
            let entity = crate::projection::scoped_entity(&scope, leg)?;
            if let Some(filter_u) = schedule.unit_filter
                && leg.amount.unit != filter_u
            {
                continue;
            }
            if let Some(filter_e) = schedule.entity_filter
                && entity != Some(filter_e)
            {
                continue;
            }
            let Some(acct) = snapshot.accounts.get(&leg.account_ref) else {
                continue;
            };
            let at = AccountType(acct.account_type);
            if !matches!(at, AccountType::ASSET | AccountType::LIABILITY) {
                if has_inline_val {
                    scope_entries
                        .entry((leg.amount.unit.0, entity))
                        .or_default()
                        .0
                        .insert(e.vid);
                }
                continue;
            }
            let signed = signed_leg(leg.side, leg.amount.mantissa)?;
            let cell = acct_net
                .entry((leg.account_ref, leg.amount.unit.0, entity))
                .or_default();
            *cell = cell
                .checked_add(signed)
                .ok_or(LanternError::Overflow("solvency balance sheet fold"))?;
            let inputs = scope_entries
                .entry((leg.amount.unit.0, entity))
                .or_default();
            inputs.0.insert(e.vid);
            inputs.1 = inputs.1.saturating_add(1);
        }
    }

    // Ensure every target of an active valuation is represented even if its
    // posted book balance is zero.
    for &target_key in active_by_target.keys() {
        acct_net.entry(target_key).or_default();
    }

    #[derive(Default)]
    struct UnitBalanceAccum {
        book_asset_basis: i128,
        valued_asset_basis: i128,
        book_liabilities: i128,
        valued_liabilities: i128,
        accts: BTreeSet<VId>,
        applied_valuations: Vec<AppliedValuationRecord>,
        docs: BTreeSet<Oid>,
    }

    let mut by_scope: BTreeMap<(u32, Option<VId>), UnitBalanceAccum> = BTreeMap::new();
    for ((acct_vid, unit_id, entity), posted_net) in acct_net {
        work.compare(1)?;
        let Some(acct) = snapshot.accounts.get(&acct_vid) else {
            continue;
        };
        let at = AccountType(acct.account_type);
        let row = by_scope.entry((unit_id, entity)).or_default();
        row.accts.insert(acct_vid);

        let book_signed_basis = match at {
            AccountType::ASSET => posted_net,
            AccountType::LIABILITY => amount_negated(posted_net, "solvency liability book basis")?,
            _ => continue,
        };

        let valued_signed_basis = if let Some((val_idx, superseded_ids, ev_docs)) =
            active_by_target.remove(&(acct_vid, unit_id, entity))
        {
            let v = &schedule.valuations[val_idx];
            let valued = match v.basis_law {
                ValuationBasisLaw::SignedDelta => amount_sum(
                    book_signed_basis,
                    v.signed_amount,
                    "solvency valuation delta",
                )?,
                ValuationBasisLaw::AbsoluteSignedBasis => v.signed_amount,
            };
            let effective_delta =
                amount_difference(valued, book_signed_basis, "solvency valuation delta")?;
            row.docs.extend(ev_docs.iter().copied());
            row.applied_valuations.push(AppliedValuationRecord {
                valuation_id: v.valuation_id.clone(),
                subject: v.subject,
                carrying_account: acct_vid,
                unit_id,
                entity,
                basis_law: v.basis_law,
                applicability: v.applicability,
                book_signed_basis,
                valued_signed_basis: valued,
                effective_delta,
                recorded_at: v.recorded_at,
                authority: v.authority,
                superseded_ids,
                evidence_documents: ev_docs,
            });
            valued
        } else {
            book_signed_basis
        };

        match at {
            AccountType::ASSET => {
                row.book_asset_basis = amount_sum(
                    row.book_asset_basis,
                    book_signed_basis,
                    "solvency signed assets sum",
                )?;
                row.valued_asset_basis = amount_sum(
                    row.valued_asset_basis,
                    valued_signed_basis,
                    "solvency valued assets sum",
                )?;
            }
            AccountType::LIABILITY => {
                row.book_liabilities = amount_sum(
                    row.book_liabilities,
                    book_signed_basis,
                    "solvency liabilities sum",
                )?;
                row.valued_liabilities = amount_sum(
                    row.valued_liabilities,
                    valued_signed_basis,
                    "solvency valued liabilities sum",
                )?;
            }
            _ => {}
        }
    }

    let schedule_digest = schedule.schedule_digest()?;
    let mut units = BTreeMap::new();
    let mut findings = Vec::new();

    for ((unit_id, entity), mut row) in by_scope {
        row.applied_valuations
            .sort_by(|a, b| a.valuation_id.cmp(&b.valuation_id));
        let adjusted_assets = if row.valued_asset_basis > 0 {
            let kept_bps = amount_difference(10_000, haircut_bps, "solvency asset haircut")?;
            amount_scaled_bps(row.valued_asset_basis, kept_bps, "solvency asset haircut")?
        } else {
            row.valued_asset_basis
        };
        let (deficit, surplus) = if row.valued_liabilities > adjusted_assets {
            (
                amount_difference(row.valued_liabilities, adjusted_assets, "solvency deficit")?,
                0,
            )
        } else {
            (
                0,
                amount_difference(adjusted_assets, row.valued_liabilities, "solvency surplus")?,
            )
        };

        let closure_documents: Vec<Oid> = row.docs.into_iter().collect();
        let certificate_digest = {
            let mut w = Writer::new();
            w.fixed(&schedule_digest)
                .fixed(&snapshot.inputs_digest)
                .u32(unit_id)
                .opt(entity.as_ref(), |w, e| {
                    w.u128(e.0);
                })
                .i32(as_of.0)
                .i64(haircut_bps_i64)
                .i128(row.book_asset_basis)
                .i128(row.valued_asset_basis)
                .i128(adjusted_assets)
                .i128(row.book_liabilities)
                .i128(row.valued_liabilities)
                .i128(deficit)
                .i128(surplus)
                .list(&row.applied_valuations, |w, av| {
                    w.str(&av.valuation_id)
                        .u8(av.subject.tag())
                        .u128(av.carrying_account.0)
                        .u8(av.basis_law.tag())
                        .u8(av.applicability.tag());
                    match av.applicability {
                        ValuationApplicabilityLaw::ExactAsOf { effective_date } => {
                            w.i32(effective_date.0);
                        }
                        ValuationApplicabilityLaw::EffectiveWindow {
                            effective_from,
                            effective_through,
                        } => {
                            w.i32(effective_from.0).i32(effective_through.0);
                        }
                    }
                    w.i128(av.book_signed_basis)
                        .i128(av.valued_signed_basis)
                        .i128(av.effective_delta)
                        .u64(av.recorded_at.0)
                        .u128(av.authority.0)
                        .list(&av.superseded_ids, |w, s| {
                            w.str(s);
                        })
                        .list(&av.evidence_documents, |w, d| {
                            w.fixed(&d.0);
                        });
                });
            let bytes = w.finish()?;
            let mut h = Hasher::new();
            h.update(BALANCE_SHEET_CLOSURE_DOMAIN);
            h.update(&bytes);
            h.finalize().0
        };

        if deficit > 0 {
            let mut cites: Vec<Cite> = row.accts.into_iter().map(Cite::Account).collect();
            let mut population = u64::try_from(row.applied_valuations.len()).unwrap_or(1);
            if let Some((entries, count)) = scope_entries.get(&(unit_id, entity)) {
                population = population.saturating_add(*count);
                let needed = cites
                    .len()
                    .saturating_add(entries.len())
                    .saturating_add(closure_documents.len());
                if needed > MAX_CITES {
                    return Err(LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "scope".into(),
                        message: format!(
                            "the complete signed solvency basis exceeds {MAX_CITES} citations; narrow the recorded/effective scope; no contributing account, entry, or valuation document is omitted"
                        ),
                    });
                }
                cites.extend(entries.iter().copied().map(Cite::Entry));
            } else if cites.len().saturating_add(closure_documents.len()) > MAX_CITES {
                return Err(LanternError::Parameter {
                    procedure: procedure.into(),
                    name: "scope".into(),
                    message: format!(
                        "the complete signed solvency basis exceeds {MAX_CITES} citations; narrow the recorded/effective scope; no contributing account, entry, or valuation document is omitted"
                    ),
                });
            }
            cites.extend(closure_documents.iter().copied().map(Cite::Document));

            let val_summary = if row.applied_valuations.is_empty() {
                "none".to_string()
            } else {
                row.applied_valuations
                    .iter()
                    .map(|av| {
                        format!(
                            "{}:{}:{}",
                            av.valuation_id,
                            av.basis_law.name(),
                            av.applicability.describe()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let scale = crate::unit_scale(book, unit_id)?;
            findings.push(finding(
                procedure,
                Severity::Critical,
                Statistic {
                    name: "insolvency_deficit".into(),
                    value: deficit,
                    scale,
                    population: population.max(1),
                },
                cites,
                format!(
                    "unit {unit_id} signed balance-sheet deficit: book_asset_basis={}, asset_basis={}, adjusted_assets={adjusted_assets}, book_liabilities={}, total_liabilities={}, insolvency_deficit={deficit} (haircut_bps={haircut_bps}; valuations=[{val_summary}]; technical solvency predicate)",
                    row.book_asset_basis,
                    row.valued_asset_basis,
                    row.book_liabilities,
                    row.valued_liabilities,
                ),
            ));
        }

        units.insert(
            (unit_id, entity),
            UnitBalanceSheetSolvency {
                unit_id,
                entity,
                as_of,
                haircut_bps: haircut_bps_i64,
                book_asset_basis: row.book_asset_basis,
                valued_asset_basis: row.valued_asset_basis,
                adjusted_assets,
                book_liabilities: row.book_liabilities,
                valued_liabilities: row.valued_liabilities,
                deficit,
                surplus,
                applied_valuations: row.applied_valuations,
                closure_documents,
                certificate_digest,
            },
        );
    }

    Ok(BalanceSheetSolvencyReport {
        as_of,
        haircut_bps: haircut_bps_i64,
        schedule_digest,
        units,
        findings,
    })
}

#[cfg(test)]
use crate::{Coordinate, Params, SnapshotEntry, run_over};
#[cfg(test)]
use fa_journal::AccountRoleSpec;
#[cfg(test)]
use fa_journal::rows::AccountRow;
#[cfg(test)]
use fa_model::{
    ControlPayload, EntryOrigin, EntryPayload, EntryRef, Erasable, LegPayload, SealKey, Settlement,
    SymbolTable, account_vid,
};
#[cfg(test)]
use fa_money::UnitRegistry;
#[cfg(test)]
use fa_time::FiscalCalendar;

#[cfg(test)]
fn day(y: i32, m: u8, d: u8) -> DateDay {
    DateDay::from_ymd(y, m, d).unwrap()
}

#[cfg(test)]
fn test_fixture(as_of: DateDay) -> (Snapshot, BookContext, VId, VId, Oid) {
    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
    let book_id = Id128([0x5a; 16]);
    let book = BookContext {
        book_id,
        calendar,
        units,
        seal_key: SealKey([0x44; 32]),
        symbols: SymbolTable::compiled(),
    };
    let cash_vid = account_vid(book_id, "1000");
    let ap_vid = account_vid(book_id, "2000");
    let exp_vid = account_vid(book_id, "6000");

    let mut accounts = BTreeMap::new();
    for (vid, code, name, account_type, normal_balance) in [
        (cash_vid, "1000", "Operating Cash", 1u8, 0u8),
        (ap_vid, "2000", "Accounts Payable", 2u8, 1u8),
        (exp_vid, "6000", "Operating Expense", 5u8, 0u8),
    ] {
        accounts.insert(
            vid,
            AccountRow {
                vid,
                code: code.into(),
                name: name.into(),
                account_type,
                normal_balance,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                created_at: CommitSeq(1),
                limit: None,
            },
        );
    }

    let role_payload = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::SCHEMA_CONTROL,
        effective_date: day(2026, 1, 1),
        document_date: None,
        description: Erasable::seal(
            &"assign cash role".to_string(),
            None,
            &book.seal_key,
            [1; 32],
            [1; 24],
        ),
        effective_period: None,
        unit_totals: Vec::new(),
        legs: Vec::new(),
        control: Some(ControlPayload::SchemaChange {
            kind: fa_journal::account_role::SCHEMA_CHANGE_ACCOUNT_ROLE,
            canonical_bytes: AccountRoleSpec {
                account: cash_vid,
                role: "cash".into(),
                assigned: true,
            }
            .encode()
            .unwrap(),
        }),
        base_totals: None,
        idempotency_key: b"role-cash".to_vec(),
        origin: EntryOrigin::Control {
            control_kind: fa_model::ControlKind::CHART_INSTALL,
            spec_body_digest: [1; 32],
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
    let role_entry = SnapshotEntry {
        vid: VId(1),
        entry: role_payload.seal(Vec::new(), None).unwrap(),
        recorded_at: CommitSeq(1),
        period: String::new(),
        approvals: Vec::new(),
    };

    let doc_oid = Oid([0x99; 32]);
    let mut documents = BTreeMap::new();
    documents.insert(
        doc_oid,
        crate::snapshot::SnapshotDocument {
            kind: 1,
            grade: 1,
            uploader: VId(7),
        },
    );

    let mut snapshot = Snapshot {
        coordinate: Coordinate {
            book_id,
            known_at: CommitSeq(50),
            effective_through: Some(as_of),
        },
        entries: vec![role_entry],
        accounts,
        roles: fa_journal::AccountRoles::default(),
        periods: BTreeMap::new(),
        transitions: BTreeMap::new(),
        open_items_as_of: None,
        rea: fa_journal::rea::ReaSnapshot {
            known_at: CommitSeq(50),
            parties: BTreeMap::new(),
            instruments: BTreeMap::new(),
            legal_entities: BTreeMap::new(),
            external_ids: BTreeMap::new(),
            relationships: Vec::new(),
            events: BTreeMap::new(),
        },
        attestations: BTreeMap::new(),
        documents,
        supplements: BTreeMap::new(),
        bank_reconciliations: None,
        inputs_digest: [0x22; 32],
    };
    snapshot.fold_roles().unwrap();
    (snapshot, book, cash_vid, ap_vid, doc_oid)
}

#[cfg(test)]
fn make_posting(
    book: &BookContext,
    vid: VId,
    eff: DateDay,
    class: EntryClass,
    legs: Vec<LegPayload>,
    extensions: Vec<(u16, Vec<u8>)>,
    doc_oid: Oid,
) -> SnapshotEntry {
    let seq = u64::try_from(vid.0).unwrap();
    let payload = EntryPayload {
        schema_minor: if extensions.is_empty() {
            0
        } else {
            fa_model::entry::EXTENSIONS_MINOR
        },
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class,
        effective_date: eff,
        document_date: Some(eff),
        description: Erasable::seal(
            &"posting".to_string(),
            None,
            &book.seal_key,
            [2; 32],
            [2; 24],
        ),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: seq.to_le_bytes().to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([2; 32]),
            intent_kind: 1,
        },
        principal_ref: VId(7),
        session_ref: None,
        evidence: vec![EvidenceRef {
            document_oid: doc_oid,
            doc_commit: [0xaa; 32],
            role: 1,
        }],
        supersession: Vec::new(),
        pending: (class == EntryClass::PENDING).then_some(fa_model::Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        }),
        external_ids: Vec::new(),
        extensions,
        tags: Vec::new(),
    };
    SnapshotEntry {
        vid,
        entry: payload.seal(Vec::new(), None).unwrap(),
        recorded_at: CommitSeq(seq),
        period: "2026-01".into(),
        approvals: Vec::new(),
    }
}

#[cfg(test)]
#[test]
fn debit_maturity_is_neither_a_liability_nor_a_forecast_inflow() {
    let as_of = day(2026, 4, 30);
    let (mut snapshot, book, cash, payable, document) = test_fixture(as_of);
    let usd = book.units.lookup("USD").unwrap();
    let expense = account_vid(book.book_id, "6000");
    snapshot.entries.push(make_posting(
        &book,
        VId(10),
        day(2026, 3, 1),
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, cash, Amount::new(usd, 100)),
            LegPayload::simple(Side::Credit, expense, Amount::new(usd, 100)),
        ],
        vec![
            InlineObligationTerms::to_receivable_extension(&[InlineObligationTerms {
                ordinal: 0,
                status: ObligationStatus::Contractual,
                installments: vec![ObligationInstallment {
                    due_date: day(2026, 3, 31),
                    amount: 100,
                }],
            }])
            .unwrap(),
        ],
        document,
    ));
    let procedure = crate::cutoff::SolvencyCashFlowTest::ID;
    assert!(
        schedule_from_inline_extensions(procedure, &snapshot, as_of)
            .unwrap()
            .is_none()
    );
    snapshot.entries.push(make_posting(
        &book,
        VId(11),
        day(2026, 3, 1),
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, expense, Amount::new(usd, 200)),
            LegPayload::simple(Side::Credit, payable, Amount::new(usd, 200)),
        ],
        vec![
            InlineObligationTerms::to_extension(&[InlineObligationTerms {
                ordinal: 1,
                status: ObligationStatus::Contractual,
                installments: vec![ObligationInstallment {
                    due_date: day(2026, 5, 1),
                    amount: 200,
                }],
            }])
            .unwrap(),
        ],
        document,
    ));
    let schedule = schedule_from_inline_extensions(procedure, &snapshot, as_of)
        .unwrap()
        .unwrap();
    assert_eq!(schedule.obligations.len(), 1);
    assert_eq!(schedule.obligations[0].entry, VId(11));
    assert_eq!(schedule.obligations[0].installments[0].amount, 200);
    assert!(schedule.expected_inflows.is_empty());
}

#[cfg(test)]
#[test]
fn cash_flow_horizon_uses_maturity_not_booking_date() {
    let apr30 = day(2026, 4, 30);
    let (mut snapshot, book, cash_vid, ap_vid, doc_oid) = test_fixture(apr30);
    let exp_vid = account_vid(book.book_id, "6000");
    let usd = book.units.lookup("USD").unwrap();

    // Cash = 100 at Apr 30; Jan-recorded debt of 1,000 contractually due Dec 31.
    let e_cash_and_long_debt = make_posting(
        &book,
        VId(10),
        day(2026, 1, 1),
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, cash_vid, Amount::new(usd, 100)),
            LegPayload::simple(Side::Debit, exp_vid, Amount::new(usd, 900)),
            LegPayload::simple(Side::Credit, ap_vid, Amount::new(usd, 1_000)),
        ],
        vec![
            InlineObligationTerms::to_extension(&[InlineObligationTerms {
                ordinal: 2,
                status: ObligationStatus::Contractual,
                installments: vec![ObligationInstallment {
                    due_date: day(2026, 12, 31),
                    amount: 1_000,
                }],
            }])
            .unwrap(),
        ],
        doc_oid,
    );
    snapshot.entries.push(e_cash_and_long_debt);

    // 1. At Apr 30 with horizon 30 (through May 30), Jan-recorded debt 1000 due Dec 31
    // produces 0 obligations within 30 days -> solvent (0 findings).
    let schedule_dec31 =
        schedule_from_inline_extensions(crate::cutoff::SolvencyCashFlowTest::ID, &snapshot, apr30)
            .unwrap()
            .unwrap();
    let mut meter = Meter::new(crate::cutoff::SolvencyCashFlowTest::ID, None, None);
    let rep_dec31 = evaluate_cash_flow_solvency(
        crate::cutoff::SolvencyCashFlowTest::ID,
        &snapshot,
        &book,
        30,
        &schedule_dec31,
        &mut meter,
    )
    .unwrap();
    let u_dec31 = &rep_dec31.units[&(usd.0, None)];
    assert_eq!(u_dec31.liquid_cash, 100);
    assert_eq!(u_dec31.maturing_obligations, 0);
    assert_eq!(u_dec31.deferred_obligations, 1_000);
    assert_eq!(u_dec31.shortfall, 0);
    assert!(rep_dec31.findings.is_empty());

    // Changing only maturity of the 1,000 debt from Dec 31 to May 20 changes both
    // the certificate digest and the solvency conclusion (shortfall = 900).
    let mut schedule_may20 = schedule_dec31.clone();
    schedule_may20.obligations[0].installments[0].due_date = day(2026, 5, 20);
    let rep_may20 = evaluate_cash_flow_solvency(
        crate::cutoff::SolvencyCashFlowTest::ID,
        &snapshot,
        &book,
        30,
        &schedule_may20,
        &mut meter,
    )
    .unwrap();
    let u_may20 = &rep_may20.units[&(usd.0, None)];
    assert_ne!(u_dec31.certificate_digest, u_may20.certificate_digest);
    assert_eq!(u_may20.maturing_obligations, 1_000);
    assert_eq!(u_may20.shortfall, 900);
    assert_eq!(rep_may20.findings.len(), 1);

    // 2. Add debt 40 due May 15, boundary debt 35 due May 30 (inclusive at 30 days),
    // and boundary debt 50 due May 31 (excluded at 30 days, included at 31 days).
    for (vid, due, amt) in [
        (VId(11), day(2026, 5, 15), 40i128),
        (VId(12), day(2026, 5, 30), 35i128),
        (VId(13), day(2026, 5, 31), 50i128),
    ] {
        snapshot.entries.push(make_posting(
            &book,
            vid,
            day(2026, 4, 10),
            EntryClass::ORIGINAL,
            vec![
                LegPayload::simple(Side::Debit, exp_vid, Amount::new(usd, amt)),
                LegPayload::simple(Side::Credit, ap_vid, Amount::new(usd, amt)),
            ],
            vec![
                InlineObligationTerms::to_extension(&[InlineObligationTerms {
                    ordinal: 1,
                    status: ObligationStatus::Contractual,
                    installments: vec![ObligationInstallment {
                        due_date: due,
                        amount: amt,
                    }],
                }])
                .unwrap(),
            ],
            doc_oid,
        ));
    }

    // Horizon 30 days (Apr 30 ..= May 30): includes May 15 (40) + May 30 (35) = 75 <= cash 100.
    // May 31 (50) and Dec 31 (1000) are excluded (deferred = 1050).
    let proc_30 = crate::cutoff::SolvencyCashFlowTest::new().unwrap();
    let run_30 = run_over(&snapshot, &book, &proc_30).unwrap();
    assert!(run_30.findings.is_empty(), "75 maturing <= 100 cash");

    let sched =
        schedule_from_inline_extensions(crate::cutoff::SolvencyCashFlowTest::ID, &snapshot, apr30)
            .unwrap()
            .unwrap();
    let rep_30 = evaluate_cash_flow_solvency(
        crate::cutoff::SolvencyCashFlowTest::ID,
        &snapshot,
        &book,
        30,
        &sched,
        &mut meter,
    )
    .unwrap();
    let u_30 = &rep_30.units[&(usd.0, None)];
    assert_eq!(u_30.maturing_obligations, 75);
    assert_eq!(u_30.deferred_obligations, 1_050);
    assert_eq!(u_30.shortfall, 0);

    // Horizon 31 days (Apr 30 ..= May 31): includes May 31 (50) -> maturing = 125 > cash 100 -> shortfall 25.
    let proc_31 = crate::cutoff::SolvencyCashFlowTest::with(
        Params::defaults(crate::cutoff::SolvencyCashFlowTest::ID)
            .unwrap()
            .set("horizon_days", 31)
            .unwrap(),
    );
    let run_31 = run_over(&snapshot, &book, &proc_31).unwrap();
    assert_eq!(run_31.findings.len(), 1);
    assert_eq!(run_31.findings[0].statistic.value, 25);
    assert!(
        run_31.findings[0]
            .narrative
            .contains("maturing_obligations=125")
    );
}

#[cfg(test)]
#[test]
fn settlements_and_commitments_are_counted_once() {
    let apr30 = day(2026, 4, 30);
    let (mut snapshot, book, cash_vid, ap_vid, doc_oid) = test_fixture(apr30);
    let exp_vid = account_vid(book.book_id, "6000");
    let usd = book.units.lookup("USD").unwrap();

    // Cash = 200 on Jan 1; Invoice of 150 on Apr 1 with two installments: 60 due May 10, 90 due Jun 15.
    let e_inv = make_posting(
        &book,
        VId(20),
        day(2026, 4, 1),
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, cash_vid, Amount::new(usd, 200)),
            LegPayload::simple(Side::Debit, exp_vid, Amount::new(usd, 150)),
            LegPayload::simple(Side::Credit, ap_vid, Amount::new(usd, 350)),
        ],
        Vec::new(),
        doc_oid,
    );
    let inv_ref = EntryRef {
        vid: e_inv.vid,
        entry_digest: e_inv.entry.entry_digest,
    };
    snapshot.entries.push(e_inv);

    // Partial settlement of 100 on Apr 20 against (VId(20), 2): reduces cash to 100 and open liability from 350 to 250.
    let mut pay_leg = LegPayload::simple(Side::Debit, ap_vid, Amount::new(usd, 100));
    pay_leg.settles.push(Settlement {
        target: inv_ref,
        ordinal: 2,
        amount: Amount::new(usd, 100),
    });
    let e_pay = make_posting(
        &book,
        VId(21),
        day(2026, 4, 20),
        EntryClass::ORIGINAL,
        vec![
            pay_leg,
            LegPayload::simple(Side::Credit, cash_vid, Amount::new(usd, 100)),
        ],
        Vec::new(),
        doc_oid,
    );
    snapshot.entries.push(e_pay);

    // A PENDING entry attempting to settle another 50 must be ignored (never relieves open liability).
    let mut pending_leg = LegPayload::simple(Side::Debit, ap_vid, Amount::new(usd, 50));
    pending_leg.settles.push(Settlement {
        target: inv_ref,
        ordinal: 2,
        amount: Amount::new(usd, 50),
    });
    let e_pending = make_posting(
        &book,
        VId(22),
        day(2026, 4, 25),
        EntryClass::PENDING,
        vec![
            pending_leg,
            LegPayload::simple(Side::Credit, cash_vid, Amount::new(usd, 50)),
        ],
        Vec::new(),
        doc_oid,
    );
    snapshot.entries.push(e_pending);

    let ev_ref = EvidenceRef {
        document_oid: doc_oid,
        doc_commit: [0xaa; 32],
        role: 1,
    };

    // Original installments: 160 due May 10, 190 due Jun 15 (total 350).
    // After the 100 partial settlement is applied once in chronological order:
    // - May 10 installment has 160 - 100 = 60 remaining (maturing within 30 days);
    // - Jun 15 installment has 190 remaining (deferred outside 30 days).
    // Also include:
    // - A commitment linked via `settles_entry: Some((VId(20), 2))` for 60 (must NOT double-count);
    // - An off-ledger commitment `COMM-RENT` for 70 due May 20 (counted once -> maturing_commitments = 70).
    // Total due within 30 days = 60 + 70 = 130 vs liquid_cash 100 -> shortfall = 30.
    let schedule = AuthenticatedObligationSchedule {
        schema_version: SCHEDULE_SCHEMA_VERSION,
        book_id: book.book_id,
        known_at: CommitSeq(50),
        as_of: apr30,
        unit_filter: None,
        entity_filter: None,
        obligations: vec![ScheduledObligation {
            entry: VId(20),
            ordinal: 2,
            account: ap_vid,
            unit: usd,
            entity: None,
            status: ObligationStatus::Contractual,
            installments: vec![
                ObligationInstallment {
                    due_date: day(2026, 5, 10),
                    amount: 160,
                },
                ObligationInstallment {
                    due_date: day(2026, 6, 15),
                    amount: 190,
                },
            ],
            evidence_refs: vec![ev_ref],
        }],
        commitments: vec![
            DeclaredCommitment {
                commitment_id: "COMM-INV20-INSTALLMENT1".into(),
                due_date: day(2026, 5, 10),
                amount: Amount::new(usd, 60),
                entity: None,
                settles_entry: Some((VId(20), 2)),
                evidence_refs: vec![ev_ref],
            },
            DeclaredCommitment {
                commitment_id: "COMM-LEASE-MAY".into(),
                due_date: day(2026, 5, 20),
                amount: Amount::new(usd, 70),
                entity: None,
                settles_entry: None,
                evidence_refs: vec![ev_ref],
            },
        ],
        expected_inflows: Vec::new(),
    };

    let mut meter = Meter::new(crate::cutoff::SolvencyCashFlowTest::ID, None, None);
    let report = evaluate_cash_flow_solvency(
        crate::cutoff::SolvencyCashFlowTest::ID,
        &snapshot,
        &book,
        30,
        &schedule,
        &mut meter,
    )
    .unwrap();
    let unit_rep = &report.units[&(usd.0, None)];
    assert_eq!(unit_rep.liquid_cash, 100);
    assert_eq!(unit_rep.maturing_obligations, 60);
    assert_eq!(unit_rep.deferred_obligations, 190);
    assert_eq!(unit_rep.maturing_commitments, 70);
    assert_eq!(unit_rep.shortfall, 30);

    // Duplicate commitment_id or missing open liability in schedule is refused.
    let mut dup_comm = schedule.clone();
    dup_comm.commitments.push(schedule.commitments[1].clone());
    assert!(
        evaluate_cash_flow_solvency(
            crate::cutoff::SolvencyCashFlowTest::ID,
            &snapshot,
            &book,
            30,
            &dup_comm,
            &mut meter,
        )
        .is_err()
    );

    let mut omitted = schedule.clone();
    omitted.obligations.clear();
    assert!(
        evaluate_cash_flow_solvency(
            crate::cutoff::SolvencyCashFlowTest::ID,
            &snapshot,
            &book,
            30,
            &omitted,
            &mut meter,
        )
        .is_err()
    );
}

#[cfg(test)]
#[test]
fn horizon_day_arithmetic_is_checked() {
    let apr30 = day(2026, 4, 30);
    let may30 = day(2026, 5, 30);
    let may31 = day(2026, 5, 31);

    // Valid inclusive horizon endpoints.
    assert_eq!(
        checked_horizon_end("solvency.cash_flow_test", apr30, 30).unwrap(),
        may30
    );
    assert_eq!(
        checked_horizon_end("solvency.cash_flow_test", apr30, 31).unwrap(),
        may31
    );

    // horizon_days == 0 is refused.
    assert!(matches!(
        checked_horizon_end("solvency.cash_flow_test", apr30, 0),
        Err(LanternError::Parameter { name, .. }) if name == "horizon_days"
    ));

    // horizon_days == u32::MAX (> i32::MAX) is refused without narrowing cast to negative.
    assert!(matches!(
        checked_horizon_end("solvency.cash_flow_test", apr30, u32::MAX),
        Err(LanternError::Parameter { name, .. }) if name == "horizon_days"
    ));
    assert!(matches!(
        checked_horizon_end(
            "solvency.cash_flow_test",
            apr30,
            u32::try_from(i32::MAX).unwrap().saturating_add(1),
        ),
        Err(LanternError::Parameter { name, .. }) if name == "horizon_days"
    ));

    // Civil-date extrema overflow (DateDay(i32::MAX) + 1) is refused without saturation.
    assert!(matches!(
        checked_horizon_end("solvency.cash_flow_test", DateDay(i32::MAX), 1),
        Err(LanternError::Parameter { name, .. }) if name == "horizon_days"
    ));
    assert_eq!(
        checked_horizon_end("solvency.cash_flow_test", DateDay(i32::MIN), 10).unwrap(),
        DateDay(i32::MIN.saturating_add(10))
    );
}

#[cfg(test)]
fn balance_sheet_fixture(
    as_of: DateDay,
) -> (Snapshot, BookContext, VId, VId, VId, VId, VId, VId, Oid) {
    let (mut snapshot, book, cash_vid, ap_vid, doc_oid) = test_fixture(as_of);
    let usd = book.units.lookup("USD").unwrap();
    let equip_vid = account_vid(book.book_id, "1510");
    let accum_dep_vid = account_vid(book.book_id, "1590");
    let eq_vid = account_vid(book.book_id, "3000");
    let exp_vid = account_vid(book.book_id, "6000");

    for (vid, code, name, account_type, normal_balance) in [
        (equip_vid, "1510", "Equipment", 1u8, 0u8),
        (accum_dep_vid, "1590", "Accumulated Depreciation", 1u8, 1u8),
        (eq_vid, "3000", "Retained Earnings", 3u8, 1u8),
    ] {
        snapshot.accounts.insert(
            vid,
            AccountRow {
                vid,
                code: code.into(),
                name: name.into(),
                account_type,
                normal_balance,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                created_at: CommitSeq(1),
                limit: None,
            },
        );
    }

    (
        snapshot,
        book,
        cash_vid,
        equip_vid,
        accum_dep_vid,
        ap_vid,
        eq_vid,
        exp_vid,
        doc_oid,
    )
}

#[cfg(test)]
#[test]
fn contra_assets_reduce_the_declared_asset_basis() {
    let mar31 = day(2026, 3, 31);
    let (mut snapshot, book, _cash_vid, equip_vid, accum_dep_vid, ap_vid, eq_vid, exp_vid, doc_oid) =
        balance_sheet_fixture(mar31);
    let usd = book.units.lookup("USD").unwrap();

    // Balanced entry 1: Dr Equipment 1510 = 100.00 (10,000) / Cr Liability 2000 = 50.00 (5,000) / Cr Equity 3000 = 50.00 (5,000).
    let e_fund = make_posting(
        &book,
        VId(10),
        day(2026, 3, 1),
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, equip_vid, Amount::new(usd, 10_000)),
            LegPayload::simple(Side::Credit, ap_vid, Amount::new(usd, 5_000)),
            LegPayload::simple(Side::Credit, eq_vid, Amount::new(usd, 5_000)),
        ],
        Vec::new(),
        doc_oid,
    );
    // Balanced entry 2: Dr Expense 6000 = 80.00 (8,000) / Cr Contra-Asset 1590 = 80.00 (8,000).
    let e_dep = make_posting(
        &book,
        VId(11),
        day(2026, 3, 15),
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, exp_vid, Amount::new(usd, 8_000)),
            LegPayload::simple(Side::Credit, accum_dep_vid, Amount::new(usd, 8_000)),
        ],
        Vec::new(),
        doc_oid,
    );
    snapshot.entries.push(e_fund);
    snapshot.entries.push(e_dep);

    // 1. Unscheduled balance-sheet test preserves signed contra-asset (-8,000):
    // net assets = 10,000 - 8,000 = 2,000 vs liabilities 5,000 -> exact deficit 3,000.
    let proc = crate::cutoff::SolvencyBalanceSheetTest::new().unwrap();
    let run_res = run_over(&snapshot, &book, &proc).unwrap();
    assert_eq!(run_res.findings.len(), 1);
    assert_eq!(run_res.findings[0].statistic.name, "insolvency_deficit");
    assert_eq!(run_res.findings[0].statistic.value, 3_000);
    assert!(
        run_res.findings[0]
            .cites
            .contains(&Cite::Account(equip_vid))
    );
    assert!(
        run_res.findings[0]
            .cites
            .contains(&Cite::Account(accum_dep_vid))
    );
    assert!(run_res.findings[0].cites.contains(&Cite::Account(ap_vid)));
    assert!(run_res.findings[0].cites.contains(&Cite::Entry(VId(10))));
    assert!(run_res.findings[0].cites.contains(&Cite::Entry(VId(11))));

    // 2. Explicit valuation schedule evaluation with empty valuations agrees
    // with the signed book basis (`book_asset_basis = 2_000`, `deficit = 3_000`).
    let mut meter = Meter::new(crate::cutoff::SolvencyBalanceSheetTest::ID, None, None);
    let empty_sched = AuthenticatedValuationSchedule {
        schema_version: SCHEDULE_SCHEMA_VERSION,
        book_id: book.book_id,
        known_at: snapshot.coordinate.known_at,
        as_of: mar31,
        caller_principal: VId(7),
        unit_filter: None,
        entity_filter: None,
        valuations: Vec::new(),
    };
    let rep = evaluate_balance_sheet_solvency(
        crate::cutoff::SolvencyBalanceSheetTest::ID,
        &snapshot,
        &book,
        0,
        &empty_sched,
        &mut meter,
    )
    .unwrap();
    let u = &rep.units[&(usd.0, None)];
    assert_eq!(u.book_asset_basis, 2_000);
    assert_eq!(u.valued_asset_basis, 2_000);
    assert_eq!(u.book_liabilities, 5_000);
    assert_eq!(u.valued_liabilities, 5_000);
    assert_eq!(u.deficit, 3_000);

    // 3. Explicit zero and negative absolute valuations on Equipment 1510 are
    // preserved without clamping (`0 - 8,000 = -8,000` -> deficit 13,000;
    // `-1,000 - 8,000 = -9,000` -> deficit 14,000), and haircuts never improve
    // a negative net asset basis.
    let ev_ref = EvidenceRef {
        document_oid: doc_oid,
        doc_commit: [0xaa; 32],
        role: 1,
    };
    for (abs_val, expected_valued_assets, expected_deficit) in [
        (0i128, -8_000i128, 13_000i128),
        (-1_000i128, -9_000i128, 14_000i128),
    ] {
        let sched = AuthenticatedValuationSchedule {
            valuations: vec![DeclaredValuationInput {
                valuation_id: "VAL-EQUIP-ABS".into(),
                subject: ValuationSubject::Account(equip_vid),
                entity: None,
                unit: usd,
                basis_law: ValuationBasisLaw::AbsoluteSignedBasis,
                applicability: ValuationApplicabilityLaw::ExactAsOf {
                    effective_date: mar31,
                },
                signed_amount: abs_val,
                recorded_at: CommitSeq(20),
                authority: VId(7),
                supersedes: None,
                evidence_refs: vec![ev_ref],
            }],
            ..empty_sched.clone()
        };
        for haircut_bps in [0i128, 5_000, 10_000] {
            let r = evaluate_balance_sheet_solvency(
                crate::cutoff::SolvencyBalanceSheetTest::ID,
                &snapshot,
                &book,
                haircut_bps,
                &sched,
                &mut meter,
            )
            .unwrap();
            let unit_res = &r.units[&(usd.0, None)];
            assert_eq!(unit_res.book_asset_basis, 2_000);
            assert_eq!(unit_res.valued_asset_basis, expected_valued_assets);
            assert_eq!(unit_res.adjusted_assets, expected_valued_assets);
            assert_eq!(unit_res.deficit, expected_deficit);
        }
    }
}

#[cfg(test)]
#[test]
fn historical_register_assertion_is_not_current_fair_value() {
    use fa_journal::attestation::{
        Attestation, AttestationClaim, CapabilityBinding, RegisterEqualsClaim, StoredAttestation,
        Subject,
    };
    use fa_policy::Profile;

    let apr30 = day(2026, 4, 30);
    let (
        mut snapshot,
        book,
        cash_vid,
        _equip_vid,
        _accum_dep_vid,
        ap_vid,
        eq_vid,
        exp_vid,
        doc_oid,
    ) = balance_sheet_fixture(apr30);
    let usd = book.units.lookup("USD").unwrap();

    // At CommitSeq(10) on Apr 1: Cash 1000 = 100.00 (10,000), Debt 2000 = 50.00 (5,000), Equity 3000 = 50.00 (5,000).
    snapshot.entries.push(make_posting(
        &book,
        VId(10),
        day(2026, 4, 1),
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, cash_vid, Amount::new(usd, 10_000)),
            LegPayload::simple(Side::Credit, ap_vid, Amount::new(usd, 5_000)),
            LegPayload::simple(Side::Credit, eq_vid, Amount::new(usd, 5_000)),
        ],
        Vec::new(),
        doc_oid,
    ));

    // At CommitSeq(11) on Apr 15: spend 80.00 (8,000) of Cash -> remaining Cash = 2,000 vs Debt 5,000 -> deficit = 3,000.
    snapshot.entries.push(make_posting(
        &book,
        VId(11),
        day(2026, 4, 15),
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, exp_vid, Amount::new(usd, 8_000)),
            LegPayload::simple(Side::Credit, cash_vid, Amount::new(usd, 8_000)),
        ],
        Vec::new(),
        doc_oid,
    ));

    let proc = crate::cutoff::SolvencyBalanceSheetTest::new().unwrap();
    let before_att = run_over(&snapshot, &book, &proc).unwrap();
    assert_eq!(before_att.findings.len(), 1);
    assert_eq!(before_att.findings[0].statistic.value, 3_000);

    // Record a valid historical RegisterEquals attestation evaluated at CommitSeq(10)
    // (where Cash was 10,000) into `snapshot.attestations`.
    let hist_claim = RegisterEqualsClaim {
        account: cash_vid,
        unit_id: usd.0,
        period: "2026-04".into(),
        entity: None,
        mantissa: 10_000,
        as_of_effective: apr30,
        evaluated_known_at: CommitSeq(10),
        fold_digest: [0x11; 32],
    };
    let cell_digest = hist_claim.cell_digest();
    snapshot.attestations.insert(
        VId(900),
        StoredAttestation {
            attestation: Attestation {
                book_id: book.book_id,
                claim: AttestationClaim::RegisterEquals(hist_claim),
                subject: Subject::Cell(cell_digest),
                principal: VId(7),
                evidence_refs: vec![doc_oid],
            },
            signed_digest: [0x22; 32],
            binding: CapabilityBinding {
                profile: Profile::Human,
                capability_commitment: [0x33; 32],
            },
        },
    );

    // Neither `SolvencyBalanceSheetTest` nor `evaluate_balance_sheet_solvency`
    // may infer valuation authority from the historical `RegisterEquals` claim.
    let after_att = run_over(&snapshot, &book, &proc).unwrap();
    assert_eq!(after_att.findings, before_att.findings);
    assert_eq!(after_att.findings[0].statistic.value, 3_000);

    let mut meter = Meter::new(crate::cutoff::SolvencyBalanceSheetTest::ID, None, None);
    let sched = AuthenticatedValuationSchedule {
        schema_version: SCHEDULE_SCHEMA_VERSION,
        book_id: book.book_id,
        known_at: snapshot.coordinate.known_at,
        as_of: apr30,
        caller_principal: VId(7),
        unit_filter: None,
        entity_filter: None,
        valuations: Vec::new(),
    };
    let rep = evaluate_balance_sheet_solvency(
        crate::cutoff::SolvencyBalanceSheetTest::ID,
        &snapshot,
        &book,
        0,
        &sched,
        &mut meter,
    )
    .unwrap();
    let u = &rep.units[&(usd.0, None)];
    assert_eq!(u.book_asset_basis, 2_000);
    assert_eq!(u.valued_asset_basis, 2_000);
    assert_eq!(u.deficit, 3_000);
    assert!(u.applied_valuations.is_empty());
}

#[cfg(test)]
#[test]
fn explicit_valuation_inputs_are_visible_applicable_and_cited() {
    let apr30 = day(2026, 4, 30);
    let (mut snapshot, book, _cash_vid, equip_vid, accum_dep_vid, ap_vid, eq_vid, exp_vid, doc_oid) =
        balance_sheet_fixture(apr30);
    let usd = book.units.lookup("USD").unwrap();
    let eur = book.units.lookup("EUR").unwrap();

    let doc2_oid = Oid([0x88; 32]);
    snapshot.documents.insert(
        doc2_oid,
        crate::snapshot::SnapshotDocument {
            kind: 1,
            grade: 1,
            uploader: VId(7),
        },
    );

    // Register an instrument carried in `equip_vid` (`1510`) so we can test
    // instrument valuation and double-application prevention.
    let inst_vid = VId(500);
    snapshot.rea.instruments.insert(
        inst_vid,
        fa_journal::rea::InstrumentRow {
            vid: inst_vid,
            code: "INST-EQUIP-1".into(),
            name: "Equipment Lease Contract".into(),
            kind: fa_model::InstrumentKind::Contract,
            unit: usd,
            held_at_party: VId(7),
            mirrors_account: equip_vid,
            external_ids: Vec::new(),
            created_at: CommitSeq(2),
        },
    );

    // Post Equipment 10,000, Contra-Asset -8,000 (net book assets = 2,000), Liability = 5,000 (deficit = 3,000).
    snapshot.entries.push(make_posting(
        &book,
        VId(10),
        day(2026, 4, 1),
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, equip_vid, Amount::new(usd, 10_000)),
            LegPayload::simple(Side::Credit, ap_vid, Amount::new(usd, 5_000)),
            LegPayload::simple(Side::Credit, eq_vid, Amount::new(usd, 5_000)),
        ],
        Vec::new(),
        doc_oid,
    ));
    snapshot.entries.push(make_posting(
        &book,
        VId(11),
        day(2026, 4, 15),
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, exp_vid, Amount::new(usd, 8_000)),
            LegPayload::simple(Side::Credit, accum_dep_vid, Amount::new(usd, 8_000)),
        ],
        Vec::new(),
        doc_oid,
    ));

    let ev1 = EvidenceRef {
        document_oid: doc_oid,
        doc_commit: [0xaa; 32],
        role: 1,
    };
    let ev2 = EvidenceRef {
        document_oid: doc2_oid,
        doc_commit: [0xbb; 32],
        role: 1,
    };

    let base_sched = AuthenticatedValuationSchedule {
        schema_version: SCHEDULE_SCHEMA_VERSION,
        book_id: book.book_id,
        known_at: CommitSeq(50),
        as_of: apr30,
        caller_principal: VId(7),
        unit_filter: None,
        entity_filter: None,
        valuations: Vec::new(),
    };
    let mut meter = Meter::new(crate::cutoff::SolvencyBalanceSheetTest::ID, None, None);

    // 1. Applicable valuation input (`VAL-1` = +1,000 delta on 1510 at CommitSeq(20))
    // superseded by `VAL-2` (+2,200 delta on 1510 at CommitSeq(25)):
    // valued_asset_basis = 2,000 + 2,200 = 4,200 vs liabilities 5,000 -> deficit = 800.
    // Both documents (`doc_oid` and `doc2_oid`) are cited in the finding closure.
    let sched_exact = AuthenticatedValuationSchedule {
        valuations: vec![
            DeclaredValuationInput {
                valuation_id: "VAL-1".into(),
                subject: ValuationSubject::Account(equip_vid),
                entity: None,
                unit: usd,
                basis_law: ValuationBasisLaw::SignedDelta,
                applicability: ValuationApplicabilityLaw::ExactAsOf {
                    effective_date: apr30,
                },
                signed_amount: 1_000,
                recorded_at: CommitSeq(20),
                authority: VId(7),
                supersedes: None,
                evidence_refs: vec![ev1],
            },
            DeclaredValuationInput {
                valuation_id: "VAL-2".into(),
                subject: ValuationSubject::Account(equip_vid),
                entity: None,
                unit: usd,
                basis_law: ValuationBasisLaw::SignedDelta,
                applicability: ValuationApplicabilityLaw::ExactAsOf {
                    effective_date: apr30,
                },
                signed_amount: 2_200,
                recorded_at: CommitSeq(25),
                authority: VId(7),
                supersedes: Some("VAL-1".into()),
                evidence_refs: vec![ev2],
            },
        ],
        ..base_sched.clone()
    };

    let rep_exact = evaluate_balance_sheet_solvency(
        crate::cutoff::SolvencyBalanceSheetTest::ID,
        &snapshot,
        &book,
        0,
        &sched_exact,
        &mut meter,
    )
    .unwrap();
    let u_exact = &rep_exact.units[&(usd.0, None)];
    assert_eq!(u_exact.book_asset_basis, 2_000);
    assert_eq!(u_exact.valued_asset_basis, 4_200);
    assert_eq!(u_exact.deficit, 800);
    assert_eq!(u_exact.applied_valuations.len(), 1);
    assert_eq!(u_exact.applied_valuations[0].valuation_id, "VAL-2");
    assert_eq!(
        u_exact.applied_valuations[0].superseded_ids,
        vec!["VAL-1".to_string()]
    );
    assert_eq!(rep_exact.findings.len(), 1);
    assert_eq!(rep_exact.findings[0].statistic.value, 800);
    assert!(
        rep_exact.findings[0]
            .cites
            .contains(&Cite::Document(doc_oid))
    );
    assert!(
        rep_exact.findings[0]
            .cites
            .contains(&Cite::Document(doc2_oid))
    );
    assert!(
        rep_exact.findings[0]
            .narrative
            .contains("VAL-2:signed_delta:exact_as_of(2026-04-30)")
    );

    // 2. Changing ONLY valuation applicability (`ExactAsOf` -> `EffectiveWindow`)
    // changes the schedule digest and certificate digest even with identical amounts.
    let mut sched_window = sched_exact.clone();
    sched_window.valuations[1].applicability = ValuationApplicabilityLaw::EffectiveWindow {
        effective_from: day(2026, 4, 1),
        effective_through: apr30,
    };
    let rep_window = evaluate_balance_sheet_solvency(
        crate::cutoff::SolvencyBalanceSheetTest::ID,
        &snapshot,
        &book,
        0,
        &sched_window,
        &mut meter,
    )
    .unwrap();
    let u_window = &rep_window.units[&(usd.0, None)];
    assert_eq!(u_window.deficit, 800);
    assert_ne!(rep_exact.schedule_digest, rep_window.schedule_digest);
    assert_ne!(u_exact.certificate_digest, u_window.certificate_digest);

    // 3. Inline valuation terms (`fa:solvency-valuation:v1`) round-trip through
    // `SolvencyBalanceSheetTest` and produce the exact same finding.
    let mut inline_snap = snapshot.clone();
    inline_snap.entries[1].entry = {
        let mut p = inline_snap.entries[1].entry.proposal.clone();
        p.schema_minor = fa_model::entry::EXTENSIONS_MINOR;
        p.extensions = vec![
            InlineValuationTerms::to_extension(&[InlineValuationTerms {
                valuation_id: "VAL-INLINE-2".into(),
                subject: ValuationSubject::Account(equip_vid),
                entity: None,
                unit: usd,
                basis_law: ValuationBasisLaw::SignedDelta,
                applicability: ValuationApplicabilityLaw::ExactAsOf {
                    effective_date: apr30,
                },
                signed_amount: 2_200,
                supersedes: None,
            }])
            .unwrap(),
        ];
        p.seal(Vec::new(), None).unwrap()
    };
    let proc = crate::cutoff::SolvencyBalanceSheetTest::new().unwrap();
    let inline_run = run_over(&inline_snap, &book, &proc).unwrap();
    assert_eq!(inline_run.findings.len(), 1);
    assert_eq!(inline_run.findings[0].statistic.value, 800);
    assert!(
        inline_run.findings[0]
            .cites
            .contains(&Cite::Document(doc_oid))
    );

    // 4. Refusal controls: missing evidence, wrong unit, wrong subject,
    // conflicting unsuperseded inputs, double application to account + instrument,
    // future-effective input, stale input, late-recorded input, unauthenticated caller.
    let single_val = DeclaredValuationInput {
        valuation_id: "VAL-SINGLE".into(),
        subject: ValuationSubject::Account(equip_vid),
        entity: None,
        unit: usd,
        basis_law: ValuationBasisLaw::SignedDelta,
        applicability: ValuationApplicabilityLaw::ExactAsOf {
            effective_date: apr30,
        },
        signed_amount: 1_000,
        recorded_at: CommitSeq(20),
        authority: VId(7),
        supersedes: None,
        evidence_refs: vec![ev1],
    };

    // (a) Missing evidence
    let mut no_ev = base_sched.clone();
    no_ev.valuations = vec![DeclaredValuationInput {
        evidence_refs: Vec::new(),
        ..single_val.clone()
    }];
    assert!(matches!(
        evaluate_balance_sheet_solvency(
            crate::cutoff::SolvencyBalanceSheetTest::ID,
            &snapshot,
            &book,
            0,
            &no_ev,
            &mut meter,
        ),
        Err(LanternError::Parameter { name, .. }) if name == "evidence_refs"
    ));

    // (b) Wrong unit (EUR valuation on USD-only account 1510)
    let mut wrong_unit = base_sched.clone();
    wrong_unit.valuations = vec![DeclaredValuationInput {
        unit: eur,
        ..single_val.clone()
    }];
    assert!(matches!(
        evaluate_balance_sheet_solvency(
            crate::cutoff::SolvencyBalanceSheetTest::ID,
            &snapshot,
            &book,
            0,
            &wrong_unit,
            &mut meter,
        ),
        Err(LanternError::Parameter { name, .. }) if name == "unit"
    ));

    // (c) Wrong subject (Expense account 6000 or unknown account/instrument)
    let mut wrong_subj = base_sched.clone();
    wrong_subj.valuations = vec![DeclaredValuationInput {
        subject: ValuationSubject::Account(exp_vid),
        ..single_val.clone()
    }];
    assert!(matches!(
        evaluate_balance_sheet_solvency(
            crate::cutoff::SolvencyBalanceSheetTest::ID,
            &snapshot,
            &book,
            0,
            &wrong_subj,
            &mut meter,
        ),
        Err(LanternError::Parameter { name, .. }) if name == "subject"
    ));

    // (d) Conflicting unsuperseded valuations on the same account
    let mut conflict_same = base_sched.clone();
    conflict_same.valuations = vec![
        single_val.clone(),
        DeclaredValuationInput {
            valuation_id: "VAL-CONFLICT".into(),
            signed_amount: 2_000,
            ..single_val.clone()
        },
    ];
    assert!(matches!(
        evaluate_balance_sheet_solvency(
            crate::cutoff::SolvencyBalanceSheetTest::ID,
            &snapshot,
            &book,
            0,
            &conflict_same,
            &mut meter,
        ),
        Err(LanternError::Parameter { name, .. }) if name == "conflict"
    ));

    // (e) Double application to both account (`1510`) and instrument (`inst_vid` carried in `1510`)
    let mut double_app = base_sched.clone();
    double_app.valuations = vec![
        single_val.clone(),
        DeclaredValuationInput {
            valuation_id: "VAL-INST".into(),
            subject: ValuationSubject::Instrument {
                instrument: inst_vid,
                carrying_account: equip_vid,
            },
            signed_amount: 500,
            ..single_val.clone()
        },
    ];
    assert!(matches!(
        evaluate_balance_sheet_solvency(
            crate::cutoff::SolvencyBalanceSheetTest::ID,
            &snapshot,
            &book,
            0,
            &double_app,
            &mut meter,
        ),
        Err(LanternError::Parameter { name, message, .. })
            if name == "conflict" && message.contains("double application to both account and instrument")
    ));

    // (f) Future-effective valuation (`effective_date > as_of`)
    let mut future_eff = base_sched.clone();
    future_eff.valuations = vec![DeclaredValuationInput {
        applicability: ValuationApplicabilityLaw::ExactAsOf {
            effective_date: day(2026, 5, 1),
        },
        ..single_val.clone()
    }];
    assert!(matches!(
        evaluate_balance_sheet_solvency(
            crate::cutoff::SolvencyBalanceSheetTest::ID,
            &snapshot,
            &book,
            0,
            &future_eff,
            &mut meter,
        ),
        Err(LanternError::Parameter { name, message, .. })
            if name == "applicability" && message.contains("future-effective")
    ));

    // (g) Stale valuation (`effective_date < as_of`, no blanket re-dating)
    let mut stale_eff = base_sched.clone();
    stale_eff.valuations = vec![DeclaredValuationInput {
        applicability: ValuationApplicabilityLaw::ExactAsOf {
            effective_date: day(2026, 4, 29),
        },
        ..single_val.clone()
    }];
    assert!(matches!(
        evaluate_balance_sheet_solvency(
            crate::cutoff::SolvencyBalanceSheetTest::ID,
            &snapshot,
            &book,
            0,
            &stale_eff,
            &mut meter,
        ),
        Err(LanternError::Parameter { name, message, .. })
            if name == "applicability" && message.contains("no blanket re-dating")
    ));

    // (h) Late-recorded valuation (`recorded_at > snapshot.coordinate.known_at`)
    let mut late_rec = base_sched.clone();
    late_rec.valuations = vec![DeclaredValuationInput {
        recorded_at: CommitSeq(51),
        ..single_val
    }];
    assert!(matches!(
        evaluate_balance_sheet_solvency(
            crate::cutoff::SolvencyBalanceSheetTest::ID,
            &snapshot,
            &book,
            0,
            &late_rec,
            &mut meter,
        ),
        Err(LanternError::Parameter { name, message, .. })
            if name == "recorded_at" && message.contains("late-recorded")
    ));

    // (i) Unauthenticated caller scope (`caller_principal == VId(0)`)
    let mut unauth = base_sched;
    unauth.caller_principal = VId(0);
    assert!(matches!(
        evaluate_balance_sheet_solvency(
            crate::cutoff::SolvencyBalanceSheetTest::ID,
            &snapshot,
            &book,
            0,
            &unauth,
            &mut meter,
        ),
        Err(LanternError::Parameter { name, .. }) if name == "caller_principal"
    ));
}
