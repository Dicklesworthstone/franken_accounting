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

use fa_journal::genesis::BookContext;
use fa_model::{
    AccountType, DecodeError, EncodeError, EntryClass, EvidenceRef, Id128, Oid, Reader, Writer,
};
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::amount::{amount_difference, amount_magnitude, amount_negated, amount_sum, signed_leg};
use crate::jet::finding;
use crate::{Cite, Finding, LanternError, MAX_CITES, Meter, Severity, Snapshot, Statistic};

/// Domain tag for canonical `AuthenticatedObligationSchedule` bytes.
pub const OBLIGATION_SCHEDULE_DOMAIN: &[u8] = b"fa:solvency-obligation-schedule:v1";

/// Domain tag for per-unit cash-flow solvency certificate closure digests.
pub const SOLVENCY_CLOSURE_DOMAIN: &[u8] = b"fa:solvency-cash-flow-closure:v1";

/// Extension tag (`0x534f` = `"SO"`) for per-entry inline obligation maturity schedules.
pub const OBLIGATION_MATURITY_EXT_TAG: u16 = 0x534f;

/// Current schema version of `AuthenticatedObligationSchedule`.
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

/// One contractual installment on an obligation (`amount > 0` in the
/// obligation's unit, due on `due_date`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObligationInstallment {
    pub due_date: DateDay,
    pub amount: i128,
}

/// Status of a scheduled obligation leg at `as_of`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObligationStatus {
    /// Contractual maturity schedule is known and complete.
    Contractual,
    /// Disputed liability; tracked separately with a reason code.
    Disputed { reason_code: u16 },
    /// Maturity terms are missing/unknown; prevents claiming complete
    /// maturity-based cash-flow solvency.
    MissingMaturity,
}

impl ObligationStatus {
    const fn tag(self) -> u8 {
        match self {
            Self::Contractual => 1,
            Self::Disputed { .. } => 2,
            Self::MissingMaturity => 3,
        }
    }
}

/// Per-entry inline maturity schedule carried in `EntryPayload::extensions`
/// under [`OBLIGATION_MATURITY_EXT_TAG`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineObligationTerms {
    pub ordinal: u16,
    pub status: ObligationStatus,
    pub installments: Vec<ObligationInstallment>,
}

impl InlineObligationTerms {
    pub fn encode_list(terms: &[Self]) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u16(SCHEDULE_SCHEMA_VERSION).list(terms, |w, item| {
            w.u16(item.ordinal).u8(item.status.tag());
            if let ObligationStatus::Disputed { reason_code } = item.status {
                w.u16(reason_code);
            }
            w.list(&item.installments, |w, inst| {
                w.i32(inst.due_date.0).i128(inst.amount);
            });
        });
        w.finish()
    }

    pub fn decode_list(bytes: &[u8]) -> Result<Vec<Self>, DecodeError> {
        let mut r = Reader::new(bytes);
        let version = r.u16("inline_obligation_terms.version")?;
        if version != SCHEDULE_SCHEMA_VERSION {
            return Err(r.invalid("inline_obligation_terms.version"));
        }
        let list = r.list(256, "inline_obligation_terms.items", |r| {
            let ordinal = r.u16("inline_obligation_terms.ordinal")?;
            let status = match r.u8("inline_obligation_terms.status")? {
                1 => ObligationStatus::Contractual,
                2 => ObligationStatus::Disputed {
                    reason_code: r.u16("inline_obligation_terms.reason_code")?,
                },
                3 => ObligationStatus::MissingMaturity,
                tag => return Err(r.bad_tag("inline_obligation_terms.status", tag)),
            };
            let installments = r.list(256, "inline_obligation_terms.installments", |r| {
                let due_date = DateDay(r.i32("installment.due_date")?);
                let amount = r.i128("installment.amount")?;
                if amount <= 0 {
                    return Err(r.invalid("installment.amount"));
                }
                Ok(ObligationInstallment { due_date, amount })
            })?;
            Ok(Self {
                ordinal,
                status,
                installments,
            })
        })?;
        r.finish()?;
        Ok(list)
    }

    pub fn to_extension(terms: &[Self]) -> Result<(u16, Vec<u8>), EncodeError> {
        Ok((OBLIGATION_MATURITY_EXT_TAG, Self::encode_list(terms)?))
    }
}

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
            any_inline = true;
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

#[cfg(test)]
use crate::{Coordinate, Params, SnapshotEntry, run_over};
#[cfg(test)]
use fa_journal::AccountRoleSpec;
#[cfg(test)]
use fa_journal::genesis::UnitPolicy;
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
    seq: u64,
    eff: DateDay,
    class: EntryClass,
    legs: Vec<LegPayload>,
    extensions: Vec<(u16, Vec<u8>)>,
    doc_oid: Oid,
) -> SnapshotEntry {
    let payload = EntryPayload {
        schema_minor: if extensions.is_empty() { 0 } else { 2 },
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
fn cash_flow_horizon_uses_maturity_not_booking_date() {
    let apr30 = day(2026, 4, 30);
    let (mut snapshot, book, cash_vid, ap_vid, doc_oid) = test_fixture(apr30);
    let exp_vid = account_vid(book.book_id, "6000");
    let usd = book.units.lookup("USD").unwrap();

    // Cash = 100 at Apr 30; Jan-recorded debt of 1,000 contractually due Dec 31.
    let e_cash_and_long_debt = make_posting(
        &book,
        VId(10),
        10,
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
    for (vid, seq, due, amt) in [
        (VId(11), 11u64, day(2026, 5, 15), 40i128),
        (VId(12), 12u64, day(2026, 5, 30), 35i128),
        (VId(13), 13u64, day(2026, 5, 31), 50i128),
    ] {
        snapshot.entries.push(make_posting(
            &book,
            vid,
            seq,
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
        20,
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
        21,
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
        22,
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
