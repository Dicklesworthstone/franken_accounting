//! The fa-reference differential adapter
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §15 A4r, §2.6 rule 6, §5.2; bead
//! fa-yugf.11, A4r).
//!
//! A P verdict is a first-refusal verdict. Where `fa-reference`'s `Oracle`
//! models the deciding law, the same intent is also decided by the oracle,
//! a second implementation with its own constants and its own arithmetic,
//! and its verdict must equal the kernel's first refusal. The composition
//! follows the kernel's order: `Oracle::post` (structure, balance, period
//! resolution, identity, period law with the principal's ops and the
//! approval count), then `sod::verdict` over the intent's approvals, then
//! `evidence::verdict` over its citations and attestations.
//!
//! Slice 1 decides a P cell on an oracle holding the book's calendar and
//! chart, with the period steps before the intent's own step replayed: the
//! intent's period in its history state, or, when the cell sets the period
//! state, driven from Future to it along the sweep order (Future → Open →
//! SoftClosed → Closed → Locked, A7c). The oracle's journal
//! holds no earlier entry yet: the laws the P cells read (balance, period,
//! identity on a fresh key, period law, SoD, evidence) do not read it. The
//! history replay that reversal and reclassification targets need is a
//! later slice.
//!
//! D cite sets (slice 3) are compared through `fa_reference::lantern`'s
//! naive procedures over rows built from the entries the run admitted: the
//! entries a procedure flags and their statistic must be the kernel's. A
//! procedure with no naive counterpart is `not_modelled`
//! (`no_lantern_function`).

use std::collections::BTreeMap;

use fa_reference::evidence::{self, Attestations, Citation, Custody, Doc, Law};
use fa_reference::lantern;
use fa_reference::sod::{self, Approval};
use fa_reference::{Account, Intent, Leg, Oracle, Side, Verdict};
use fa_registry::sod_policy::{SodKey, SodPolicy};
use fa_registry::{Admissibility, Decision, EntryClasses};
use fa_time::{CustomYear, DateDay, FiscalCalendar, PeriodState, PeriodTransition};

use super::Case;
use super::amount::parse_amount;
use super::book::{BookVariant, IntentDef, LegDef, StepKind};

/// The citation role `fa post --evidence <oid>` records (`Source`, tag 1).
const SOURCE_ROLE: u8 = 1;
/// The document kind the runner adds a stub as (`Other`).
const STUB_KIND: &str = "Other";
/// The grade `fa document add` records by default.
const STUB_GRADE: &str = "AgentUpload";
/// The principal the runner adds documents as (the book's embedded owner):
/// any identity no case principal maps to.
const OWNER: u64 = 0;

/// The reference verdict on one comparison (A4r).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefVerdict {
    Agree,
    Disagree {
        reference: String,
        kernel: String,
    },
    /// The oracle does not model the deciding law; the reason is one of a
    /// closed list (`case_delta`, `allocation`, `unmodelled_first_step`,
    /// `no_lantern_function`).
    NotModelled {
        reason: &'static str,
    },
}

impl RefVerdict {
    /// The runner's `ref=` token.
    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            Self::Agree => "agree",
            Self::Disagree { .. } => "disagree",
            Self::NotModelled { .. } => "not_modelled",
        }
    }
}

/// What a P cell sets on top of the intent's own encoding (A5a's cell
/// values for the kernel-read attributes).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CellSetting {
    pub entry_class: Option<String>,
    pub period_state: Option<PeriodState>,
    /// The `evidence_attached` value: `none`, `placeholder_unreviewed`,
    /// `placeholder_reviewed`, or `manual_assertion(<code>)`.
    pub evidence: Option<String>,
    /// The cell's own idempotency key (A7c's `cell_key`).
    pub key: Option<String>,
    /// The `approval_encoding` value: `draft_self_promotion` adds the
    /// owner's own promotion after an admitted plan (A8b).
    pub approval_encoding: Option<String>,
}

/// The adapter over one book variant.
pub struct ReferenceAdapter<'c> {
    case: &'c Case,
    book: &'c BookVariant,
    oracle: Oracle,
    law: Law,
    sod: SodPolicy,
    matrix: Admissibility,
    /// Unit code → (registry id, scale).
    units: BTreeMap<String, (u32, u8)>,
    /// Period label → the book's period code (`FY<fy>-P<nn>`).
    codes: BTreeMap<String, String>,
    /// A test-only hook: period steps the replay skips (A4r's planted
    /// negative).
    skip: Vec<(String, StepKind)>,
}

fn day(text: &str) -> Result<DateDay, String> {
    DateDay::parse(text).map_err(|e| format!("date `{text}`: {e:?}"))
}

/// The principal identity the oracle compares: the first 16 bytes of
/// SHA-256(`fa:case-principal:v1` ‖ label). Any injective map serves.
#[must_use]
pub fn principal_id(label: &str) -> u128 {
    let mut b = b"fa:case-principal:v1".to_vec();
    b.extend_from_slice(label.as_bytes());
    let d = crate::sha256::digest(&b);
    let mut x = [0u8; 16];
    x.copy_from_slice(&d[..16]);
    u128::from_be_bytes(x)
}

/// A document surrogate for the oracle's evidence law.
fn doc_id(id: &str) -> u64 {
    let d = crate::sha256::digest(id.as_bytes());
    let mut x = [0u8; 8];
    x.copy_from_slice(&d[..8]);
    u64::from_be_bytes(x)
}

impl<'c> ReferenceAdapter<'c> {
    /// The oracle set up from the variant's `[book]`, `[[period]]` and
    /// `[[account]]` rows; each decision replays the period steps before
    /// its intent's step.
    ///
    /// # Errors
    ///
    /// A period, date, unit or account type the oracle cannot take.
    pub fn new(case: &'c Case, book: &'c BookVariant) -> Result<Self, String> {
        Self::with_skips(case, book, Vec::new())
    }

    /// [`Self::new`] skipping the listed period steps (tests only: A4r's
    /// planted wrong-state negative).
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn with_skips(
        case: &'c Case,
        book: &'c BookVariant,
        skip: Vec<(String, StepKind)>,
    ) -> Result<Self, String> {
        // The calendar the runner creates: one custom year per fiscal year.
        let mut years: BTreeMap<i128, Vec<(DateDay, DateDay, String)>> = BTreeMap::new();
        for p in &book.periods {
            years.entry(p.fiscal_year).or_default().push((
                day(&p.start)?,
                day(&p.end)?,
                p.code.clone(),
            ));
        }
        let mut custom = Vec::new();
        let mut codes = BTreeMap::new();
        for (fy, periods) in &mut years {
            periods.sort();
            let fy32 = i32::try_from(*fy).map_err(|_| format!("fiscal year {fy}"))?;
            let spans: Vec<(DateDay, DateDay)> = periods.iter().map(|(a, b, _)| (*a, *b)).collect();
            custom.push(CustomYear::from_periods(fy32, &spans).map_err(|e| e.to_string())?);
            for (i, (_, _, label)) in periods.iter().enumerate() {
                codes.insert(label.clone(), format!("FY{fy}-P{:02}", i + 1));
            }
        }
        let calendar = FiscalCalendar::custom("custom", custom, 0).map_err(|e| e.to_string())?;
        let mut oracle = Oracle::new(calendar);
        oracle.set_opening_date(day(&book.book.opening_date)?);
        for fy in years.keys() {
            oracle.create_periods(i32::try_from(*fy).map_err(|_| format!("fiscal year {fy}"))?);
        }
        let types: BTreeMap<String, u8> = fa_registry::account_types_embedded()
            .map_err(|e| format!("account_types.toml: {e:?}"))?
            .into_iter()
            .map(|t| (t.name, t.tag))
            .collect();
        for a in &book.accounts {
            oracle.add_account(Account {
                code: a.code.clone(),
                is_leaf: true,
                unit: None,
            });
            let tag = types.get(&a.account_type).ok_or_else(|| {
                format!(
                    "account {}: type `{}` is not registered",
                    a.code, a.account_type
                )
            })?;
            oracle.set_account_type(&a.code, *tag);
        }
        let units = fa_registry::units_embedded()
            .map_err(|e| format!("units: {e:?}"))?
            .into_iter()
            .map(|u| (u.code, (u.id, u.scale)))
            .collect();
        let classes = EntryClasses::embedded().map_err(|e| format!("entry_classes.toml: {e:?}"))?;
        let matrix =
            Admissibility::embedded(&classes).map_err(|e| format!("admissibility.toml: {e:?}"))?;
        let sod = SodPolicy::embedded(&classes, &matrix)
            .map_err(|e| format!("sod_policy.toml: {e:?}"))?;
        let law = Law::embedded().map_err(|e| format!("evidence law: {e:?}"))?;
        Ok(Self {
            case,
            book,
            oracle,
            law,
            sod,
            matrix,
            units,
            codes,
            skip,
        })
    }

    fn transition(state: PeriodState, kind: StepKind) -> Option<(PeriodTransition, PeriodState)> {
        match (kind, state) {
            (StepKind::PeriodOpen, PeriodState::Future) => {
                Some((PeriodTransition::Open, PeriodState::Open))
            }
            (StepKind::PeriodSoftClose, PeriodState::Open) => {
                Some((PeriodTransition::SoftClose, PeriodState::SoftClosed))
            }
            (StepKind::PeriodClose, PeriodState::Open | PeriodState::SoftClosed) => {
                Some((PeriodTransition::Close, PeriodState::Closed))
            }
            (StepKind::PeriodLock, PeriodState::Closed) => {
                Some((PeriodTransition::Lock, PeriodState::Locked))
            }
            _ => None,
        }
    }

    /// The oracle after the period steps before `seq`, every period in its
    /// history state except `fresh`, left Future; and those states.
    fn oracle_at(
        &self,
        seq: i128,
        fresh: Option<&str>,
    ) -> Result<(Oracle, BTreeMap<String, PeriodState>), String> {
        let mut oracle = self.oracle.clone();
        let mut states: BTreeMap<String, PeriodState> = self
            .codes
            .keys()
            .map(|l| (l.clone(), PeriodState::Future))
            .collect();
        for step in self.book.steps.iter().filter(|s| s.seq < seq) {
            let Some(kind) = step.step_kind() else {
                continue;
            };
            if !matches!(
                kind,
                StepKind::PeriodOpen
                    | StepKind::PeriodSoftClose
                    | StepKind::PeriodClose
                    | StepKind::PeriodLock
            ) || fresh == Some(step.reference.as_str())
                || self.skip.contains(&(step.reference.clone(), kind))
            {
                continue;
            }
            let label = step.reference.as_str();
            let from = states.get(label).copied().unwrap_or(PeriodState::Future);
            Self::advance(&mut oracle, &self.codes, label, from, kind)?;
            if let Some((_, to)) = Self::transition(from, kind) {
                states.insert(label.to_string(), to);
            }
        }
        Ok((oracle, states))
    }

    fn advance(
        oracle: &mut Oracle,
        codes: &BTreeMap<String, String>,
        label: &str,
        from: PeriodState,
        kind: StepKind,
    ) -> Result<(), String> {
        let code = codes
            .get(label)
            .ok_or_else(|| format!("period `{label}` is not declared"))?;
        let (t, _) = Self::transition(from, kind)
            .ok_or_else(|| format!("period {label}: {kind:?} from {from:?}"))?;
        oracle
            .transition(code, t)
            .map_err(|e| format!("period {label} ({code}): {kind:?} refused {e}"))?;
        Ok(())
    }

    /// The `[[step]]` seq that posts `intent` (its `intent` step, or the
    /// `batch` step whose range holds it); past the history when none does.
    fn step_of(&self, intent: &IntentDef) -> i128 {
        let ids: Vec<&str> = self.book.intents.iter().map(|i| i.id.as_str()).collect();
        let in_range = |r: &str| {
            r.split_once("..").is_some_and(|(a, b)| {
                let (Some(i), Some(j), Some(k)) = (
                    ids.iter().position(|x| *x == a),
                    ids.iter().position(|x| *x == b),
                    ids.iter().position(|x| *x == intent.id),
                ) else {
                    return false;
                };
                i <= k && k <= j
            })
        };
        self.book
            .steps
            .iter()
            .find(|s| match s.step_kind() {
                Some(StepKind::Intent) => s.reference == intent.id,
                Some(StepKind::Batch) => s.reference == intent.id || in_range(&s.reference),
                _ => false,
            })
            .map_or_else(
                || self.book.steps.iter().map(|s| s.seq).max().unwrap_or(0) + 1,
                |s| s.seq,
            )
    }

    /// The period label an effective date falls in.
    fn period_of(&self, date: &str) -> Option<&str> {
        self.book
            .periods
            .iter()
            .find(|p| p.start.as_str() <= date && date <= p.end.as_str())
            .map(|p| p.code.as_str())
    }

    /// The oracle's intent for `intent` under `cell`.
    ///
    /// # Errors
    ///
    /// A leg whose unit or amount the oracle cannot take.
    pub fn intent(&self, intent: &IntentDef, cell: &CellSetting) -> Result<Intent, String> {
        let mut legs = Vec::new();
        for l in self.book.legs.iter().filter(|l| l.intent == intent.id) {
            let (unit, scale) = *self
                .units
                .get(&l.unit)
                .ok_or_else(|| format!("leg {}#{}: unit `{}`", l.intent, l.ordinal, l.unit))?;
            let mantissa = parse_amount(&l.amount_literal, scale)
                .map_err(|e| format!("leg {}#{}: {e:?}", l.intent, l.ordinal))?;
            legs.push(Leg {
                side: if l.side == "Dr" {
                    Side::Debit
                } else {
                    Side::Credit
                },
                account: l.account.clone(),
                unit,
                entity: l.entity.clone(),
                mantissa,
            });
        }
        let ops = self
            .book
            .principals
            .iter()
            .find(|p| p.label == intent.principal)
            .map(|p| p.grants.clone())
            .unwrap_or_default();
        let key = cell
            .key
            .clone()
            .or_else(|| intent.idempotency_key.clone())
            .unwrap_or_else(|| format!("case-{}", intent.id));
        Ok(Intent {
            class: cell
                .entry_class
                .clone()
                .unwrap_or_else(|| intent.class.clone()),
            date: day(&intent.effective_date)?,
            discriminator: None,
            legs,
            key: key.into_bytes(),
            ops,
            approvals: 0,
            reverses: None,
            supersession_reason: 0,
            resolves: None,
            settles: Vec::new(),
        })
    }

    /// The oracle's first refusal for `intent` under `cell` (`Ok(None)`
    /// admits), or why the oracle does not model it.
    ///
    /// # Errors
    ///
    /// `NotModelled` for a case Δ or an allocation; a string for an intent
    /// the adapter cannot build (an adapter defect).
    pub fn first_refusal(
        &self,
        intent: &IntentDef,
        cell: &CellSetting,
    ) -> Result<Result<Option<&'static str>, RefVerdict>, String> {
        if intent.is_delta() {
            return Ok(Err(RefVerdict::NotModelled {
                reason: "case_delta",
            }));
        }
        if intent.is_allocation() {
            return Ok(Err(RefVerdict::NotModelled {
                reason: "allocation",
            }));
        }
        let label = self.period_of(&intent.effective_date).ok_or_else(|| {
            format!(
                "{}: no declared period holds {}",
                intent.id, intent.effective_date
            )
        })?;
        let seq = self.step_of(intent);
        // The cell's period state, reached from Future along the sweep
        // order; else the history's at the intent's step.
        let (mut oracle, states) =
            self.oracle_at(seq, cell.period_state.is_some().then_some(label))?;
        let mut state = states.get(label).copied().unwrap_or(PeriodState::Future);
        if let Some(target) = cell.period_state {
            let rank = |s: PeriodState| match s {
                PeriodState::Future => 0,
                PeriodState::Open => 1,
                PeriodState::SoftClosed => 2,
                PeriodState::Closed => 3,
                _ => 4,
            };
            for (kind, to) in [
                (StepKind::PeriodOpen, PeriodState::Open),
                (StepKind::PeriodSoftClose, PeriodState::SoftClosed),
                (StepKind::PeriodClose, PeriodState::Closed),
                (StepKind::PeriodLock, PeriodState::Locked),
            ] {
                if rank(to) <= rank(state)
                    || rank(to) > rank(target)
                    || self.skip.contains(&(label.to_string(), kind))
                {
                    continue;
                }
                Self::advance(&mut oracle, &self.codes, label, state, kind)?;
                state = to;
            }
        }
        let reference = self.intent(intent, cell)?;
        // 1. Structure, balance, period, identity, period law.
        if let Verdict::Refused { code } = oracle.post(&reference) {
            return Ok(Ok(Some(code)));
        }
        // 2. SoD over the intent's approvals: none recorded by a P cell,
        //    except an entry_approval cell's own approval by the preparer,
        //    attached at post (A0, §6.4 W-P-01(b)).
        let key = SodKey {
            class: reference.class.clone(),
            state: Some(state),
            disposition: None,
            transition: None,
        };
        let (_, req) = self.sod.requirement(&key);
        let matrix_approvals = match self.matrix.decide(&reference.class, state) {
            Some(Decision::With { approvals, .. }) => *approvals,
            _ => 0,
        };
        let profile = self
            .book
            .principals
            .iter()
            .find(|p| p.label == intent.principal)
            .map_or("Human", |p| p.profile.as_str());
        let approvals: Vec<Approval> =
            if cell.approval_encoding.as_deref() == Some("entry_approval") {
                vec![Approval {
                    principal: principal_id(&intent.principal),
                    profile: profile.to_string(),
                    op: req.approver_op.clone(),
                }]
            } else {
                Vec::new()
            };
        if let Some((code, _)) = sod::verdict(
            req,
            matrix_approvals,
            principal_id(&intent.principal),
            profile,
            &approvals,
        ) {
            return Ok(Ok(Some(code)));
        }
        // 3. The evidence minimum over the cell's evidence.
        let (docs, citations, attestations) = self.evidence(intent, cell);
        if let Some(code) = evidence::verdict(
            &self.law,
            &reference.class,
            &docs,
            &citations,
            &attestations,
        ) {
            return Ok(Ok(Some(code)));
        }
        // 4. A draft self-promotion: the plan admitted, and its owner then
        //    promotes the draft himself, the one approval the draft-promote
        //    rule reads (sod_policy.toml#draft-promote).
        if cell.approval_encoding.as_deref() == Some("draft_self_promotion") {
            let key = SodKey {
                class: "DraftControl".into(),
                state: None,
                disposition: None,
                transition: Some("Promote".into()),
            };
            let (_, req) = self.sod.requirement(&key);
            let owner = principal_id(&intent.principal);
            let promotion = Approval {
                principal: owner,
                profile: profile.to_string(),
                op: req.approver_op.clone(),
            };
            if let Some((code, _)) = sod::verdict(req, 0, owner, profile, &[promotion]) {
                return Ok(Ok(Some(code)));
            }
        }
        Ok(Ok(None))
    }

    /// The documents, citations and attestations of `intent` under the
    /// cell's `evidence_attached` value, else the intent's own `evidence`
    /// document (reviewed when the book's row names a reviewer).
    fn evidence(
        &self,
        intent: &IntentDef,
        cell: &CellSetting,
    ) -> (BTreeMap<u64, Doc>, Vec<Citation>, Attestations) {
        let mut docs = BTreeMap::new();
        let mut citations = Vec::new();
        let mut attestations = Attestations::default();
        let cite = |id: &str,
                    reviewed: Option<&str>,
                    docs: &mut BTreeMap<u64, Doc>,
                    citations: &mut Vec<Citation>,
                    attestations: &mut Attestations| {
            let surrogate = doc_id(id);
            let commit = crate::sha256::digest(format!("fa:case-doc:{id}").as_bytes());
            docs.insert(
                surrogate,
                Doc {
                    kind: STUB_KIND.into(),
                    grade: STUB_GRADE.into(),
                    commit,
                    uploader: OWNER,
                    custody: Custody::uploaded(),
                },
            );
            citations.push(Citation {
                doc: surrogate,
                commit,
                role: SOURCE_ROLE,
            });
            if let Some(reviewer) = reviewed {
                let r = principal_id(reviewer);
                attestations
                    .reviews
                    .insert(surrogate, u64::try_from(r >> 64).unwrap_or(u64::MAX));
            }
        };
        let document = intent
            .evidence
            .as_deref()
            .and_then(|e| self.book.documents.iter().find(|d| d.id == e));
        match cell.evidence.as_deref() {
            None => {
                if let Some(d) = document {
                    cite(
                        &d.id,
                        d.reviewed_by.as_deref().filter(|r| !r.is_empty()),
                        &mut docs,
                        &mut citations,
                        &mut attestations,
                    );
                }
            }
            Some("none") => {}
            Some("placeholder_unreviewed") => {
                let id = document
                    .map_or_else(|| format!("placeholder:{}", intent.fact), |d| d.id.clone());
                cite(&id, None, &mut docs, &mut citations, &mut attestations);
            }
            Some("placeholder_reviewed") => {
                let id = document
                    .map_or_else(|| format!("placeholder:{}", intent.fact), |d| d.id.clone());
                cite(
                    &id,
                    Some("case-second-reader"),
                    &mut docs,
                    &mut citations,
                    &mut attestations,
                );
            }
            Some(other) => {
                let code = other
                    .strip_prefix("manual_assertion(")
                    .and_then(|r| r.strip_suffix(')'))
                    .and_then(reason_tag);
                attestations.manual = Some(code.unwrap_or(u16::MAX));
            }
        }
        (docs, citations, attestations)
    }

    /// The reference verdict on a P cell against the kernel's first refusal
    /// (`kernel`: the refusal id, or `None` when the kernel admitted).
    #[must_use]
    pub fn p_cell(
        &self,
        intent: &IntentDef,
        cell: &CellSetting,
        kernel: Option<&str>,
    ) -> RefVerdict {
        match self.first_refusal(intent, cell) {
            Ok(Ok(reference)) => {
                if reference == kernel {
                    RefVerdict::Agree
                } else {
                    RefVerdict::Disagree {
                        reference: reference.unwrap_or("admit").to_string(),
                        kernel: kernel.unwrap_or("admit").to_string(),
                    }
                }
            }
            Ok(Err(not_modelled)) => not_modelled,
            Err(why) => RefVerdict::Disagree {
                reference: format!("unmapped ({why})"),
                kernel: kernel.unwrap_or("admit").to_string(),
            },
        }
    }

    /// The case this adapter serves.
    #[must_use]
    pub const fn case(&self) -> &'c Case {
        self.case
    }
}

/// One entry the run admitted, as the reference's Lantern rows read it: the
/// intent and its legs (a case intent's, or a filler variant's). Filler
/// entries are rows of the population but not `compared`: the runner maps
/// only the case's entries back from the kernel's findings.
#[derive(Clone, Debug)]
pub struct LiveEntry<'a> {
    pub intent: &'a IntentDef,
    pub legs: Vec<&'a LegDef>,
    pub compared: bool,
}

impl ReferenceAdapter<'_> {
    /// The naive procedure's rows over `live`, in their given order: dates,
    /// periods (exclusive ends), legs at their unit's scale, the preparer,
    /// and a Reversal's target index.
    fn rows(&self, live: &[LiveEntry<'_>]) -> Result<Vec<lantern::Row>, String> {
        let mut rows = Vec::with_capacity(live.len());
        for (index, e) in live.iter().enumerate() {
            let date = day(&e.intent.effective_date)?;
            let period = self
                .book
                .periods
                .iter()
                .find(|p| p.start <= e.intent.effective_date && e.intent.effective_date <= p.end)
                .ok_or_else(|| format!("{}: no declared period holds its date", e.intent.id))?;
            let mut legs = Vec::new();
            for l in &e.legs {
                let (unit, scale) = *self
                    .units
                    .get(&l.unit)
                    .ok_or_else(|| format!("leg {}#{}: unit `{}`", l.intent, l.ordinal, l.unit))?;
                legs.push(lantern::Leg {
                    account: l.account.clone(),
                    debit: l.side == "Dr",
                    unit,
                    scale: u32::from(scale),
                    mantissa: parse_amount(&l.amount_literal, scale)
                        .map_err(|err| format!("leg {}#{}: {err:?}", l.intent, l.ordinal))?,
                });
            }
            let reverses = (e.intent.target_kind.as_deref() == Some("reverses"))
                .then(|| {
                    let target = e.intent.target.as_deref()?;
                    live.iter().position(|x| x.intent.id == target)
                })
                .flatten();
            // A migrated entry's legacy pair is its preparer and its one
            // approver (A7m); a native intent carries no approval.
            let (preparer, approvers) = match (
                e.intent.source_entered_by.as_deref(),
                e.intent.source_approved_by.as_deref(),
            ) {
                (Some(entered), Some(approved)) => {
                    (entered.to_string(), vec![approved.to_string()])
                }
                _ => (e.intent.principal.clone(), Vec::new()),
            };
            rows.push(lantern::Row {
                index,
                date,
                document_date: e.intent.document_date.as_deref().map(day).transpose()?,
                period: self.codes.get(&period.code).cloned().unwrap_or_default(),
                period_start: None,
                period_end: day(&period.end)?
                    .add_days(1)
                    .map_err(|err| format!("period {}: {err:?}", period.code))?,
                legs,
                preparer,
                approvers,
                description_chars: e.intent.memo.as_ref().map(|m| m.chars().count()),
                external_ids: Vec::new(),
                recorded_after_close: false,
                reverses,
                replaces: None,
            });
        }
        Ok(rows)
    }

    /// The reference verdict on a D procedure's findings: the entries the
    /// reference's naive procedure flags over `live`, each with its
    /// statistic, against the kernel's (`kernel`: intent id → statistic
    /// value). `params` are the run's procedure parameters (`name` → value);
    /// one it does not set takes the registered default.
    #[must_use]
    pub fn d_cites(
        &self,
        procedure: &str,
        params: &BTreeMap<String, i128>,
        live: &[LiveEntry<'_>],
        kernel: &BTreeMap<String, String>,
    ) -> RefVerdict {
        let param = |name: &str| -> Option<i128> {
            params.get(name).copied().or_else(|| {
                fa_registry::procedures::Procedures::embedded()
                    .ok()?
                    .get(procedure)?
                    .parameter(name)
                    .map(|p| p.default)
            })
        };
        let rows = match self.rows(live) {
            Ok(rows) => rows,
            Err(why) => {
                return RefVerdict::Disagree {
                    reference: format!("unmapped ({why})"),
                    kernel: render(kernel),
                };
            }
        };
        let reference: BTreeMap<String, String> = match procedure {
            "jet.round_amounts" => {
                let Some(power) = param("round_power").and_then(|p| u32::try_from(p).ok()) else {
                    return RefVerdict::Disagree {
                        reference: "unmapped (no round_power)".into(),
                        kernel: render(kernel),
                    };
                };
                lantern::round_amounts(&rows, power)
                    .into_iter()
                    .filter(|(i, _)| live[*i].compared)
                    .map(|(i, round)| (live[i].intent.id.clone(), round.to_string()))
                    .collect()
            }
            // Each flagged entry with its approvals by its preparer (the
            // kernel's `own_approvals`).
            "jet.self_approved" => lantern::self_approved(&rows)
                .into_iter()
                .filter(|i| live[*i].compared)
                .map(|i| {
                    let r = &rows[i];
                    let own = r.approvers.iter().filter(|a| **a == r.preparer).count();
                    (live[i].intent.id.clone(), own.to_string())
                })
                .collect(),
            _ => {
                return RefVerdict::NotModelled {
                    reason: "no_lantern_function",
                };
            }
        };
        if reference == *kernel {
            RefVerdict::Agree
        } else {
            RefVerdict::Disagree {
                reference: render(&reference),
                kernel: render(kernel),
            }
        }
    }
}

/// A finding map as a disagreement names it: `<intent>:<statistic>,...`.
fn render(map: &BTreeMap<String, String>) -> String {
    if map.is_empty() {
        return "none".into();
    }
    map.iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// A period state by its name (`Future`, `Open`, `SoftClosed`, `Closed`,
/// `Locked`), as the sweep and the branch classes spell it.
#[must_use]
pub fn period_state(name: &str) -> Option<PeriodState> {
    Some(match name {
        "Future" => PeriodState::Future,
        "Open" => PeriodState::Open,
        "SoftClosed" => PeriodState::SoftClosed,
        "Closed" => PeriodState::Closed,
        "Locked" => PeriodState::Locked,
        _ => return None,
    })
}

/// A registered ManualAssertion reason code's tag, by name.
fn reason_tag(name: &str) -> Option<u16> {
    fa_registry::reason_codes::ReasonCodes::embedded()
        .ok()?
        .rows
        .iter()
        .find(|c| c.name == name)
        .map(|c| c.code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cases::tests::pilot_planted;

    fn cell(state: Option<PeriodState>, evidence: Option<&str>, key: &str) -> CellSetting {
        CellSetting {
            entry_class: Some("Original".into()),
            period_state: state,
            evidence: evidence.map(Into::into),
            key: Some(key.into()),
            approval_encoding: None,
        }
    }

    fn f4(case: &Case) -> &IntentDef {
        case.books["native"]
            .intents
            .iter()
            .find(|i| i.id == "F4")
            .expect("F4")
    }

    /// W-P-03's cell: an Original into a Closed period is FA-REF-010 in the
    /// oracle (`Oracle::post`), agreeing with the kernel's refusal.
    #[test]
    fn original_into_a_closed_period_is_fa_ref_010_in_the_reference() {
        let case = pilot_planted(&[]);
        let book = &case.books["native"];
        let a = ReferenceAdapter::new(&case, book).expect("the adapter");
        let c = cell(Some(PeriodState::Closed), None, "wp03-closed");
        assert_eq!(a.first_refusal(f4(&case), &c), Ok(Ok(Some("FA-REF-010"))));
        assert_eq!(
            a.p_cell(f4(&case), &c, Some("FA-REF-010")),
            RefVerdict::Agree
        );
        // Open, with the intent's reviewed placeholder, admits.
        let open = cell(Some(PeriodState::Open), None, "wp03-open");
        assert_eq!(a.first_refusal(f4(&case), &open), Ok(Ok(None)));
    }

    /// W-P-02's cells through `evidence::verdict`: no evidence is
    /// FA-REF-080, an unreviewed placeholder FA-REF-086, a reviewed one
    /// admits.
    #[test]
    fn no_evidence_cell_is_fa_ref_080_in_the_reference() {
        let case = pilot_planted(&[]);
        let a = ReferenceAdapter::new(&case, &case.books["native"]).expect("the adapter");
        let c = cell(None, Some("none"), "wp02-none");
        assert_eq!(a.first_refusal(f4(&case), &c), Ok(Ok(Some("FA-REF-080"))));
        let reviewed = cell(None, Some("placeholder_reviewed"), "wp02-reviewed");
        assert_eq!(a.first_refusal(f4(&case), &reviewed), Ok(Ok(None)));
    }

    /// W-P-01's cells (A8b): an admitted plan promoted by its own owner is
    /// FA-REF-008 under the draft-promote rule; a plan the evidence minimum
    /// refuses gives that refusal first.
    #[test]
    fn draft_self_promotion_cell_is_fa_ref_008_in_the_reference() {
        let case = pilot_planted(&[]);
        let a = ReferenceAdapter::new(&case, &case.books["native"]).expect("the adapter");
        let draft = |evidence: &str, key: &str| CellSetting {
            approval_encoding: Some("draft_self_promotion".into()),
            ..cell(None, Some(evidence), key)
        };
        let reviewed = draft("placeholder_reviewed", "wp01-reviewed");
        assert_eq!(
            a.first_refusal(f4(&case), &reviewed),
            Ok(Ok(Some("FA-REF-008")))
        );
        assert_eq!(
            a.p_cell(f4(&case), &reviewed, Some("FA-REF-008")),
            RefVerdict::Agree
        );
        // Without the encoding the same cell admits.
        let plain = cell(None, Some("placeholder_reviewed"), "wp01-plain");
        assert_eq!(a.first_refusal(f4(&case), &plain), Ok(Ok(None)));
        let none = draft("none", "wp01-none");
        assert_eq!(
            a.first_refusal(f4(&case), &none),
            Ok(Ok(Some("FA-REF-080")))
        );
    }

    /// W-P-01(b)'s cells (A0): the preparer's own approval attached at post
    /// is refused FA-REF-008 before the evidence minimum is read, so the
    /// cell with no evidence is FA-REF-008 too.
    #[test]
    fn entry_self_approval_cell_is_fa_ref_008_before_the_evidence_minimum() {
        let case = pilot_planted(&[]);
        let a = ReferenceAdapter::new(&case, &case.books["native"]).expect("the adapter");
        let approved = |evidence: &str, key: &str| CellSetting {
            approval_encoding: Some("entry_approval".into()),
            ..cell(None, Some(evidence), key)
        };
        for (evidence, key) in [
            ("placeholder_reviewed", "wp01b-reviewed"),
            ("none", "wp01b-none"),
        ] {
            assert_eq!(
                a.first_refusal(f4(&case), &approved(evidence, key)),
                Ok(Ok(Some("FA-REF-008"))),
                "{evidence}"
            );
        }
    }

    #[test]
    fn unreviewed_placeholder_cell_is_fa_ref_086_in_the_reference() {
        let case = pilot_planted(&[]);
        let a = ReferenceAdapter::new(&case, &case.books["native"]).expect("the adapter");
        let c = cell(None, Some("placeholder_unreviewed"), "wp02-unreviewed");
        assert_eq!(a.first_refusal(f4(&case), &c), Ok(Ok(Some("FA-REF-086"))));
    }

    /// A4r's planted negative at the adapter: a hook that skips the 2001Q2
    /// close leaves the oracle deciding W-P-03's Closed cell in SoftClosed,
    /// where an Original needs post_softclosed (FA-REF-011 without it): the
    /// reference disagrees with the kernel's FA-REF-010, naming both.
    #[test]
    fn planted_wrong_period_state_in_the_adapter_fails() {
        let case = pilot_planted(&[]);
        let book = &case.books["native"];
        let a = ReferenceAdapter::with_skips(
            &case,
            book,
            vec![("2001Q2".into(), StepKind::PeriodClose)],
        )
        .expect("the adapter");
        let c = cell(Some(PeriodState::Closed), None, "wp03-closed");
        match a.p_cell(f4(&case), &c, Some("FA-REF-010")) {
            RefVerdict::Disagree { reference, kernel } => {
                assert_eq!(kernel, "FA-REF-010");
                // gen-acct-manager-1 holds {read, post}, not post_softclosed.
                assert_eq!(reference, "FA-REF-011", "the reference saw SoftClosed");
            }
            other => panic!("expected disagree, observed {other:?}"),
        }
    }

    fn live<'a>(case: &'a Case, ids: &[&str]) -> Vec<LiveEntry<'a>> {
        let book = &case.books["native"];
        ids.iter()
            .map(|id| LiveEntry {
                intent: book
                    .intents
                    .iter()
                    .find(|i| i.id == *id)
                    .expect("an intent"),
                legs: book.legs.iter().filter(|l| l.intent == *id).collect(),
                compared: true,
            })
            .collect()
    }

    fn found(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// A D on jet.round_amounts compares through
    /// fa_reference::lantern::round_amounts: F4's debit (560,000,000.00) is a
    /// multiple of 10^3, so the reference flags F4. The kernel's findings
    /// agree only when they are exactly the reference's entries and counts.
    #[test]
    fn d_on_round_amounts_compares_cite_sets_through_the_reference() {
        let case = pilot_planted(&[]);
        let a = ReferenceAdapter::new(&case, &case.books["native"]).expect("the adapter");
        let entries = live(&case, &["F2", "F4"]);
        let none = BTreeMap::new();
        let reference = match a.d_cites("jet.round_amounts", &none, &entries, &BTreeMap::new()) {
            RefVerdict::Disagree { reference, .. } => reference,
            other => panic!("an empty kernel side disagrees, observed {other:?}"),
        };
        let flagged: BTreeMap<String, String> = reference
            .split(',')
            .filter_map(|p| p.split_once(':'))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert!(flagged.contains_key("F4"), "{reference}");
        assert_eq!(
            a.d_cites("jet.round_amounts", &none, &entries, &flagged),
            RefVerdict::Agree
        );
        // One entry more, or a different count, disagrees.
        let mut extra = flagged.clone();
        extra.insert("F2".into(), "1".into());
        assert!(matches!(
            a.d_cites("jet.round_amounts", &none, &entries, &extra),
            RefVerdict::Disagree { .. }
        ));
        let mut count = flagged;
        count.insert("F4".into(), "99".into());
        assert!(matches!(
            a.d_cites("jet.round_amounts", &none, &entries, &count),
            RefVerdict::Disagree { .. }
        ));
    }

    /// expense.capitalization has no naive Lantern function: not_modelled,
    /// with its reason, never an agreement.
    #[test]
    fn d_without_a_lantern_function_is_not_modelled() {
        let case = pilot_planted(&[]);
        let a = ReferenceAdapter::new(&case, &case.books["native"]).expect("the adapter");
        assert_eq!(
            a.d_cites(
                "expense.capitalization",
                &BTreeMap::new(),
                &live(&case, &["F4"]),
                &found(&[("F4", "56000000000")])
            ),
            RefVerdict::NotModelled {
                reason: "no_lantern_function"
            }
        );
    }

    /// A case Δ and an allocation are never modelled, and say why.
    #[test]
    fn delta_and_allocation_are_not_modelled_with_their_reason() {
        let case = pilot_planted(&[]);
        let a = ReferenceAdapter::new(&case, &case.books["native"]).expect("the adapter");
        let delta = case.books["native"]
            .intents
            .iter()
            .find(|i| i.id == "delta-F4")
            .expect("delta-F4");
        assert_eq!(
            a.p_cell(delta, &CellSetting::default(), None),
            RefVerdict::NotModelled {
                reason: "case_delta"
            }
        );
    }
}
