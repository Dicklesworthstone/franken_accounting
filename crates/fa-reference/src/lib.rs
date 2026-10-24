//! The reference oracle (plan §16.2).
//!
//! Everything here is the *obvious* implementation: canonical maps, linear
//! scans, and sign-magnitude limb integers written from scratch so that a
//! shared arithmetic bug in `fa-money` cannot make the differential green.
//! The oracle mirrors the kernel's law order exactly — structure, control,
//! supported subset, balance, period resolution, identity (recorded outcome
//! or conflict), period law, accounts, reversal shape, resolution shape — and
//! returns the same
//! refusal codes as independent string constants, so a renumbering on either
//! side is a differential failure, never a silent agreement.
//!
//! Boundary: `std`, `fa-time`, and the registries. No `fa-money`, no
//! `fa-model`, no substrate.
//!
//! Period authority (plan §14.2, Appendix C PeriodControl) is modelled the
//! same way: an [`Authority`] is the plan's caveat list in plain values, the
//! admission point is an explicit input, revocations and the security policy
//! epoch are the oracle's own state, and the transition's SoD rule is looked
//! up literally in `sod_policy.toml` and judged by [`sod::verdict`].

#![forbid(unsafe_code)]

pub mod admissibility;
pub mod canon;
pub mod evidence;
pub mod external_subledger;
pub mod fx;
pub mod lantern;
pub mod lots;
pub mod rea;
pub mod read_scope;
pub mod reconciliation;
pub mod reports;
pub mod sod;
pub mod statements;
mod temporal;

/// The registered control kinds (`registries/entry_classes.toml`
/// `[[control_kind]]`, fa-g23), written out literally: `(id, name, the
/// control class it mints)`. The oracle's own copy, so a drift between the
/// kernel's origin bytes and the registry is a differential failure.
pub const CONTROL_KINDS: &[(u16, &str, &str)] = &[
    (1, "chart_install", "SchemaControl"),
    (2, "period_transition", "PeriodControl"),
    (3, "policy_activation", "PolicyControl"),
    (4, "time_tick", "TimeControl"),
    (5, "schedule_cancel", "ScheduleControl"),
    (6, "import_run", "ImportControl"),
    (7, "legal_hold", "HoldControl"),
    (8, "capability_revocation", "PolicyControl"),
    (9, "migration_run", "MigrationControl"),
    (10, "capability_issuance", "PolicyControl"),
    (11, "draft_transition", "DraftControl"),
    (12, "scenario_transition", "ScenarioControl"),
    (13, "period_creation", "SchemaControl"),
    (14, "production_transition", "ProductionControl"),
    (15, "statement_issuance", "IssuanceControl"),
    (16, "engagement_transition", "EngagementControl"),
    (17, "case_transition", "CaseControl"),
    (18, "recurring_schedule", "ScheduleControl"),
    (19, "rule_activation", "PolicyControl"),
];

/// The control class a record of kind `id` must carry, per the oracle's copy.
#[must_use]
pub fn control_kind_class(id: u16) -> Option<&'static str> {
    CONTROL_KINDS
        .iter()
        .find(|(k, _, _)| *k == id)
        .map(|(_, _, class)| *class)
}

use std::collections::{BTreeMap, BTreeSet};

use fa_registry::sod_policy::{SodPolicy, SodRequirement};
use fa_registry::{Admissibility, Decision, EntryClasses};
use fa_time::{DateDay, FiscalCalendar, PeriodDef, PeriodKind, PeriodState, PeriodTransition};

// ---------------------------------------------------------------------------
// Own arithmetic: sign-magnitude, base 2^32 limbs, little-endian.
// ---------------------------------------------------------------------------

/// An unbounded integer with its own limb arithmetic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Int {
    neg: bool,
    /// Magnitude, little-endian base 2^32, no trailing zero limbs; empty = 0.
    mag: Vec<u32>,
}

impl Int {
    #[must_use]
    pub fn zero() -> Self {
        Self {
            neg: false,
            mag: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_u128(mut m: u128) -> Self {
        let mut mag = Vec::new();
        while m != 0 {
            mag.push((m & 0xFFFF_FFFF) as u32);
            m >>= 32;
        }
        Self { neg: false, mag }
    }

    #[must_use]
    pub fn to_u128(&self) -> Option<u128> {
        if self.neg || self.mag.len() > 4 {
            return None;
        }
        let mut m: u128 = 0;
        for (i, limb) in self.mag.iter().enumerate() {
            m |= u128::from(*limb) << (32 * i);
        }
        Some(m)
    }

    #[must_use]
    pub fn from_i128(v: i128) -> Self {
        let neg = v < 0;
        let mut m = v.unsigned_abs();
        let mut mag = Vec::new();
        while m != 0 {
            mag.push((m & 0xFFFF_FFFF) as u32);
            m >>= 32;
        }
        Self { neg, mag }
    }

    /// `None` when the value does not fit `i128`.
    #[must_use]
    pub fn to_i128(&self) -> Option<i128> {
        if self.mag.len() > 4 {
            return None;
        }
        let mut m: u128 = 0;
        for (i, limb) in self.mag.iter().enumerate() {
            m |= u128::from(*limb) << (32 * i);
        }
        if self.neg {
            if m > (i128::MAX as u128) + 1 {
                return None;
            }
            Some((m as i128).wrapping_neg())
        } else {
            i128::try_from(m).ok()
        }
    }

    #[must_use]
    pub fn abs(&self) -> Self {
        Self {
            neg: false,
            mag: self.mag.clone(),
        }
    }

    #[must_use]
    pub fn negated(&self) -> Self {
        Self {
            neg: !self.neg,
            mag: self.mag.clone(),
        }
        .trim()
    }

    fn trim(mut self) -> Self {
        while self.mag.last() == Some(&0) {
            self.mag.pop();
        }
        if self.mag.is_empty() {
            self.neg = false;
        }
        self
    }

    fn cmp_mag(a: &[u32], b: &[u32]) -> core::cmp::Ordering {
        if a.len() != b.len() {
            return a.len().cmp(&b.len());
        }
        for i in (0..a.len()).rev() {
            if a[i] != b[i] {
                return a[i].cmp(&b[i]);
            }
        }
        core::cmp::Ordering::Equal
    }

    fn add_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
        let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
        let mut carry = 0u64;
        for i in 0..a.len().max(b.len()) {
            let s = u64::from(*a.get(i).unwrap_or(&0)) + u64::from(*b.get(i).unwrap_or(&0)) + carry;
            out.push((s & 0xFFFF_FFFF) as u32);
            carry = s >> 32;
        }
        if carry != 0 {
            out.push(carry as u32);
        }
        out
    }

    /// `a - b` for `|a| >= |b|`.
    fn sub_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
        let mut out = Vec::with_capacity(a.len());
        let mut borrow = 0i64;
        for (i, &ai) in a.iter().enumerate() {
            let mut d = i64::from(ai) - i64::from(*b.get(i).unwrap_or(&0)) - borrow;
            if d < 0 {
                d += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(d as u32);
        }
        out
    }

    /// Schoolbook base-2^32 limb multiplication.
    fn mul_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
        if a.is_empty() || b.is_empty() {
            return Vec::new();
        }
        let mut out = vec![0u32; a.len() + b.len()];
        for (i, &ai) in a.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &bj) in b.iter().enumerate() {
                let prod = u64::from(ai) * u64::from(bj) + u64::from(out[i + j]) + carry;
                out[i + j] = (prod & 0xFFFF_FFFF) as u32;
                carry = prod >> 32;
            }
            out[i + b.len()] = carry as u32;
        }
        out
    }

    /// Bit-by-bit long division of unsigned magnitudes (`b` non-empty).
    fn div_rem_mag(a: &[u32], b: &[u32]) -> (Vec<u32>, Vec<u32>) {
        if Self::cmp_mag(a, b) == core::cmp::Ordering::Less {
            return (Vec::new(), a.to_vec());
        }
        let total_bits = a.len() * 32;
        let mut q = vec![0u32; a.len()];
        let mut r: Vec<u32> = Vec::new();
        for bit_idx in (0..total_bits).rev() {
            let limb = bit_idx / 32;
            let shift = bit_idx % 32;
            let bit = (a[limb] >> shift) & 1;
            let mut carry = bit;
            for rl in &mut r {
                let next_carry = *rl >> 31;
                *rl = (*rl << 1) | carry;
                carry = next_carry;
            }
            if carry != 0 {
                r.push(carry);
            }
            while r.last() == Some(&0) {
                r.pop();
            }
            if Self::cmp_mag(&r, b) != core::cmp::Ordering::Less {
                r = Self::sub_mag(&r, b);
                while r.last() == Some(&0) {
                    r.pop();
                }
                q[limb] |= 1u32 << shift;
            }
        }
        (q, r)
    }

    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        if self.neg == rhs.neg {
            return Self {
                neg: self.neg,
                mag: Self::add_mag(&self.mag, &rhs.mag),
            }
            .trim();
        }
        match Self::cmp_mag(&self.mag, &rhs.mag) {
            core::cmp::Ordering::Less => Self {
                neg: rhs.neg,
                mag: Self::sub_mag(&rhs.mag, &self.mag),
            }
            .trim(),
            _ => Self {
                neg: self.neg,
                mag: Self::sub_mag(&self.mag, &rhs.mag),
            }
            .trim(),
        }
    }

    #[must_use]
    pub fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.negated())
    }

    /// Independent schoolbook multiplication (`std` only).
    #[must_use]
    pub fn mul(&self, rhs: &Self) -> Self {
        Self {
            neg: self.neg ^ rhs.neg,
            mag: Self::mul_mag(&self.mag, &rhs.mag),
        }
        .trim()
    }

    /// Independent truncating integer division and remainder (`None` on zero divisor).
    /// Satisfies `self == q * rhs + r`, `|r| < |rhs|`, and `r` has the sign of `self` when nonzero.
    #[must_use]
    pub fn div_rem(&self, rhs: &Self) -> Option<(Self, Self)> {
        if rhs.is_zero() {
            return None;
        }
        let (q_mag, r_mag) = Self::div_rem_mag(&self.mag, &rhs.mag);
        let q = Self {
            neg: self.neg ^ rhs.neg,
            mag: q_mag,
        }
        .trim();
        let r = Self {
            neg: self.neg,
            mag: r_mag,
        }
        .trim();
        Some((q, r))
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.mag.is_empty()
    }

    /// Strictly below zero (a trimmed zero is never negative).
    #[must_use]
    pub fn is_negative(&self) -> bool {
        self.neg && !self.mag.is_empty()
    }
}

impl PartialOrd for Int {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Int {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match (self.is_negative(), other.is_negative()) {
            (true, false) => core::cmp::Ordering::Less,
            (false, true) => core::cmp::Ordering::Greater,
            (false, false) => Self::cmp_mag(&self.mag, &other.mag),
            (true, true) => Self::cmp_mag(&other.mag, &self.mag),
        }
    }
}

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Debit,
    Credit,
}

impl Side {
    #[must_use]
    pub fn flipped(self) -> Self {
        match self {
            Self::Debit => Self::Credit,
            Self::Credit => Self::Debit,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    pub side: Side,
    pub account: String,
    pub unit: u32,
    /// The leg's legal entity (plan §4.1, §5.2): a declared entity's code,
    /// or `None` (the book's single entity, or a book declaring none).
    pub entity: Option<String>,
    pub mantissa: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub code: String,
    pub is_leaf: bool,
    /// `None` = any unit.
    pub unit: Option<u32>,
}

/// A balance limit (plan §5.4): bounds on the account's net balance in its
/// normal-balance sign (`net = normal-side posted − opposite-side posted`).
/// `per_period` makes it a budget cap (plan §5.5): the bounds apply to each
/// period's activity separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limit {
    pub normal: Side,
    pub lower: Option<i128>,
    pub upper: Option<i128>,
    pub per_period: bool,
}

/// A limited account's literal fold: posted and outstanding reserved sums
/// per side, and how many journal entries moved them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Availability {
    pub debits_posted: Int,
    pub credits_posted: Int,
    pub debits_pending: Int,
    pub credits_pending: Int,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    /// Class name as registered (`Original`, `Reversal`, …).
    pub class: String,
    pub date: DateDay,
    pub discriminator: Option<String>,
    pub legs: Vec<Leg>,
    pub key: Vec<u8>,
    pub ops: Vec<String>,
    pub approvals: usize,
    /// For a Reversal: the journal index of the entry it reverses.
    pub reverses: Option<usize>,
    /// Registered `supersession` reason; consulted only for a reversal.
    pub supersession_reason: u16,
    /// For a Resolution: the pending entry it resolves and its disposition.
    pub resolves: Option<Resolve>,
    /// Applications (plan §5.7): `legs[leg]` applies `mantissa` to journal
    /// entry `target`'s leg `ordinal`.
    pub settles: Vec<Settle>,
}

/// One application of an intent's leg to an open item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settle {
    pub leg: usize,
    pub target: usize,
    pub ordinal: usize,
    pub mantissa: i128,
}

/// Provenance asserted by a caller of the public posting path. Migration
/// provenance is modelled by [`Oracle::post_migration`] and its verified run.
/// The remaining system origins may only be minted internally.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClaimedOrigin {
    #[default]
    Intent,
    Rule,
    Control,
    Sweep,
    Schedule,
}

/// A caller's unverified functional-currency aggregate. The model need only
/// represent its unit and totals: no supplied law or rate can authorize it
/// before the FX admission law exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedBaseTotals {
    pub unit: u32,
    pub debits: i128,
    pub credits: i128,
}

/// Claims outside the reference model's ordinary authored intent. These are
/// plain model values, independent of production payload and envelope types.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PostClaims {
    pub origin: ClaimedOrigin,
    pub plan_certificate: Option<[u8; 32]>,
    pub base_totals: Option<ClaimedBaseTotals>,
}

/// A Resolution's target and disposition (plan §5.4): `posts = Some(ordinals)`
/// posts `Intent.legs` as a sub-vector drawn from those pending legs;
/// `posts = None` voids (releases) the whole hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolve {
    pub target: usize,
    pub posts: Option<Vec<u16>>,
}

/// Refusal codes, as independent constants (see the module docs).
pub mod code {
    pub const UNBALANCED: &str = "FA-REF-001";
    pub const NOT_A_LEAF: &str = "FA-REF-002";
    pub const UNIT_POLICY: &str = "FA-REF-003";
    pub const UNKNOWN_ACCOUNT: &str = "FA-REF-004";
    pub const UNIT_UNREGISTERED: &str = "FA-REF-154";
    pub const PERIOD_LAW: &str = "FA-REF-010";
    pub const SOD: &str = "FA-REF-008";
    pub const CAPABILITY: &str = "FA-REF-011";
    pub const APPROVALS: &str = "FA-REF-012";
    pub const AGENT_TRUNK: &str = "FA-REF-013";
    pub const EXPIRED: &str = "FA-REF-014";
    pub const PERIOD_RESOLVE: &str = "FA-REF-020";
    pub const PERIOD_UNKNOWN: &str = "FA-REF-021";
    pub const STALE_APPROVAL: &str = "FA-REF-022";
    pub const REVOKED: &str = "FA-REF-023";
    pub const CONFLICT: &str = "FA-REF-030";
    pub const IDEMPOTENCY_CONFLICT: &str = "FA-REF-032";
    pub const TRANSITION: &str = "FA-REF-040";
    pub const PERIOD_REASON: &str = "FA-REF-041";
    pub const REVERSAL_TARGET: &str = "FA-REF-050";
    pub const REVERSAL_SHAPE: &str = "FA-REF-051";
    pub const REPLACEMENT_UNPAIRED: &str = "FA-REF-160";
    pub const ALREADY_REVERSED: &str = "FA-REF-052";
    pub const REVERSAL_PERIOD: &str = "FA-REF-053";
    pub const SUPERSESSION_REASON: &str = "FA-REF-054";
    pub const RESOLUTION_TARGET: &str = "FA-REF-060";
    pub const RESOLUTION_SHAPE: &str = "FA-REF-061";
    pub const ALREADY_RESOLVED: &str = "FA-REF-062";
    pub const SETTLE_TARGET: &str = "FA-REF-070";
    pub const SETTLE_SHAPE: &str = "FA-REF-071";
    pub const OVER_APPLICATION: &str = "FA-REF-072";
    pub const LIVE_APPLICATIONS: &str = "FA-REF-073";
    pub const AVAILABILITY_LOWER: &str = "FA-REF-090";
    pub const AVAILABILITY_UPPER: &str = "FA-REF-091";
    pub const LIMIT_CEILING: &str = "FA-REF-092";
    pub const BALANCING_SHAPE: &str = "FA-REF-093";
    pub const TICK_ORDER: &str = "FA-REF-094";
    pub const TICK_MISSING: &str = "FA-REF-095";
    pub const DEADLINE_OVERFLOW: &str = "FA-REF-096";
    pub const HOLD_DUE: &str = "FA-REF-097";
    pub const DIMENSION_MISSING: &str = "FA-REF-005";
    pub const ENTITY_UNDECLARED: &str = "FA-REF-104";
    pub const STRUCTURE: &str = "FA-REF-100";
    pub const CONTROL_VIA_POST: &str = "FA-REF-101";
    pub const CLASS_NOT_IMPLEMENTED: &str = "FA-REF-102";
    pub const CASE_MEMBERSHIP: &str = "FA-REF-178";
    pub const RECLASSIFICATION_SHAPE: &str = "FA-REF-185";
    pub const RUN_NOT_OPEN: &str = "FA-REF-130";
    pub const TIE_OUT_MISMATCH: &str = "FA-REF-131";
    pub const MIGRATION_OUTSIDE_RUN: &str = "FA-REF-132";
    pub const TICK_UNCORROBORATED: &str = "FA-REF-144";
    pub const DRAFT_UNKNOWN: &str = "FA-REF-157";
    pub const DRAFT_NOT_OPEN: &str = "FA-REF-158";
    pub const PLAN_INVALIDATED: &str = "FA-REF-034";
}

/// Independent copy of `registries/limits.toml` `max_tick_utc_ns` (`i64::MAX`).
pub const MAX_TICK_UTC_NS: u64 = 9_223_372_036_854_775_807;
/// Independent copy of `registries/limits.toml` `max_clock_skew_ns` (`366` days).
pub const MAX_CLOCK_SKEW_NS: u64 = 31_622_400_000_000_000;

/// A draft's state (plan §15.2, fa-s7x).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DraftState {
    Open,
    Promoted,
    Discarded,
}

/// A draft as the oracle keeps it: its owner, its planned intents in order,
/// its state, and the journal indices its promotion posted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    pub owner: String,
    pub intents: Vec<Intent>,
    pub state: DraftState,
    pub promoted: Vec<usize>,
    /// The principals whose Discard is recorded (a retry by one is its
    /// recorded outcome).
    pub discarded_by: Vec<String>,
}

/// The outcome of a draft act (plan §15.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DraftVerdict {
    /// A new record was journaled.
    Recorded,
    /// The identical record was already journaled; nothing was written.
    AlreadyRecorded,
    /// The draft's intents posted as one batch at these journal indices
    /// (`already` for the recorded promotion's retry).
    Promoted { indices: Vec<usize>, already: bool },
    /// Nothing was recorded. `member` names a promotion member that refused.
    Refused {
        member: Option<usize>,
        code: &'static str,
    },
}

/// The outcome of an atomic batch (plan §5.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchVerdict {
    /// Every member posted, in order: their journal indices.
    Posted { indices: Vec<usize> },
    /// An identical retry: the recorded members' journal indices.
    Recorded { indices: Vec<usize> },
    /// Nothing was recorded. `member` names the member that refused, or is
    /// `None` when the batch key itself conflicts.
    Refused {
        member: Option<usize>,
        code: &'static str,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A new entry, with its index in the oracle's journal.
    Posted {
        index: usize,
        period: String,
    },
    /// The same intent was already recorded; the earlier entry's index.
    Recorded {
        index: usize,
    },
    Refused {
        code: &'static str,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub class: String,
    pub date: DateDay,
    pub period: String,
    pub legs: Vec<Leg>,
    pub key: Vec<u8>,
    pub reverses: Option<usize>,
    /// For a Resolution: the journal index of the pending entry it resolves.
    pub resolves: Option<usize>,
    pub settles: Vec<Settle>,
    /// A `Migration` chunk: the run it stages into (plan §8.6). Selected by
    /// a fold only where that run is finalized at the fold's coordinate.
    pub run: Option<usize>,
}

/// A migration run's declared legacy trial balance (plan §8.6): lines
/// `(account, unit, net in debit sign)`, strictly ascending by
/// `(account, unit)`, never zero; opened on the first day of a fiscal year.
/// `full_detail` set: a `FullDetail` run (ruling 3675). Otherwise `periods`
/// empty: an `OpeningOnly` run; non-empty: a `PeriodBalances` run, naming
/// every elapsed period before the book's opening date with its trial
/// balance as of the period's end (cumulative).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSpec {
    pub key: String,
    pub opening_date: DateDay,
    pub lines: TrialBalance,
    pub periods: Vec<(String, TrialBalance)>,
    pub full_detail: Option<FullDetailSpec>,
}

/// A legacy trial balance: lines `(account, unit, net in debit sign)`.
pub type TrialBalance = Vec<(String, u32, i128)>;

/// A `FullDetail` run's own declarations: the trial balance at the start of
/// its first declared period (empty from legacy inception), and whether its
/// detail is the sole source of the opening balances.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullDetailSpec {
    pub detail_base: TrialBalance,
    pub sole: bool,
}

impl RunSpec {
    /// Whether this run declares `period` as one of its elapsed periods.
    #[must_use]
    pub fn declares(&self, period: &str) -> bool {
        self.periods.iter().any(|(code, _)| code == period)
    }

    /// A sole-source `FullDetail` run.
    #[must_use]
    pub fn sole(&self) -> bool {
        self.full_detail.as_ref().is_some_and(|f| f.sole)
    }

    /// The first day from which this run's chunks count in folds: a
    /// non-sole `FullDetail` run's opening date; `None` otherwise.
    #[must_use]
    pub fn counts_from(&self) -> Option<DateDay> {
        self.full_detail
            .as_ref()
            .is_some_and(|f| !f.sole)
            .then_some(self.opening_date)
    }
}

/// One declared trial balance's own law, as the oracle states it: 1..=4096
/// lines, accounts 1..=64 bytes, never zero, strictly ascending, balanced
/// per unit.
fn check_trial_balance(lines: &[(String, u32, i128)]) -> Result<(), &'static str> {
    if lines.is_empty() {
        return Err(code::STRUCTURE);
    }
    check_balance_lines(lines)
}

/// [`check_trial_balance`] without the non-empty rule (a FullDetail
/// cumulative balance or base may net to nothing).
fn check_balance_lines(lines: &[(String, u32, i128)]) -> Result<(), &'static str> {
    if lines.len() > 4096 {
        return Err(code::STRUCTURE);
    }
    if lines
        .iter()
        .any(|(account, _, m)| account.is_empty() || account.len() > 64 || *m == 0)
    {
        return Err(code::STRUCTURE);
    }
    if !lines
        .windows(2)
        .all(|w| (&w[0].0, w[0].1) < (&w[1].0, w[1].1))
    {
        return Err(code::STRUCTURE);
    }
    let mut per_unit: BTreeMap<u32, Int> = BTreeMap::new();
    for (_, unit, m) in lines {
        let e = per_unit.entry(*unit).or_insert_with(Int::zero);
        *e = e.add(&Int::from_i128(*m));
    }
    if per_unit.values().any(|net| !net.is_zero()) {
        return Err(code::TIE_OUT_MISMATCH);
    }
    Ok(())
}

/// A run's lifecycle (plan §8.6): `Open → Finalized | Abandoned`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Open,
    Finalized,
    Abandoned,
}

/// A known-at coordinate of this model: how many journal entries and how
/// many run controls (Open, Finalize, Abandon) had been accepted. A
/// Finalize adds no entry, so the entry count alone cannot say whether a
/// chunk was visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Known {
    pub entries: usize,
    pub controls: usize,
}

#[derive(Clone, Debug)]
struct Run {
    spec: RunSpec,
    state: RunState,
    /// Journal indices of the run's chunks, in acceptance order.
    chunks: Vec<usize>,
    /// The run-control index of the Finalize that activated the run.
    finalized: Option<usize>,
}

/// What a run control's identity binds.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ControlContent {
    Open(RunSpec),
    Transition {
        run: usize,
        finalize: bool,
        chunks: usize,
    },
}

/// The semantic content an identity binds (what the kernel's
/// `proposal_digest` covers, minus fields this model does not carry).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Content {
    class: String,
    date: DateDay,
    discriminator: Option<String>,
    legs: Vec<Leg>,
    reverses: Option<usize>,
    supersession_reason: u16,
    resolves: Option<Resolve>,
    settles: Vec<Settle>,
    key: Vec<u8>,
    /// A balancing request's leg: the identity binds the request (its legs
    /// at the requested amount, and which leg balances), not what moved.
    balancing: Option<u16>,
    /// A timed hold's `timeout_ns` (the deadline's anchor is not content:
    /// it is derived from the hold's journal position).
    timeout: Option<u64>,
    /// Minted by the expiry sweep: never the content of a submitted intent.
    by_sweep: bool,
    /// An Adjusting entry's scheduled reversal date (plan §7.6): the
    /// proposal digest covers it.
    auto_reverse: Option<DateDay>,
}

impl Content {
    fn of(
        i: &Intent,
        balancing: Option<u16>,
        timeout: Option<u64>,
        auto_reverse: Option<DateDay>,
    ) -> Self {
        Self {
            class: i.class.clone(),
            date: i.date,
            discriminator: i.discriminator.clone(),
            legs: i.legs.clone(),
            reverses: i.reverses,
            supersession_reason: if i.reverses.is_some() {
                i.supersession_reason
            } else {
                0
            },
            resolves: i.resolves.clone(),
            settles: i.settles.clone(),
            key: i.key.clone(),
            balancing,
            timeout,
            by_sweep: false,
            auto_reverse,
        }
    }
}

/// A scheduled reversal in the model (plan §7.6): its date, the period that
/// date lies in, and whether a manual reversal cancelled it by lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleState {
    pub reverse_on: DateDay,
    pub period: String,
    pub cancelled: bool,
}

/// Where a schedule whose date the latest tick has reached stands (the
/// kernel's `ReversalStatus`, without the reasons).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    /// The period admits a Reversal under the scheduler's `post`.
    Due,
    /// The period does not exist yet or is Future.
    Waiting,
    /// The Reversal row refuses the scheduler, or the target has live
    /// applications.
    Blocked,
}

/// One scheduled-reversal sweep batch in the model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReversalSweep {
    pub tick: u64,
    /// `(target index, its scheduled reversal's index)`.
    pub minted: Vec<(usize, usize)>,
    /// Targets examined and not minted (period row, applications, limits).
    pub blocked: Vec<usize>,
    /// Reached schedules left for the next batch under this tick.
    pub remaining: usize,
}

/// One expiry-sweep batch in the model (plan §5.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepBatch {
    /// The tick (its observed instant) the batch ran under.
    pub tick: u64,
    /// `(hold index, its Expires resolution's index)`, in journal order.
    pub expired: Vec<(usize, usize)>,
    /// Holds due under this tick left for the next batch.
    pub remaining_due: usize,
}

/// One cell of the oracle's fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    pub debits: Int,
    pub credits: Int,
    pub entry_count: u64,
}

/// A capability as plan §14.2 states it, in plain values: who holds it,
/// under which profile, the ops it carries, the books it is confined to
/// (`None`: no `books` caveat), and its expiry bound (an admission point
/// `at >= expires_at` is expired). `token` names it for revocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    pub token: u64,
    pub holder: u128,
    pub profile: String,
    pub ops: Vec<String>,
    pub books: Option<Vec<u128>>,
    pub expires_at: Option<u64>,
}

/// An approval as recorded: the approver, profile and op, and the security
/// policy epoch that was current when it was recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    pub approval: sod::Approval,
    pub epoch: u64,
}

/// An account's `(opened, closed, promoted_on)` days (`fa-up7`).
type Effectivity = (Option<DateDay>, Option<DateDay>, Option<DateDay>);

#[derive(Clone)]
pub struct Oracle {
    calendar: FiscalCalendar,
    accounts: BTreeMap<String, Account>,
    /// Period code → (definition, state). Only created periods exist.
    periods: BTreeMap<String, (PeriodDef, PeriodState)>,
    /// The book's opening date (plan §7.2): a Normal period ending on or
    /// before it is born Historical and Locked.
    opening_date: Option<DateDay>,
    journal: Vec<Entry>,
    /// Key → (journal index, content) for key-identified entries.
    keys: BTreeMap<Vec<u8>, (usize, Content)>,
    /// Reversed target index → (reversal index, content).
    reversed: BTreeMap<usize, (usize, Content)>,
    /// Resolved pending index → (resolution index, content).
    resolved: BTreeMap<usize, (usize, Content)>,
    /// Limited account code → its limit.
    limits: BTreeMap<String, Limit>,
    /// Committed TimeEvidence ticks (plan §7.1a).
    ticks: Vec<u64>,
    /// Corroboration (`monotonic_ok`) parallel to `ticks` (fa-psz).
    tick_corroborated: Vec<bool>,
    /// Timed hold index → its deadline (the latest tick when it posted, plus
    /// its timeout).
    deadlines: BTreeMap<usize, u64>,
    /// The sweep's position: (tick index, last hold index it expired).
    cursor: Option<(usize, usize)>,
    /// The book declares a `time_zone_policy` (Utc: a tick's civil date is
    /// its UTC day).
    tz_declared: bool,
    /// Scheduled target index → its schedule.
    schedules: BTreeMap<usize, ScheduleState>,
    /// The book's declared legal entities (plan §4.1 `Book.entities`).
    entities: Vec<String>,
    /// Registered unit ids: units.toml, which genesis journals as the
    /// book's unit table (plan §4.4).
    units: BTreeSet<u32>,
    /// Registered statistical quantity unit ids (`balance_policy = "single_sided"`).
    single_sided_units: BTreeSet<u32>,
    /// The reversal sweep's position: (tick index, last target examined).
    schedule_cursor: Option<(usize, usize)>,
    /// Migration runs, by opening order (plan §8.6).
    runs: Vec<Run>,
    /// Run key → run index.
    run_keys: BTreeMap<String, usize>,
    /// Every accepted run control, as the journal length when it was
    /// accepted (the model's control timeline).
    run_controls: Vec<usize>,
    /// Control idempotency key → (content, run).
    control_keys: BTreeMap<Vec<u8>, (ControlContent, usize)>,
    /// (run, key) → (journal index, content) for Migration chunks.
    migration_keys: BTreeMap<(usize, Vec<u8>), (usize, Content)>,
    classes: EntryClasses,
    sod: SodPolicy,
    /// Batch key -> (the recorded request, its members' journal indices)
    /// (plan §5.9 IntentOutcome).
    batches: BTreeMap<Vec<u8>, (Vec<Intent>, Vec<usize>)>,
    /// Drafts by name (plan §15.2, fa-s7x).
    drafts: BTreeMap<String, Draft>,
    /// Tokens of revoked capabilities.
    revoked: BTreeSet<u64>,
    /// The security policy epoch: the number of activations so far.
    epoch: u64,
    /// True only while the model mints its own scheduled reversal: the one
    /// path that may cite ScheduledAccrualReversal (fa-cvg).
    minting_scheduled: bool,
    /// The target of the Reclassification [`Oracle::reclassify`] is posting
    /// (plan §8.2 `Reclassifies`, fa-xvba); `None` on every other path.
    reclassifying: Option<usize>,
    /// Recorded reclassifications: target → its reclassifications, and each
    /// reclassification's target.
    reclassifications: BTreeMap<usize, Vec<usize>>,
    reclassification_targets: BTreeMap<usize, usize>,
    /// Optional registered account type tag per account code (`registries/account_types.toml`,
    /// `fa-a57x`, `fa-xjlb`): defaults to monetary (`1`) when unset; `6` (`Memo`),
    /// `7` (`Statistical`), and `8` (`OffBalance`) sit outside the monetary balance law
    /// and trial-balance footing.
    account_types: BTreeMap<String, u8>,
    /// Optional `(opened, closed, promoted_on)` per account code (`fa-up7`, `FA-INV-01.account-effective`).
    account_effectivity: BTreeMap<String, Effectivity>,
    /// Optional parent code per account code (`fa-up7`).
    account_parents: BTreeMap<String, String>,
}

impl Oracle {
    pub fn new(calendar: FiscalCalendar) -> Self {
        let classes = EntryClasses::embedded().expect("entry_classes.toml");
        let matrix = Admissibility::embedded(&classes).expect("admissibility.toml");
        let sod = SodPolicy::embedded(&classes, &matrix).expect("sod_policy.toml");
        let unit_rows = fa_registry::units_embedded().expect("units.toml");
        let units = unit_rows.iter().map(|u| u.id).collect();
        let single_sided_units = unit_rows
            .into_iter()
            .filter(|u| u.balance_policy == "single_sided")
            .map(|u| u.id)
            .collect();
        Self {
            calendar,
            accounts: BTreeMap::new(),
            periods: BTreeMap::new(),
            opening_date: None,
            journal: Vec::new(),
            keys: BTreeMap::new(),
            reversed: BTreeMap::new(),
            resolved: BTreeMap::new(),
            limits: BTreeMap::new(),
            ticks: Vec::new(),
            tick_corroborated: Vec::new(),
            deadlines: BTreeMap::new(),
            cursor: None,
            tz_declared: false,
            schedules: BTreeMap::new(),
            entities: Vec::new(),
            units,
            single_sided_units,
            schedule_cursor: None,
            runs: Vec::new(),
            run_keys: BTreeMap::new(),
            run_controls: Vec::new(),
            control_keys: BTreeMap::new(),
            migration_keys: BTreeMap::new(),
            classes,
            sod,
            batches: BTreeMap::new(),
            drafts: BTreeMap::new(),
            revoked: BTreeSet::new(),
            epoch: 0,
            minting_scheduled: false,
            reclassifying: None,
            reclassifications: BTreeMap::new(),
            reclassification_targets: BTreeMap::new(),
            account_types: BTreeMap::new(),
            account_effectivity: BTreeMap::new(),
            account_parents: BTreeMap::new(),
        }
    }

    /// Record the registered account type tag (`1..=8`) for `code` (`fa-a57x`, `fa-xjlb`).
    pub fn set_account_type(&mut self, code: &str, account_type: u8) {
        self.account_types.insert(code.to_string(), account_type);
    }

    /// Whether `code` is a `Memo` (`6`), `Statistical` (`7`), or `OffBalance` (`8`)
    /// account (`fa-a57x`, `fa-xjlb`).
    #[must_use]
    pub fn is_memo_account(&self, code: &str) -> bool {
        matches!(self.account_types.get(code).copied(), Some(6..=8))
    }

    /// Whether `code` is a balanced memo account (`Memo` = `6`, `OffBalance` = `8`).
    #[must_use]
    pub fn is_balanced_memo_account(&self, code: &str) -> bool {
        matches!(self.account_types.get(code).copied(), Some(6 | 8))
    }

    /// Whether `code` is a `Statistical` (`7`) account.
    #[must_use]
    pub fn is_statistical_account(&self, code: &str) -> bool {
        matches!(self.account_types.get(code).copied(), Some(7))
    }

    /// Whether `unit` is a statistical quantity unit (`balance_policy = "single_sided"`).
    #[must_use]
    pub fn is_single_sided_unit(&self, unit: u32) -> bool {
        self.single_sided_units.contains(&unit)
    }

    /// The book declares `time_zone_policy = Utc` at genesis (plan §7.7).
    /// The book declares these legal entities at genesis (plan §4.1).
    pub fn declare_entities(&mut self, codes: &[&str]) {
        self.entities = codes.iter().map(|c| (*c).to_string()).collect();
    }

    /// The entity a leg belongs to: its own, the book's single entity when
    /// it names none, `None` in a book declaring none.
    fn entity_of(&self, l: &Leg) -> Option<String> {
        l.entity.clone().or_else(|| match self.entities.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        })
    }

    /// The literal per-entity fold of one period (plan §5.3 by legal
    /// entity): posted legs of every non-Pending entry effective in it,
    /// keyed `(account, unit, entity)`.
    #[must_use]
    pub fn fold_by_entity(&self, period: &str) -> BTreeMap<(String, u32, Option<String>), Cell> {
        let mut cells: BTreeMap<(String, u32, Option<String>), Cell> = BTreeMap::new();
        let known = self.known();
        for e in self
            .journal
            .iter()
            .filter(|e| e.period == period && e.class != "Pending" && self.visible(e, known))
        {
            let mut touched: Vec<(String, u32, Option<String>)> = Vec::new();
            for l in &e.legs {
                let key = (l.account.clone(), l.unit, self.entity_of(l));
                let c = cells.entry(key.clone()).or_insert(Cell {
                    debits: Int::zero(),
                    credits: Int::zero(),
                    entry_count: 0,
                });
                let m = Int::from_i128(l.mantissa);
                match l.side {
                    Side::Debit => c.debits = c.debits.add(&m),
                    Side::Credit => c.credits = c.credits.add(&m),
                }
                if !touched.contains(&key) {
                    touched.push(key);
                }
            }
            for key in touched {
                if let Some(c) = cells.get_mut(&key) {
                    c.entry_count += 1;
                }
            }
        }
        cells
    }

    pub fn declare_time_zone(&mut self) {
        self.tz_declared = true;
    }

    pub fn add_account(&mut self, a: Account) {
        self.accounts.insert(a.code.clone(), a);
    }

    /// Set the half-open `[opened, closed)` effective interval for `code` (`fa-up7`).
    pub fn set_account_effectivity(
        &mut self,
        code_str: &str,
        opened: Option<DateDay>,
        closed: Option<DateDay>,
    ) {
        let promoted = self
            .account_effectivity
            .get(code_str)
            .and_then(|(_, _, p)| *p);
        self.account_effectivity
            .insert(code_str.to_string(), (opened, closed, promoted));
    }

    /// Open a new account in the reference oracle (`fa-up7`, plan §5.6).
    pub fn open_account(
        &mut self,
        a: Account,
        parent: Option<&str>,
        opened: DateDay,
        closed: Option<DateDay>,
    ) -> Result<(), &'static str> {
        if a.code.is_empty() || a.code.len() > 64 {
            return Err(code::STRUCTURE);
        }
        if closed.is_some_and(|c| opened >= c) {
            return Err(code::STRUCTURE);
        }
        if self.accounts.contains_key(&a.code) {
            return Err(code::STRUCTURE);
        }
        if let Some(unit) = a.unit
            && !self.units.contains(&unit)
        {
            return Err(code::UNIT_UNREGISTERED);
        }
        if let Some(p) = parent {
            let Some(parent_acc) = self.accounts.get(p) else {
                return Err(code::UNKNOWN_ACCOUNT);
            };
            if parent_acc.is_leaf {
                return Err(code::NOT_A_LEAF);
            }
            self.account_parents.insert(a.code.clone(), p.to_string());
        }
        let code_str = a.code.clone();
        self.accounts.insert(code_str.clone(), a);
        self.account_effectivity
            .insert(code_str, (Some(opened), closed, None));
        Ok(())
    }

    /// Close an account at `closed_on` in the reference oracle (`fa-up7`, plan §5.6).
    pub fn close_account(
        &mut self,
        code_str: &str,
        closed_on: DateDay,
    ) -> Result<(), &'static str> {
        if code_str.is_empty() || code_str.len() > 64 {
            return Err(code::STRUCTURE);
        }
        if !self.accounts.contains_key(code_str) {
            return Err(code::UNKNOWN_ACCOUNT);
        }
        let (opened, existing_close, promoted) = self
            .account_effectivity
            .get(code_str)
            .copied()
            .unwrap_or((None, None, None));
        if existing_close.is_some() {
            return Err(code::NOT_A_LEAF);
        }
        if opened.is_some_and(|o| o >= closed_on) || promoted.is_some_and(|p| p > closed_on) {
            return Err(code::STRUCTURE);
        }
        let known = self.known();
        let mut net_balances: BTreeMap<u32, Int> = BTreeMap::new();
        for (idx, e) in self.journal.iter().enumerate() {
            let touches = e.legs.iter().any(|l| l.account == code_str);
            if !touches {
                continue;
            }
            if e.date >= closed_on {
                return Err(code::NOT_A_LEAF);
            }
            if e.class == "Pending" && !self.resolved.contains_key(&idx) {
                return Err(code::NOT_A_LEAF);
            }
            if e.class == "Pending" || !self.visible(e, known) {
                continue;
            }
            for l in &e.legs {
                if l.account != code_str {
                    continue;
                }
                let signed = match l.side {
                    Side::Debit => Int::from_i128(l.mantissa),
                    Side::Credit => Int::from_i128(-l.mantissa),
                };
                let bal = net_balances.entry(l.unit).or_insert_with(Int::zero);
                *bal = bal.add(&signed);
            }
        }
        if net_balances.values().any(|b| !b.is_zero()) {
            return Err(code::NOT_A_LEAF);
        }
        self.account_effectivity
            .insert(code_str.to_string(), (opened, Some(closed_on), promoted));
        Ok(())
    }

    /// Promote a leaf account to a summary account at `promotion_date` in the
    /// reference oracle (`fa-up7`, plan §5.6).
    pub fn promote_to_summary(
        &mut self,
        code_str: &str,
        promotion_date: DateDay,
    ) -> Result<(), &'static str> {
        if code_str.is_empty() || code_str.len() > 64 {
            return Err(code::STRUCTURE);
        }
        let Some(acc) = self.accounts.get(code_str) else {
            return Err(code::UNKNOWN_ACCOUNT);
        };
        if !acc.is_leaf {
            return Err(code::NOT_A_LEAF);
        }
        if self.limits.contains_key(code_str) {
            return Err(code::STRUCTURE);
        }
        let (opened, closed, promoted) = self
            .account_effectivity
            .get(code_str)
            .copied()
            .unwrap_or((None, None, None));
        if promoted.is_some() {
            return Err(code::NOT_A_LEAF);
        }
        if opened.is_some_and(|o| o > promotion_date) || closed.is_some_and(|c| promotion_date > c)
        {
            return Err(code::STRUCTURE);
        }
        for e in &self.journal {
            if e.date > promotion_date && e.legs.iter().any(|l| l.account == code_str) {
                return Err(code::NOT_A_LEAF);
            }
        }
        if let Some(acc_mut) = self.accounts.get_mut(code_str) {
            acc_mut.is_leaf = false;
        }
        self.account_effectivity
            .insert(code_str.to_string(), (opened, closed, Some(promotion_date)));
        Ok(())
    }

    /// Give an account a balance limit (plan §5.4); the chart declares it.
    pub fn set_limit(&mut self, code: &str, limit: Limit) {
        self.limits.insert(code.to_string(), limit);
    }

    /// Declare the book's opening date (genesis, plan §7.2), before any
    /// period is created.
    pub fn set_opening_date(&mut self, day: DateDay) {
        self.opening_date = Some(day);
    }

    /// Create a fiscal year's periods: `Future`, except a Normal period that
    /// ends on or before the book's opening date, which is born Historical
    /// and Locked.
    pub fn create_periods(&mut self, fy: i32) {
        for mut p in self.calendar.periods_for_year(fy).expect("periods") {
            let state = match self.opening_date {
                Some(day) if p.kind == PeriodKind::Normal && p.end <= day => {
                    p.kind = PeriodKind::Historical;
                    PeriodState::Locked
                }
                _ if admissibility::pre_opening_governs(p.kind, p.end, self.opening_date) => {
                    admissibility::PRE_OPENING_BORN
                }
                _ => PeriodState::Future,
            };
            self.periods.insert(p.code.clone(), (p, state));
        }
    }

    pub fn period_state(&self, code: &str) -> Option<PeriodState> {
        self.periods.get(code).map(|(_, s)| *s)
    }

    pub fn entry(&self, index: usize) -> Option<&Entry> {
        self.journal.get(index)
    }

    /// Revoke the capability named `token` (plan §14.2: a journaled
    /// `CapabilityEvent`): every later act under it is refused.
    pub fn revoke(&mut self, token: u64) {
        self.revoked.insert(token);
    }

    /// Activate a policy: the epoch advances, so every approval recorded
    /// before it is stale.
    pub fn activate_policy(&mut self) {
        self.epoch += 1;
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The effective date the period law gives the `PeriodControl` entry
    /// of `t` on period `code` (plan §7.3, fa-87r), read from the oracle's
    /// own period table: an Open is dated on the period's first day, every
    /// other transition on its last day (the day before its exclusive end).
    /// `None` for a period the oracle does not hold.
    #[must_use]
    pub fn transition_date(&self, code: &str, t: PeriodTransition) -> Option<DateDay> {
        let (def, _) = self.periods.get(code)?;
        Some(match t {
            PeriodTransition::Open => def.start,
            _ => DateDay(def.end.0 - 1),
        })
    }

    /// [`Oracle::transition`] for a principal giving `reason` (plan §7.3,
    /// fa-cvg): once the period law admits the transition, its reason must be
    /// registered in `reason_codes.toml`, under `period_reopen` for a reopen
    /// and `period_control` for every other transition; zero never is.
    pub fn transition_with_reason(
        &mut self,
        code: &str,
        t: PeriodTransition,
        reason: u16,
    ) -> Result<(PeriodState, PeriodState), &'static str> {
        if let Some((def, from)) = self.periods.get(code)
            && !admissibility::kind_has_restriction(def.kind)
            && !admissibility::pre_opening_governs(def.kind, def.end, self.opening_date)
            && admissibility::oracle_transition(*from, t).is_ok()
        {
            let scope = match t {
                PeriodTransition::Reopen { .. } => "period_reopen",
                _ => "period_control",
            };
            let reasons =
                fa_registry::reason_codes::ReasonCodes::embedded().expect("reason registry");
            if !reasons
                .rows
                .iter()
                .any(|r| r.scope == scope && r.code == reason)
            {
                return Err(code::PERIOD_REASON);
            }
        }
        self.transition(code, t)
    }

    /// [`Oracle::transition_minting`] without its mint lists.
    pub fn transition(
        &mut self,
        code: &str,
        t: PeriodTransition,
    ) -> Result<(PeriodState, PeriodState), &'static str> {
        self.transition_minting(code, t)
            .map(|(from, to, _, _)| (from, to))
    }

    /// A transition, and for `Open` the scheduled reversals dated in the
    /// period whose date the latest tick has reached, minted in it (plan
    /// §7.6 rule (b)): `(from, to, minted (target, reversal), blocked)`.
    /// The period law as the walks drive it: an authority holding `close`
    /// and `reopen`, with as many distinct Human approvals as the
    /// transition's rule asks for (the differential's kernel side records
    /// exactly those). A case-bound reopen still refuses: its rule names an
    /// exclusion no case object can decide yet.
    #[allow(clippy::type_complexity)]
    pub fn transition_minting(
        &mut self,
        code: &str,
        t: PeriodTransition,
    ) -> Result<(PeriodState, PeriodState, Vec<(usize, usize)>, Vec<usize>), &'static str> {
        const PREPARER: u128 = 1;
        let full = Authority {
            token: u64::MAX,
            holder: PREPARER,
            profile: "Human".into(),
            ops: vec!["close".into(), "reopen".into()],
            books: None,
            expires_at: None,
        };
        let mut approvals = Vec::new();
        if let Some((_, from)) = self.periods.get(code)
            && admissibility::oracle_transition(*from, t).is_ok()
        {
            let req = self.period_rule(*from, t);
            for i in 0..req.approvers {
                approvals.push(Recorded {
                    approval: sod::Approval {
                        principal: PREPARER + 1 + u128::from(i),
                        profile: "Human".into(),
                        op: req.approver_op.clone(),
                    },
                    epoch: self.epoch,
                });
            }
        }
        self.transition_minting_under(code, t, PREPARER, &full, 0, 0, &approvals)
    }

    /// A period transition by `actor` under `authority` at admission point
    /// `at` on book `book`, citing `approvals` (plan §14, Appendix C
    /// PeriodControl). The authority is judged before the period is looked
    /// at: holder, Agent, op (`reopen` for a reopen, `close` for every other
    /// transition: §14.2 has no `open` op), books, expiry, revocation. Then
    /// the state machine; then each approval's epoch; then the SoD rule for
    /// (PeriodControl, from, transition).
    #[allow(clippy::too_many_arguments)]
    pub fn transition_under(
        &mut self,
        code: &str,
        t: PeriodTransition,
        actor: u128,
        authority: &Authority,
        book: u128,
        at: u64,
        approvals: &[Recorded],
    ) -> Result<(PeriodState, PeriodState), &'static str> {
        self.transition_minting_under(code, t, actor, authority, book, at, approvals)
            .map(|(from, to, _, _)| (from, to))
    }

    /// [`Oracle::transition_under`] with the `Open` mints of
    /// [`Oracle::transition_minting`].
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn transition_minting_under(
        &mut self,
        code: &str,
        t: PeriodTransition,
        actor: u128,
        authority: &Authority,
        book: u128,
        at: u64,
        approvals: &[Recorded],
    ) -> Result<(PeriodState, PeriodState, Vec<(usize, usize)>, Vec<usize>), &'static str> {
        if authority.holder != actor {
            return Err(code::CAPABILITY);
        }
        if authority.profile == "Agent" {
            return Err(code::AGENT_TRUNK);
        }
        let op = match t {
            PeriodTransition::Reopen { .. } => "reopen",
            _ => "close",
        };
        if !authority.ops.iter().any(|o| o == op) {
            return Err(code::CAPABILITY);
        }
        if let Some(books) = &authority.books
            && !books.contains(&book)
        {
            return Err(code::CAPABILITY);
        }
        if let Some(bound) = authority.expires_at
            && at >= bound
        {
            return Err(code::EXPIRED);
        }
        if self.revoked.contains(&authority.token) {
            return Err(code::REVOKED);
        }
        let Some((def, state)) = self.periods.get(code) else {
            return Err(code::PERIOD_UNKNOWN);
        };
        // A Historical period or pre-opening special period refuses every transition.
        if admissibility::kind_has_restriction(def.kind) {
            return Err(code::TRANSITION);
        }
        if admissibility::pre_opening_governs(def.kind, def.end, self.opening_date) {
            return Err(code::TRANSITION);
        }
        let from = *state;
        let to = admissibility::oracle_transition(from, t).map_err(|()| code::TRANSITION)?;
        if approvals.iter().any(|a| a.epoch != self.epoch) {
            return Err(code::STALE_APPROVAL);
        }
        let req = self.period_rule(from, t);
        let literal: Vec<sod::Approval> = approvals.iter().map(|a| a.approval.clone()).collect();
        if let Some((refusal, _kind)) = sod::verdict(req, 0, actor, &authority.profile, &literal) {
            return Err(refusal);
        }
        if let Some((_, state)) = self.periods.get_mut(code) {
            *state = to;
        }
        let (mut minted, mut blocked) = (Vec::new(), Vec::new());
        if t == PeriodTransition::Open
            && self.tick_corroborated.last() == Some(&true)
            && let Some(today) = self.today()
        {
            let due: Vec<usize> = self
                .schedules
                .iter()
                .filter(|(target, s)| {
                    s.period == code && s.reverse_on <= today && self.schedule_live(**target)
                })
                .map(|(target, _)| *target)
                .take(8190)
                .collect();
            for target in due {
                match self.mint_scheduled(target) {
                    Some(index) => minted.push((target, index)),
                    None => blocked.push(target),
                }
            }
        }
        Ok((from, to, minted, blocked))
    }

    /// The `sod_policy.toml` row for `(PeriodControl, from, transition)`,
    /// found by a literal scan; the default requirement when none matches.
    fn period_rule(&self, from: PeriodState, t: PeriodTransition) -> &SodRequirement {
        let name = match t {
            PeriodTransition::Open => "Open",
            PeriodTransition::SoftClose => "SoftClose",
            PeriodTransition::Close => "Close",
            PeriodTransition::Lock => "Lock",
            PeriodTransition::Reopen { .. } => "Reopen",
        };
        for rule in &self.sod.rules {
            if rule.key.class == "PeriodControl"
                && rule.key.state == Some(from)
                && rule.key.disposition.is_none()
                && rule.key.transition.as_deref() == Some(name)
            {
                return &rule.requirement;
            }
        }
        &self.sod.default
    }

    pub fn post(&mut self, intent: &Intent) -> Verdict {
        self.post_with_claims(intent, &PostClaims::default())
    }

    /// An atomic batch (plan §5.8), modelled literally: every member posts
    /// against the oracle as the earlier members leave it, and a refusal
    /// anywhere leaves the oracle exactly as it was. The batch key names its
    /// outcome (plan §5.9): an identical retry returns the recorded indices,
    /// any other request under the key is an idempotency conflict, and a
    /// member whose identity is already recorded refuses the batch.
    pub fn post_batch(&mut self, key: &[u8], members: &[Intent]) -> BatchVerdict {
        if let Some((request, indices)) = self.batches.get(key) {
            return if request.as_slice() == members {
                BatchVerdict::Recorded {
                    indices: indices.clone(),
                }
            } else {
                BatchVerdict::Refused {
                    member: None,
                    code: code::IDEMPOTENCY_CONFLICT,
                }
            };
        }
        let mut trial = self.clone();
        let mut indices = Vec::with_capacity(members.len());
        for (i, intent) in members.iter().enumerate() {
            match trial.post(intent) {
                Verdict::Posted { index, .. } => indices.push(index),
                Verdict::Recorded { .. } => {
                    return BatchVerdict::Refused {
                        member: Some(i),
                        code: code::IDEMPOTENCY_CONFLICT,
                    };
                }
                Verdict::Refused { code } => {
                    return BatchVerdict::Refused {
                        member: Some(i),
                        code,
                    };
                }
            }
        }
        trial
            .batches
            .insert(key.to_vec(), (members.to_vec(), indices.clone()));
        *self = trial;
        BatchVerdict::Posted { indices }
    }

    /// The draft `name`, if opened.
    #[must_use]
    pub fn draft(&self, name: &str) -> Option<&Draft> {
        self.drafts.get(name)
    }

    /// Open the draft `name` for `owner` (plan §15.2). One draft per name:
    /// the owner's identical retry is its record; anyone else's is a
    /// conflict.
    pub fn open_draft(&mut self, name: &str, owner: &str) -> DraftVerdict {
        match self.drafts.get(name) {
            Some(d) if d.owner == owner => DraftVerdict::AlreadyRecorded,
            Some(_) => DraftVerdict::Refused {
                member: None,
                code: code::IDEMPOTENCY_CONFLICT,
            },
            None => {
                self.drafts.insert(
                    name.to_string(),
                    Draft {
                        owner: owner.to_string(),
                        intents: Vec::new(),
                        state: DraftState::Open,
                        promoted: Vec::new(),
                        discarded_by: Vec::new(),
                    },
                );
                DraftVerdict::Recorded
            }
        }
    }

    /// Plan `intent` into the open draft `name` as `planner`: only its owner
    /// plans; one intent per key (the identical one is its record, even
    /// after the draft is promoted or discarded: FA-INV-09); and the intent
    /// must post on a copy of this book as it stands, which is then thrown
    /// away (the rehearsal writes nothing).
    pub fn plan_into_draft(&mut self, name: &str, planner: &str, intent: &Intent) -> DraftVerdict {
        let refused = |code| DraftVerdict::Refused { member: None, code };
        let Some(d) = self.drafts.get(name) else {
            return refused(code::DRAFT_UNKNOWN);
        };
        if d.owner != planner {
            return refused(code::CAPABILITY);
        }
        if let Some(planned) = d.intents.iter().find(|i| i.key == intent.key) {
            return if planned == intent {
                DraftVerdict::AlreadyRecorded
            } else {
                refused(code::IDEMPOTENCY_CONFLICT)
            };
        }
        if d.state != DraftState::Open {
            return refused(code::DRAFT_NOT_OPEN);
        }
        let mut rehearsal = self.clone();
        match rehearsal.post(intent) {
            Verdict::Posted { .. } => {}
            Verdict::Recorded { .. } => return refused(code::PLAN_INVALIDATED),
            Verdict::Refused { code } => return refused(code),
        }
        if let Some(d) = self.drafts.get_mut(name) {
            d.intents.push(intent.clone());
        }
        DraftVerdict::Recorded
    }

    /// Promote the draft `name` as `promoter` holding `ops`: the promoter
    /// holds `approve` and is not the owner; the planned intents post as one
    /// batch (this oracle's own batch law) against the book as it stands
    /// now; a promoted draft's retry is its recorded promotion.
    pub fn promote_draft(&mut self, name: &str, promoter: &str, ops: &[&str]) -> DraftVerdict {
        let refused = |code| DraftVerdict::Refused { member: None, code };
        if !ops.contains(&"approve") {
            return refused(code::CAPABILITY);
        }
        let Some(d) = self.drafts.get(name).cloned() else {
            return refused(code::DRAFT_UNKNOWN);
        };
        if d.owner == promoter {
            return refused(code::SOD);
        }
        match d.state {
            DraftState::Promoted => {
                return DraftVerdict::Promoted {
                    indices: d.promoted,
                    already: true,
                };
            }
            DraftState::Discarded => return refused(code::DRAFT_NOT_OPEN),
            DraftState::Open => {}
        }
        if d.intents.is_empty() {
            return refused(code::STRUCTURE);
        }
        let key = [b"fa:draft-promotion:".as_slice(), name.as_bytes()].concat();
        match self.post_batch(&key, &d.intents) {
            BatchVerdict::Posted { indices } => {
                if let Some(d) = self.drafts.get_mut(name) {
                    d.state = DraftState::Promoted;
                    d.promoted = indices.clone();
                }
                DraftVerdict::Promoted {
                    indices,
                    already: false,
                }
            }
            BatchVerdict::Recorded { .. } => refused(code::IDEMPOTENCY_CONFLICT),
            BatchVerdict::Refused { member, code } => DraftVerdict::Refused { member, code },
        }
    }

    /// Discard the draft `name` as `actor` holding `ops` (`post`, the
    /// `draft-discard` row's op): its owner, or a principal also holding
    /// `approve`; nothing is deleted.
    pub fn discard_draft(&mut self, name: &str, actor: &str, ops: &[&str]) -> DraftVerdict {
        let refused = |code| DraftVerdict::Refused { member: None, code };
        if !ops.contains(&"post") {
            return refused(code::CAPABILITY);
        }
        let Some(d) = self.drafts.get(name) else {
            return refused(code::DRAFT_UNKNOWN);
        };
        if d.owner != actor && !ops.contains(&"approve") {
            return refused(code::CAPABILITY);
        }
        if d.discarded_by.iter().any(|a| a == actor) {
            return DraftVerdict::AlreadyRecorded;
        }
        if d.state != DraftState::Open {
            return refused(code::DRAFT_NOT_OPEN);
        }
        if let Some(d) = self.drafts.get_mut(name) {
            d.state = DraftState::Discarded;
            d.discarded_by.push(actor.to_string());
        }
        DraftVerdict::Recorded
    }

    /// Post a caller's intent and envelope claims through the same model law.
    /// Refusing a claim does not consume an idempotency key or move a balance.
    pub fn post_with_claims(&mut self, intent: &Intent, claims: &PostClaims) -> Verdict {
        let v = self.post_inner(intent, None, None, None, None, claims);
        // A manual Reversal of a scheduled target cancels the schedule by
        // lineage (plan §7.6): it can never fire.
        if matches!(v, Verdict::Posted { .. })
            && intent.class == "Reversal"
            && let Some(s) = intent.reverses.and_then(|t| self.schedules.get_mut(&t))
        {
            s.cancelled = true;
        }
        v
    }

    /// An Adjusting entry that schedules its own reversal on `reverse_on`
    /// (plan §7.6, Appendix B `Accrue`/`Defer`).
    pub fn post_scheduled(&mut self, intent: &Intent, reverse_on: DateDay) -> Verdict {
        self.post_inner(
            intent,
            None,
            None,
            Some(reverse_on),
            None,
            &PostClaims::default(),
        )
    }

    /// The schedule of `target`, if it scheduled its reversal.
    #[must_use]
    pub fn schedule(&self, target: usize) -> Option<&ScheduleState> {
        self.schedules.get(&target)
    }

    /// The civil date of the latest tick (UTC), when the book declares its
    /// time-zone policy and has a tick.
    fn today(&self) -> Option<DateDay> {
        const NS_PER_DAY: u64 = 86_400_000_000_000;
        if !self.tz_declared {
            return None;
        }
        let ns = self.latest_tick()?;
        i32::try_from(ns / NS_PER_DAY).ok().map(DateDay)
    }

    /// Neither cancelled nor executed: its target is unreversed.
    fn schedule_live(&self, target: usize) -> bool {
        self.schedules.get(&target).is_some_and(|s| !s.cancelled)
            && !self.reversed.contains_key(&target)
    }

    /// Mint the scheduled reversal of `target` through the ordinary posting
    /// law with the scheduler's authority (`post` only): the exact swap,
    /// dated `reverse_on`. `Some(index)` when it posted; `None` when the
    /// period row, live applications, or availability refused it (blocked).
    fn mint_scheduled(&mut self, target: usize) -> Option<usize> {
        let s = self.schedules.get(&target)?.clone();
        let original = self.journal.get(target)?.clone();
        let intent = Intent {
            class: "Reversal".into(),
            date: s.reverse_on,
            discriminator: None,
            legs: original
                .legs
                .iter()
                .map(|l| Leg {
                    side: l.side.flipped(),
                    ..l.clone()
                })
                .collect(),
            key: b"scheduled".to_vec(),
            ops: vec!["post".into()],
            approvals: 0,
            reverses: Some(target),
            supersession_reason: 12,
            resolves: None,
            settles: Vec::new(),
        };
        self.minting_scheduled = true;
        let minted = self.post_inner(&intent, None, None, None, None, &PostClaims::default());
        self.minting_scheduled = false;
        match minted {
            Verdict::Posted { index, .. } => {
                if let Some((_, content)) = self.reversed.get_mut(&target) {
                    content.by_sweep = true;
                }
                Some(index)
            }
            _ => None,
        }
    }

    /// Every live schedule whose date the latest tick has reached, in target
    /// order, with where it stands (the kernel's `due_reversals`).
    #[must_use]
    pub fn reached_reversals(&self) -> Vec<(usize, Reached)> {
        let Some(today) = self.today() else {
            return Vec::new();
        };
        self.schedules
            .iter()
            .filter(|(target, s)| s.reverse_on <= today && self.schedule_live(**target))
            .map(|(target, s)| {
                let status = match self.period_state(&s.period) {
                    None | Some(PeriodState::Future) => Reached::Waiting,
                    Some(state) => {
                        match admissibility::decide_disposition("Reversal", state, false) {
                            Some(Decision::Admit) => Reached::Due,
                            Some(Decision::With { op, .. }) if op == "post" => Reached::Due,
                            _ => Reached::Blocked,
                        }
                    }
                };
                let live_applications =
                    (0..self.journal[*target].legs.len()).any(|i| self.applied_to(*target, i) != 0);
                let status = if status == Reached::Due && live_applications {
                    Reached::Blocked
                } else {
                    status
                };
                (*target, status)
            })
            .collect()
    }

    /// One scheduled-reversal sweep batch (plan §7.6 rule (a), §5.4 cursor
    /// discipline): up to `max_batch` reached schedules whose periods exist
    /// and are not Future, after the cursor when it belongs to the latest
    /// tick, each minted or blocked; then the cursor moves to the last.
    pub fn sweep_reversals_batch(
        &mut self,
        max_batch: usize,
    ) -> Result<Option<ReversalSweep>, &'static str> {
        if max_batch == 0 {
            return Err(code::STRUCTURE);
        }
        let Some(tick_index) = self.ticks.len().checked_sub(1) else {
            return Ok(None);
        };
        if !self.tick_corroborated[tick_index] {
            return Err(code::TICK_UNCORROBORATED);
        }
        let after = match self.schedule_cursor {
            Some((t, last)) if t == tick_index => Some(last),
            _ => None,
        };
        let reached: Vec<usize> = self
            .reached_reversals()
            .into_iter()
            .filter(|(_, s)| *s != Reached::Waiting)
            .map(|(t, _)| t)
            .filter(|t| after.is_none_or(|a| *t > a))
            .collect();
        let take = reached.len().min(max_batch);
        if take == 0 {
            return Ok(None);
        }
        let (mut minted, mut blocked) = (Vec::new(), Vec::new());
        for &target in &reached[..take] {
            match self.mint_scheduled(target) {
                Some(index) => minted.push((target, index)),
                None => blocked.push(target),
            }
        }
        self.schedule_cursor = Some((tick_index, reached[take - 1]));
        Ok(Some(ReversalSweep {
            tick: self.ticks[tick_index],
            minted,
            blocked,
            remaining: reached.len() - take,
        }))
    }

    /// Journal a TimeEvidence tick (plan §7.1a): strictly after the latest
    /// corroborated tick (or latest tick when no corroborated tick exists yet).
    /// `Ok(tick index)`.
    pub fn record_tick(&mut self, observed_utc_ns: u64) -> Result<usize, &'static str> {
        self.record_tick_with(observed_utc_ns, true)
    }

    /// Journal a TimeEvidence tick with an explicit monotonic-corroboration flag.
    pub fn record_tick_with(
        &mut self,
        observed_utc_ns: u64,
        monotonic_ok: bool,
    ) -> Result<usize, &'static str> {
        if observed_utc_ns > MAX_TICK_UTC_NS {
            return Err(code::STRUCTURE);
        }
        let prev_corroborated = self.latest_corroborated_tick();
        let prev_anchor = prev_corroborated.or_else(|| self.latest_tick());
        let effective_ok = monotonic_ok
            && prev_anchor.is_none_or(|prev| {
                observed_utc_ns >= prev && observed_utc_ns.saturating_sub(prev) <= MAX_CLOCK_SKEW_NS
            });
        let order_anchor = prev_corroborated.or_else(|| {
            if effective_ok {
                None
            } else {
                self.latest_tick()
            }
        });
        if order_anchor.is_some_and(|t| observed_utc_ns <= t) {
            return Err(code::TICK_ORDER);
        }
        self.ticks.push(observed_utc_ns);
        self.tick_corroborated.push(effective_ok);
        Ok(self.ticks.len() - 1)
    }

    /// The latest committed tick's instant.
    #[must_use]
    pub fn latest_tick(&self) -> Option<u64> {
        self.ticks.last().copied()
    }

    /// The latest corroborated tick's instant (`monotonic_ok = true` within skew bound).
    #[must_use]
    pub fn latest_corroborated_tick(&self) -> Option<u64> {
        self.ticks
            .iter()
            .zip(&self.tick_corroborated)
            .rev()
            .find(|(_, ok)| **ok)
            .map(|(t, _)| *t)
    }

    /// A timed hold (plan §5.4): a `Pending` whose deadline is the latest
    /// tick at the moment it posts plus `timeout_ns`.
    pub fn post_timed(&mut self, intent: &Intent, timeout_ns: u64) -> Verdict {
        if intent.class != "Pending" {
            return Verdict::Refused {
                code: code::STRUCTURE,
            };
        }
        self.post_inner(
            intent,
            None,
            Some(timeout_ns),
            None,
            None,
            &PostClaims::default(),
        )
    }

    /// A timed hold's deadline.
    #[must_use]
    pub fn deadline(&self, hold: usize) -> Option<u64> {
        self.deadlines.get(&hold).copied()
    }

    /// Every unresolved timed hold the latest tick has reached, in journal
    /// order: due, and still pending in every register until expired.
    #[must_use]
    pub fn due(&self) -> Vec<usize> {
        let Some(now) = self.latest_tick() else {
            return Vec::new();
        };
        self.deadlines
            .iter()
            .filter(|(h, d)| now >= **d && !self.resolved.contains_key(h))
            .map(|(h, _)| *h)
            .collect()
    }

    /// One expiry-sweep batch (plan §5.4): the first `max_batch` due holds
    /// after the cursor when the cursor belongs to the latest tick (else
    /// from the first), each expired by a leg-less resolution dated in its
    /// hold's period, then the cursor moves to the last one. `Ok(None)` when
    /// nothing is due; a release is admissible in every state but Future.
    pub fn sweep_batch(&mut self, max_batch: usize) -> Result<Option<SweepBatch>, &'static str> {
        if max_batch == 0 {
            return Err(code::STRUCTURE);
        }
        let Some(tick_index) = self.ticks.len().checked_sub(1) else {
            return Ok(None);
        };
        if !self.tick_corroborated[tick_index] {
            return Err(code::TICK_UNCORROBORATED);
        }
        let after = match self.cursor {
            Some((t, last)) if t == tick_index => Some(last),
            _ => None,
        };
        let due: Vec<usize> = self
            .due()
            .into_iter()
            .filter(|h| after.is_none_or(|a| *h > a))
            .collect();
        let take = due.len().min(max_batch);
        if take == 0 {
            return Ok(None);
        }
        let mut expired = Vec::with_capacity(take);
        for &h in &due[..take] {
            let hold = self.journal[h].clone();
            let state = self
                .period_state(&hold.period)
                .unwrap_or(PeriodState::Future);
            // The hand-transcribed Resolution(Expires) row of the hold's period
            // state decides (the sweep holds `post` only).
            if admissibility::decide_expires(state) != Decision::Admit {
                return Err(code::PERIOD_LAW);
            }
            let index = self.journal.len();
            let key = b"expires".to_vec();
            self.journal.push(Entry {
                class: "Resolution".into(),
                date: hold.date,
                period: hold.period.clone(),
                legs: Vec::new(),
                key: key.clone(),
                reverses: None,
                resolves: Some(h),
                settles: Vec::new(),
                run: None,
            });
            self.resolved.insert(
                h,
                (
                    index,
                    Content {
                        class: "Resolution".into(),
                        date: hold.date,
                        discriminator: None,
                        legs: Vec::new(),
                        reverses: None,
                        supersession_reason: 0,
                        resolves: Some(Resolve {
                            target: h,
                            posts: None,
                        }),
                        settles: Vec::new(),
                        key,
                        balancing: None,
                        timeout: None,
                        by_sweep: true,
                        auto_reverse: None,
                    },
                ),
            );
            expired.push((h, index));
        }
        self.cursor = Some((tick_index, due[take - 1]));
        Ok(Some(SweepBatch {
            tick: self.ticks[tick_index],
            expired,
            remaining_due: due.len() - take,
        }))
    }

    /// A balancing post (plan §5.5, TigerBeetle `balancing_*`): a two-leg
    /// single-unit Original/Adjusting/Pending of one positive amount `R`
    /// whose leg `leg` balances — it moves `min(R, admissible)`, where
    /// `admissible` is the room on that leg's side of its account's cell
    /// (its period cell for a budget cap); with no room, or no limit in that
    /// direction, the request stays at `R` and the law decides. The identity
    /// binds the request (`R` and `leg`). The moved amount is the journal
    /// entry's legs.
    pub fn post_balancing(&mut self, intent: &Intent, leg: u16) -> Verdict {
        let shape_ok = matches!(intent.class.as_str(), "Original" | "Adjusting" | "Pending")
            && intent.reverses.is_none()
            && intent.resolves.is_none()
            && intent.settles.is_empty()
            && leg <= 1
            && match intent.legs.as_slice() {
                [a, b] => {
                    a.unit == b.unit
                        && a.mantissa == b.mantissa
                        && a.mantissa > 0
                        && a.side != b.side
                        && a.account != b.account
                }
                _ => false,
            };
        if !shape_ok {
            return Verdict::Refused {
                code: code::BALANCING_SHAPE,
            };
        }
        self.post_inner(intent, Some(leg), None, None, None, &PostClaims::default())
    }

    /// Post a Reclassification of journal entry `target` (plan §8.2
    /// `Reclassifies`, Appendix B Reclass; fa-xvba). `intent` has class
    /// `Reclassification` and no `reverses`; it moves a positive part of the
    /// target's legs, bucketed by (account, unit, side, entity), to at least
    /// one other place, within what the target's earlier live
    /// reclassifications left. A reversed target, an exceeding move and a
    /// move back to where it came from are RECLASSIFICATION_SHAPE.
    pub fn reclassify(&mut self, intent: &Intent, target: usize) -> Verdict {
        self.reclassifying = Some(target);
        let verdict = self.post_inner(intent, None, None, None, None, &PostClaims::default());
        self.reclassifying = None;
        verdict
    }

    /// Whether `intent` fits the Reclassifies law against `target`.
    fn reclassification_fits(&self, intent: &Intent, target: usize) -> bool {
        let Some(original) = self.journal.get(target) else {
            return false;
        };
        let reclassifiable = matches!(
            original.class.as_str(),
            "Original" | "Adjusting" | "Reversal" | "Reclassification"
        ) || (original.class == "Resolution" && !original.legs.is_empty());
        if !reclassifiable || !self.is_live(target) {
            return false;
        }
        let opposite = |side: Side| match side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
        let bucket = |l: &Leg, side: Side| {
            (
                l.account.clone(),
                l.unit,
                side == Side::Debit,
                l.entity.clone(),
            )
        };
        let mut left: BTreeMap<(String, u32, bool, Option<String>), Int> = BTreeMap::new();
        for l in &original.legs {
            let slot = left.entry(bucket(l, l.side)).or_insert_with(Int::zero);
            *slot = slot.add(&Int::from_i128(l.mantissa));
        }
        for &prior in self.reclassifications.get(&target).into_iter().flatten() {
            if !self.is_live(prior) {
                continue;
            }
            for l in &self.journal[prior].legs {
                if let Some(slot) = left.get_mut(&bucket(l, opposite(l.side))) {
                    *slot = slot.sub(&Int::from_i128(l.mantissa));
                }
            }
        }
        let mut moved: BTreeMap<(String, u32, bool, Option<String>), Int> = BTreeMap::new();
        let mut sources = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        for l in &intent.legs {
            let key = bucket(l, opposite(l.side));
            let place = (l.account.clone(), l.unit, l.entity.clone());
            if let Some(remaining) = left.get(&key) {
                let slot = moved.entry(key).or_insert_with(Int::zero);
                *slot = slot.add(&Int::from_i128(l.mantissa));
                if remaining.sub(slot).is_negative() {
                    return false;
                }
                sources.insert(place);
            } else {
                destinations.insert(place);
            }
        }
        !sources.is_empty() && !destinations.is_empty() && destinations.is_disjoint(&sources)
    }

    fn post_inner(
        &mut self,
        intent: &Intent,
        balancing: Option<u16>,
        timeout: Option<u64>,
        auto_reverse: Option<DateDay>,
        run: Option<usize>,
        claims: &PostClaims,
    ) -> Verdict {
        // 1. Structure.
        let Some(class) = self.classes.by_name(&intent.class) else {
            return Verdict::Refused {
                code: code::STRUCTURE,
            };
        };
        let is_resolution = intent.class == "Resolution";
        let is_release =
            is_resolution && intent.resolves.as_ref().is_some_and(|r| r.posts.is_none());
        let allows_single_sided_class = matches!(
            intent.class.as_str(),
            "Original" | "Adjusting" | "Reversal" | "Migration"
        );
        let single_sided_statistical = intent.legs.len() == 1
            && allows_single_sided_class
            && self.is_single_sided_unit(intent.legs[0].unit);
        let shape_ok = match (&intent.resolves, is_resolution) {
            (None, false) => intent.legs.len() >= 2 || single_sided_statistical,
            (None, true) | (Some(_), false) => false,
            (Some(Resolve { posts: None, .. }), true) => intent.legs.is_empty(),
            (Some(Resolve { posts: Some(o), .. }), true) => {
                intent.legs.len() >= 2
                    && o.len() == intent.legs.len()
                    && o.windows(2).all(|w| w[0] < w[1])
            }
        };
        if !shape_ok
            || intent.key.is_empty()
            || intent.key.len() > 64
            // A leg moves a positive amount (plan §4.4): never negative, never zero.
            || intent.legs.iter().any(|l| l.mantissa <= 0)
        {
            return Verdict::Refused {
                code: code::STRUCTURE,
            };
        }
        if class.kind == fa_registry::ClassKind::Control {
            return Verdict::Refused {
                code: code::CONTROL_VIA_POST,
            };
        }
        // 1b. A Replacement posts only paired with its Reversal in one batch
        //     (plan §8.2, FA-INV-08.replacement-paired); this entry point
        //     posts one entry, so it is always the unpaired case.
        if intent.class == "Replacement" {
            return Verdict::Refused {
                code: code::REPLACEMENT_UNPAIRED,
            };
        }
        // 1b''. A PriorPeriodAdjustment, Revision or Restatement posts only
        //       as an Approved restatement case's entry, in the case's own
        //       Post batch (plan §8.3, beads fa-75j4, fa-651f); this entry
        //       point posts one entry outside any case.
        if matches!(
            intent.class.as_str(),
            "PriorPeriodAdjustment" | "Revision" | "Restatement"
        ) {
            return Verdict::Refused {
                code: code::CASE_MEMBERSHIP,
            };
        }
        // 1b'''. A Reclassification names its target (plan §8.2): posted only
        //        through Oracle::reclassify, which names nothing else.
        let reclass_target = self.reclassifying;
        if (intent.class == "Reclassification") != reclass_target.is_some() {
            return Verdict::Refused {
                code: if intent.class == "Reclassification" {
                    code::RECLASSIFICATION_SHAPE
                } else {
                    code::CLASS_NOT_IMPLEMENTED
                },
            };
        }
        // The supported subset, and a Reversal's target presence.
        let is_reversal = intent.class == "Reversal";
        if !matches!(
            intent.class.as_str(),
            "Original"
                | "Adjusting"
                | "Reversal"
                | "Pending"
                | "Resolution"
                | "Migration"
                | "Reclassification"
        ) {
            return Verdict::Refused {
                code: code::CLASS_NOT_IMPLEMENTED,
            };
        }
        // 1b'. Migration provenance (plan §8.6): a Migration entry names its
        //      run, and only a Migration entry names one.
        if (intent.class == "Migration") != run.is_some() {
            return Verdict::Refused {
                code: code::MIGRATION_OUTSIDE_RUN,
            };
        }
        // Unverified caller claims never become journal authority. System
        // minting and checked migration use their separate model entry points.
        if claims.plan_certificate.is_some()
            || claims.origin != ClaimedOrigin::Intent
            || claims.base_totals.is_some()
        {
            return Verdict::Refused {
                code: code::CLASS_NOT_IMPLEMENTED,
            };
        }
        if is_reversal && intent.reverses.is_none() {
            return Verdict::Refused {
                code: code::REVERSAL_TARGET,
            };
        }
        if !is_reversal && intent.reverses.is_some() {
            return Verdict::Refused {
                code: code::CLASS_NOT_IMPLEMENTED,
            };
        }
        // 1d'. Legal entities (plan §4.1, §5.2), leg by leg: a named entity
        //      the book has not declared is refused; in a book declaring
        //      more than one, a leg naming none is refused.
        for l in &intent.legs {
            match &l.entity {
                Some(e) if !self.entities.contains(e) => {
                    return Verdict::Refused {
                        code: code::ENTITY_UNDECLARED,
                    };
                }
                None if self.entities.len() > 1 => {
                    return Verdict::Refused {
                        code: code::DIMENSION_MISSING,
                    };
                }
                _ => {}
            }
        }
        // 1e. Application structure (plan §5.7), from the intent alone:
        //     only a posting entry applies; positive amounts; each target
        //     leg named once per leg; a leg applies at most itself.
        for (i, leg) in intent.legs.iter().enumerate() {
            let mine: Vec<&Settle> = intent.settles.iter().filter(|s| s.leg == i).collect();
            if mine.is_empty() {
                continue;
            }
            match intent.class.as_str() {
                "Original" | "Adjusting" => {}
                // A Migration chunk carries no settles (ruling 3733 C2):
                // it is imported net of its legacy applications.
                "Reversal" | "Migration" => {
                    return Verdict::Refused {
                        code: code::SETTLE_SHAPE,
                    };
                }
                _ => {
                    // Two-phase entries: not applied here.
                    return Verdict::Refused {
                        code: code::CLASS_NOT_IMPLEMENTED,
                    };
                }
            }
            let mut named = BTreeSet::new();
            let mut sum = Int::zero();
            for s in mine {
                if s.mantissa <= 0 || !named.insert((s.target, s.ordinal)) {
                    return Verdict::Refused {
                        code: code::SETTLE_SHAPE,
                    };
                }
                sum = sum.add(&Int::from_i128(s.mantissa));
            }
            if Int::from_i128(leg.mantissa).sub(&sum).is_negative() {
                return Verdict::Refused {
                    code: code::SETTLE_SHAPE,
                };
            }
        }
        if intent.settles.iter().any(|s| s.leg >= intent.legs.len()) {
            return Verdict::Refused {
                code: code::STRUCTURE,
            };
        }
        // 1f. A scheduled reversal (plan §7.6, §7.7): only an Adjusting
        //     entry without applications, for a later date, in a book that
        //     declares its time-zone policy, on a date in a normal period.
        let mut schedule_period = None;
        if let Some(reverse_on) = auto_reverse {
            if intent.class != "Adjusting"
                || !intent.settles.is_empty()
                || reverse_on <= intent.date
            {
                return Verdict::Refused {
                    code: code::STRUCTURE,
                };
            }
            if !self.tz_declared {
                return Verdict::Refused {
                    code: code::CLASS_NOT_IMPLEMENTED,
                };
            }
            let resolved = self
                .calendar
                .fiscal_year_of(reverse_on)
                .ok()
                .and_then(|fy| self.calendar.periods_for_year(fy).ok())
                .and_then(|defs| {
                    temporal::resolve(&defs, reverse_on, None).map(|p| p.code.clone())
                });
            let Some(p) = resolved else {
                return Verdict::Refused {
                    code: code::PERIOD_RESOLVE,
                };
            };
            schedule_period = Some(p);
        }
        // 2. Balance per unit (deferring registered statistical quantity units
        //    on single-sided-capable classes to Step 6).
        let is_deferred_single_sided_unit =
            |unit: u32| allows_single_sided_class && self.is_single_sided_unit(unit);
        let mut per_unit: BTreeMap<u32, (Int, Int)> = BTreeMap::new();
        for l in &intent.legs {
            if is_deferred_single_sided_unit(l.unit) {
                continue;
            }
            let e = per_unit.entry(l.unit).or_insert((Int::zero(), Int::zero()));
            let m = Int::from_i128(l.mantissa);
            match l.side {
                Side::Debit => e.0 = e.0.add(&m),
                Side::Credit => e.1 = e.1.add(&m),
            }
        }
        if per_unit.values().any(|(d, c)| d != c) {
            return Verdict::Refused {
                code: code::UNBALANCED,
            };
        }
        // 2'. Balance per (unit, legal entity) (FA-INV-01 `per-entity`).
        let mut per_entity: BTreeMap<(u32, Option<String>), (Int, Int)> = BTreeMap::new();
        for l in &intent.legs {
            if is_deferred_single_sided_unit(l.unit) {
                continue;
            }
            let e = per_entity
                .entry((l.unit, self.entity_of(l)))
                .or_insert((Int::zero(), Int::zero()));
            let m = Int::from_i128(l.mantissa);
            match l.side {
                Side::Debit => e.0 = e.0.add(&m),
                Side::Credit => e.1 = e.1.add(&m),
            }
        }
        if per_entity.values().any(|(d, c)| d != c) {
            return Verdict::Refused {
                code: code::UNBALANCED,
            };
        }
        // 3. Resolve the period.
        let Ok(fy) = self.calendar.fiscal_year_of(intent.date) else {
            return Verdict::Refused {
                code: code::PERIOD_RESOLVE,
            };
        };
        let Ok(defs) = self.calendar.periods_for_year(fy) else {
            return Verdict::Refused {
                code: code::PERIOD_RESOLVE,
            };
        };
        let Some(period) = temporal::resolve(&defs, intent.date, intent.discriminator.as_deref())
        else {
            return Verdict::Refused {
                code: code::PERIOD_RESOLVE,
            };
        };
        // 3''. A Migration chunk names its period: the Opening period, or a
        //      Normal code (whether it was born Historical is step 5's).
        if run.is_some() && intent.discriminator.is_none() {
            return Verdict::Refused {
                code: code::MIGRATION_OUTSIDE_RUN,
            };
        }
        let (calendar_kind, period_start, period_end) = (period.kind, period.start, period.end);
        let period = period.code.clone();
        // 4. Identity: the recorded outcome when the content is the same,
        //    a conflict when it is not — before any law is re-checked.
        let content = Content::of(intent, balancing, timeout, auto_reverse);
        let existing = match (intent.reverses, &intent.resolves) {
            (Some(target), _) => self.reversed.get(&target),
            (None, Some(r)) => self.resolved.get(&r.target),
            (None, None) => match run {
                Some(r) => self.migration_keys.get(&(r, intent.key.clone())),
                None => self.keys.get(&intent.key),
            },
        };
        if let Some((index, recorded)) = existing {
            // A Reclassification's identity also binds its target.
            let same_target = self.reclassification_targets.get(index).copied() == reclass_target;
            return if *recorded == content && same_target {
                Verdict::Recorded { index: *index }
            } else if is_reversal {
                Verdict::Refused {
                    code: code::ALREADY_REVERSED,
                }
            } else if is_resolution {
                Verdict::Refused {
                    code: code::ALREADY_RESOLVED,
                }
            } else {
                Verdict::Refused {
                    code: code::IDEMPOTENCY_CONFLICT,
                }
            };
        }
        if is_reversal || reclass_target.is_some() {
            let reasons =
                fa_registry::reason_codes::ReasonCodes::embedded().expect("reason registry");
            let reserved = intent.supersession_reason
                == fa_registry::reason_codes::SCHEDULED_ACCRUAL_REVERSAL
                && !self.minting_scheduled;
            if reserved
                || !reasons.rows.iter().any(|row| {
                    row.scope == "supersession" && row.code == intent.supersession_reason
                })
            {
                return Verdict::Refused {
                    code: code::SUPERSESSION_REASON,
                };
            }
        }
        // 4''. A Reclassification (plan §8.2 Reclassifies; fa-xvba): within
        //      what its live target's earlier live reclassifications left.
        if let Some(target) = reclass_target
            && !self.reclassification_fits(intent, target)
        {
            return Verdict::Refused {
                code: code::RECLASSIFICATION_SHAPE,
            };
        }
        // 4'. The run: known, Open, and the chunk on its opening date.
        if let Some(r) = run {
            let Some(rs) = self.runs.get(r) else {
                return Verdict::Refused {
                    code: code::MIGRATION_OUTSIDE_RUN,
                };
            };
            if rs.state != RunState::Open {
                return Verdict::Refused {
                    code: code::RUN_NOT_OPEN,
                };
            }
            let own_opening =
                calendar_kind == PeriodKind::Opening && period_start == rs.spec.opening_date;
            let admitted = if own_opening {
                true
            } else if calendar_kind == PeriodKind::Normal {
                rs.spec.declares(&period)
            } else {
                rs.spec.full_detail.is_some() && {
                    let first = &self.periods[&rs.spec.periods[0].0].0;
                    let last = &self.periods[&rs.spec.periods[rs.spec.periods.len() - 1].0].0;
                    period_start >= first.start && period_end <= last.end
                }
            };
            if !admitted {
                return Verdict::Refused {
                    code: code::MIGRATION_OUTSIDE_RUN,
                };
            }
            if own_opening && rs.spec.sole() {
                return Verdict::Refused {
                    code: code::MIGRATION_OUTSIDE_RUN,
                };
            }
            if own_opening && intent.date != rs.spec.opening_date {
                return Verdict::Refused {
                    code: code::MIGRATION_OUTSIDE_RUN,
                };
            }
        }
        // 5. Period law against the period's current state and its born
        //    kind: a Historical period admits only Migration. A period the
        //    calendar defines but nobody created admits nothing.
        if !self.periods.contains_key(&period) {
            return Verdict::Refused {
                code: code::PERIOD_UNKNOWN,
            };
        }
        let born = self.periods.get(&period).map(|(d, _)| d.kind);
        if born.is_some_and(|k| !admissibility::kind_admits(k, &intent.class)) {
            return Verdict::Refused {
                code: code::PERIOD_LAW,
            };
        }
        if born.is_some_and(|kind| {
            admissibility::pre_opening_governs(kind, period_end, self.opening_date)
                && !admissibility::pre_opening_admits(&intent.class)
        }) {
            return Verdict::Refused {
                code: code::PERIOD_LAW,
            };
        }
        if born.is_some_and(|kind| !admissibility::special_period_admits(kind, &intent.class)) {
            return Verdict::Refused {
                code: code::PERIOD_LAW,
            };
        }
        let state = self.period_state(&period).unwrap_or(PeriodState::Future);
        match admissibility::decide_disposition(&intent.class, state, is_release) {
            Some(Decision::Admit) => {}
            Some(Decision::With { op, approvals }) => {
                if !intent.ops.contains(&op) {
                    return Verdict::Refused {
                        code: code::CAPABILITY,
                    };
                }
                if intent.approvals < usize::from(approvals) {
                    return Verdict::Refused {
                        code: code::APPROVALS,
                    };
                }
            }
            Some(Decision::Refuse) | None => {
                return Verdict::Refused {
                    code: code::PERIOD_LAW,
                };
            }
        }
        // 6. Accounts, in leg order.
        for l in &intent.legs {
            let Some(a) = self.accounts.get(&l.account) else {
                return Verdict::Refused {
                    code: code::UNKNOWN_ACCOUNT,
                };
            };
            if !a.is_leaf {
                return Verdict::Refused {
                    code: code::NOT_A_LEAF,
                };
            }
            if let Some(&(opened, closed, _)) = self.account_effectivity.get(&l.account)
                && (opened.is_some_and(|o| intent.date < o)
                    || closed.is_some_and(|c| intent.date >= c))
            {
                return Verdict::Refused {
                    code: code::NOT_A_LEAF,
                };
            }
            if !self.units.contains(&l.unit) {
                return Verdict::Refused {
                    code: code::UNIT_UNREGISTERED,
                };
            }
            if a.unit.is_some_and(|u| u != l.unit) {
                return Verdict::Refused {
                    code: code::UNIT_POLICY,
                };
            }
        }
        if intent
            .legs
            .iter()
            .any(|l| self.is_memo_account(&l.account) || is_deferred_single_sided_unit(l.unit))
        {
            for partition in [0u8, 1, 2] {
                let mut by_unit: BTreeMap<u32, (Int, Int)> = BTreeMap::new();
                let mut by_entity: BTreeMap<(u32, Option<String>), (Int, Int)> = BTreeMap::new();
                for l in &intent.legs {
                    let leg_partition = if self.is_balanced_memo_account(&l.account) {
                        1u8
                    } else if self.is_statistical_account(&l.account) {
                        if is_deferred_single_sided_unit(l.unit) {
                            continue;
                        }
                        2u8
                    } else {
                        0u8
                    };
                    if leg_partition != partition {
                        continue;
                    }
                    let amt = Int::from_i128(l.mantissa);
                    let u_slot = by_unit
                        .entry(l.unit)
                        .or_insert_with(|| (Int::zero(), Int::zero()));
                    let e_slot = by_entity
                        .entry((l.unit, self.entity_of(l)))
                        .or_insert_with(|| (Int::zero(), Int::zero()));
                    match l.side {
                        Side::Debit => {
                            u_slot.0 = u_slot.0.add(&amt);
                            e_slot.0 = e_slot.0.add(&amt);
                        }
                        Side::Credit => {
                            u_slot.1 = u_slot.1.add(&amt);
                            e_slot.1 = e_slot.1.add(&amt);
                        }
                    }
                }
                if by_unit.values().any(|(d, c)| d != c) || by_entity.values().any(|(d, c)| d != c)
                {
                    return Verdict::Refused {
                        code: code::UNBALANCED,
                    };
                }
            }
        }
        // 6'. A staged chunk never moves a limit (not modelled until the
        //     migration availability slice).
        if run.is_some()
            && intent
                .legs
                .iter()
                .any(|l| self.limits.contains_key(&l.account))
        {
            return Verdict::Refused {
                code: code::CLASS_NOT_IMPLEMENTED,
            };
        }
        // 7a. Application law (plan §5.7): a witnessed, live, posted target
        //     leg on the same account and unit with the opposite side, within
        //     its open amount (counting earlier settlements of this intent).
        let mut used: BTreeMap<(usize, usize), Int> = BTreeMap::new();
        for s in &intent.settles {
            let leg = &intent.legs[s.leg];
            let Some(target) = self.journal.get(s.target) else {
                return Verdict::Refused {
                    code: code::SETTLE_TARGET,
                };
            };
            if !self.carries_open_items(target) || !self.is_live(s.target) {
                return Verdict::Refused {
                    code: code::SETTLE_TARGET,
                };
            }
            let Some(tl) = target.legs.get(s.ordinal) else {
                return Verdict::Refused {
                    code: code::SETTLE_SHAPE,
                };
            };
            if tl.account != leg.account
                || tl.unit != leg.unit
                || tl.side == leg.side
                || self.entity_of(tl) != self.entity_of(leg)
            {
                return Verdict::Refused {
                    code: code::SETTLE_SHAPE,
                };
            }
            let before = used
                .get(&(s.target, s.ordinal))
                .cloned()
                .unwrap_or_else(Int::zero);
            let mut consumed = Int::zero();
            for t in target.settles.iter().filter(|t| t.leg == s.ordinal) {
                consumed = consumed.add(&Int::from_i128(t.mantissa));
            }
            let open = Int::from_i128(tl.mantissa)
                .sub(&consumed)
                .sub(&self.applied_to_int(s.target, s.ordinal))
                .sub(&before);
            let settle_amt = Int::from_i128(s.mantissa);
            if open.sub(&settle_amt).is_negative() {
                return Verdict::Refused {
                    code: code::OVER_APPLICATION,
                };
            }
            used.insert((s.target, s.ordinal), before.add(&settle_amt));
        }
        // 7. Reversal law: the target exists and the legs are its exact side-swap.
        if let Some(target) = intent.reverses {
            let Some(original) = self.journal.get(target) else {
                return Verdict::Refused {
                    code: code::REVERSAL_TARGET,
                };
            };
            // Only a posted entry is reversible (plan §8.2): a hold and a
            // release posted nothing; a Resolution(Posts) did.
            let reversible = matches!(
                original.class.as_str(),
                "Original" | "Adjusting" | "Reversal" | "Reclassification"
            ) || (original.class == "Resolution" && !original.legs.is_empty());
            if !reversible {
                return Verdict::Refused {
                    code: code::REVERSAL_TARGET,
                };
            }
            let target_period = &self.periods[&original.period].0;
            let current_period = &self.periods[&period].0;
            // Independent of production's chronological_key: definition
            // enumeration appends Opening, while chronological order puts
            // it before the first Normal period.
            let rank = |kind| match kind {
                PeriodKind::Opening => 0,
                PeriodKind::Normal | PeriodKind::Historical => 1,
                PeriodKind::Adjustment => 2,
                PeriodKind::Closing => 3,
            };
            let order = current_period
                .start
                .cmp(&target_period.start)
                .then_with(|| rank(current_period.kind).cmp(&rank(target_period.kind)))
                .then_with(|| current_period.fiscal_year.cmp(&target_period.fiscal_year))
                .then_with(|| current_period.ordinal.cmp(&target_period.ordinal));
            if order.is_lt() {
                return Verdict::Refused {
                    code: code::REVERSAL_PERIOD,
                };
            }
            let swapped = original.legs.len() == intent.legs.len()
                && original.legs.iter().zip(&intent.legs).all(|(o, r)| {
                    o.account == r.account
                        && o.unit == r.unit
                        && o.entity == r.entity
                        && o.mantissa == r.mantissa
                        && o.side.flipped() == r.side
                });
            if !swapped {
                return Verdict::Refused {
                    code: code::REVERSAL_SHAPE,
                };
            }
            // 7c. Application effects (plan §5.7, §8.2): an item or any ancestor
            //     in its reversal chain with live applications is not reversed;
            //     re-applying by reversing a reversal waits for the full netting law.
            let mut anc = Some(target);
            while let Some(idx) = anc {
                let entry = &self.journal[idx];
                for i in 0..entry.legs.len() {
                    if self.applied_to(idx, i) != 0 {
                        return Verdict::Refused {
                            code: code::LIVE_APPLICATIONS,
                        };
                    }
                }
                if entry.class == "Reversal" {
                    if entry
                        .reverses
                        .and_then(|g| self.journal.get(g))
                        .is_some_and(|g| !g.settles.is_empty())
                    {
                        return Verdict::Refused {
                            code: code::CLASS_NOT_IMPLEMENTED,
                        };
                    }
                    anc = entry.reverses;
                } else {
                    anc = None;
                }
            }
        }
        // 7b. Resolution law: the target is a pending entry; a Posts
        //     sub-vector is drawn leg by leg (same account, unit, side;
        //     0 < posted ≤ reserved).
        if let Some(r) = &intent.resolves {
            let Some(target) = self.journal.get(r.target) else {
                return Verdict::Refused {
                    code: code::RESOLUTION_TARGET,
                };
            };
            if target.class != "Pending" {
                return Verdict::Refused {
                    code: code::RESOLUTION_TARGET,
                };
            }
            if let Some(ordinals) = &r.posts {
                for (leg, o) in intent.legs.iter().zip(ordinals) {
                    let Some(src) = target.legs.get(usize::from(*o)) else {
                        return Verdict::Refused {
                            code: code::RESOLUTION_SHAPE,
                        };
                    };
                    if src.account != leg.account
                        || src.unit != leg.unit
                        || src.entity != leg.entity
                        || src.side != leg.side
                        || leg.mantissa <= 0
                        || leg.mantissa > src.mantissa
                    {
                        return Verdict::Refused {
                            code: code::RESOLUTION_SHAPE,
                        };
                    }
                }
            }
        }
        // 7e. Timing (plan §5.4): a timed hold needs a tick to anchor on and
        //     a representable deadline; a Posts on a hold whose deadline the
        //     latest corroborated tick has reached is refused (Voids is not).
        let mut deadline = None;
        if let Some(t) = timeout {
            let Some(anchor) = self
                .latest_corroborated_tick()
                .or_else(|| self.latest_tick())
            else {
                return Verdict::Refused {
                    code: code::TICK_MISSING,
                };
            };
            let Some(d) = anchor.checked_add(t) else {
                return Verdict::Refused {
                    code: code::DEADLINE_OVERFLOW,
                };
            };
            deadline = Some(d);
        }
        if let Some(Resolve {
            target,
            posts: Some(_),
        }) = &intent.resolves
            && let (Some(d), Some(now)) =
                (self.deadlines.get(target), self.latest_corroborated_tick())
            && now >= *d
        {
            return Verdict::Refused {
                code: code::HOLD_DUE,
            };
        }
        // 7d. Reserved availability, budget caps, balancing (plan §5.4–5.5).
        //     A balancing request first resolves its legs to
        //     min(R, admissible) on the literal fold; then each limited cell
        //     the entry moves — keyed (account, period) for a budget cap:
        //     posted and reserved legs in the entry's period, released legs in
        //     the hold's — in order of first appearance (the entry's legs,
        //     then a resolved hold's legs), is judged on the literal fold.
        let legs: Vec<Leg> = match balancing {
            None => intent.legs.clone(),
            Some(leg) => {
                let target = &intent.legs[usize::from(leg)];
                let requested = target.mantissa;
                let moved = match self.limits.get(&target.account) {
                    None => requested,
                    Some(limit) => {
                        let cell = self.availability_in(
                            &target.account,
                            limit.per_period.then_some(period.as_str()),
                        );
                        let (n, o, pin, pout) = match limit.normal {
                            Side::Debit => (
                                &cell.debits_posted,
                                &cell.credits_posted,
                                &cell.debits_pending,
                                &cell.credits_pending,
                            ),
                            Side::Credit => (
                                &cell.credits_posted,
                                &cell.debits_posted,
                                &cell.credits_pending,
                                &cell.debits_pending,
                            ),
                        };
                        let net = n.sub(o);
                        let room = if target.side == limit.normal {
                            limit.upper.map(|u| Int::from_i128(u).sub(&net.add(pin)))
                        } else {
                            limit.lower.map(|l| net.sub(pout).sub(&Int::from_i128(l)))
                        };
                        match room {
                            Some(r) if !r.is_negative() && !r.is_zero() => {
                                // min(R, room), exactly: R − room < 0 ⇔ R < room.
                                if Int::from_i128(requested).sub(&r).is_negative() {
                                    requested
                                } else {
                                    r.to_i128().unwrap_or(requested)
                                }
                            }
                            _ => requested,
                        }
                    }
                };
                intent
                    .legs
                    .iter()
                    .map(|l| Leg {
                        mantissa: moved,
                        ..l.clone()
                    })
                    .collect()
            }
        };
        let hold = intent
            .resolves
            .as_ref()
            .and_then(|r| self.journal.get(r.target));
        let released: Vec<Leg> = hold.map(|t| t.legs.clone()).unwrap_or_default();
        let hold_period: Option<String> = hold.map(|t| t.period.clone());
        let cell_of = |account: &str, release: bool| -> Option<(String, Option<String>)> {
            let limit = self.limits.get(account)?;
            let p = match (limit.per_period, release) {
                (false, _) => None,
                (true, false) => Some(period.clone()),
                (true, true) => hold_period.clone(),
            };
            Some((account.to_string(), p))
        };
        let mut order: Vec<(String, Option<String>)> = Vec::new();
        for (l, release) in legs
            .iter()
            .map(|l| (l, false))
            .chain(released.iter().map(|l| (l, true)))
        {
            if let Some(k) = cell_of(&l.account, release)
                && !order.contains(&k)
            {
                order.push(k);
            }
        }
        for (account, cell_period) in &order {
            let account = account.as_str();
            let limit = &self.limits[account];
            let before = self.availability_in(account, cell_period.as_deref());
            let mut after = before.clone();
            let bump = |slot: &mut Int, m: i128, sign: bool| {
                let m = Int::from_i128(m);
                *slot = if sign { slot.add(&m) } else { slot.sub(&m) };
            };
            for l in legs.iter().filter(|l| {
                l.account == account
                    && cell_of(&l.account, false).as_ref().map(|k| &k.1) == Some(cell_period)
            }) {
                match (intent.class.as_str(), l.side) {
                    ("Pending", Side::Debit) => bump(&mut after.debits_pending, l.mantissa, true),
                    ("Pending", Side::Credit) => bump(&mut after.credits_pending, l.mantissa, true),
                    (_, Side::Debit) => bump(&mut after.debits_posted, l.mantissa, true),
                    (_, Side::Credit) => bump(&mut after.credits_posted, l.mantissa, true),
                }
            }
            for l in released.iter().filter(|l| {
                l.account == account
                    && cell_of(&l.account, true).as_ref().map(|k| &k.1) == Some(cell_period)
            }) {
                match l.side {
                    Side::Debit => bump(&mut after.debits_pending, l.mantissa, false),
                    Side::Credit => bump(&mut after.credits_pending, l.mantissa, false),
                }
            }
            if [
                &after.debits_posted,
                &after.credits_posted,
                &after.debits_pending,
                &after.credits_pending,
            ]
            .iter()
            .any(|v| v.to_i128().is_none())
            {
                return Verdict::Refused {
                    code: code::LIMIT_CEILING,
                };
            }
            // (L, U) = (net − pending_out, net + pending_in), normal sign.
            let lu = |a: &Availability| {
                let (n, o, pin, pout) = match limit.normal {
                    Side::Debit => (
                        &a.debits_posted,
                        &a.credits_posted,
                        &a.debits_pending,
                        &a.credits_pending,
                    ),
                    Side::Credit => (
                        &a.credits_posted,
                        &a.debits_posted,
                        &a.credits_pending,
                        &a.debits_pending,
                    ),
                };
                let net = n.sub(o);
                (net.sub(pout), net.add(pin))
            };
            let (l0, u0) = lu(&before);
            let (l1, u1) = lu(&after);
            if let Some(lower) = limit.lower
                && l1.sub(&l0).is_negative()
                && l1.sub(&Int::from_i128(lower)).is_negative()
            {
                return Verdict::Refused {
                    code: code::AVAILABILITY_LOWER,
                };
            }
            if let Some(upper) = limit.upper
                && u0.sub(&u1).is_negative()
                && Int::from_i128(upper).sub(&u1).is_negative()
            {
                return Verdict::Refused {
                    code: code::AVAILABILITY_UPPER,
                };
            }
        }
        let index = self.journal.len();
        self.journal.push(Entry {
            class: intent.class.clone(),
            date: intent.date,
            period: period.clone(),
            legs,
            key: intent.key.clone(),
            reverses: intent.reverses,
            resolves: intent.resolves.as_ref().map(|r| r.target),
            settles: intent.settles.clone(),
            run,
        });
        if let Some(r) = run {
            self.runs[r].chunks.push(index);
        }
        if let Some(target) = reclass_target {
            self.reclassifications
                .entry(target)
                .or_default()
                .push(index);
            self.reclassification_targets.insert(index, target);
        }
        if let Some(d) = deadline {
            self.deadlines.insert(index, d);
        }
        if let (Some(reverse_on), Some(period)) = (auto_reverse, schedule_period) {
            self.schedules.insert(
                index,
                ScheduleState {
                    reverse_on,
                    period,
                    cancelled: false,
                },
            );
        }
        match (intent.reverses, &intent.resolves) {
            (Some(target), _) => {
                self.reversed.insert(target, (index, content));
            }
            (None, Some(r)) => {
                self.resolved.insert(r.target, (index, content));
            }
            (None, None) => match run {
                Some(r) => {
                    self.migration_keys
                        .insert((r, intent.key.clone()), (index, content));
                }
                None => {
                    self.keys.insert(intent.key.clone(), (index, content));
                }
            },
        }
        Verdict::Posted { index, period }
    }

    /// Open a migration run (plan §8.6), in the kernel's order: the body's
    /// own law, then `migrate` held, then the control's identity, then the
    /// run key's.
    pub fn open_run(
        &mut self,
        spec: &RunSpec,
        control_key: &[u8],
        ops: &[String],
    ) -> Result<usize, &'static str> {
        if spec.key.is_empty() || spec.key.len() > 64 {
            return Err(code::STRUCTURE);
        }
        if spec.sole() {
            if !spec.lines.is_empty()
                || spec
                    .full_detail
                    .as_ref()
                    .is_some_and(|f| !f.detail_base.is_empty())
            {
                return Err(code::STRUCTURE);
            }
        } else {
            check_trial_balance(&spec.lines)?;
        }
        let full = spec.full_detail.is_some();
        if (full && spec.periods.is_empty()) || spec.periods.len() > 256 {
            return Err(code::STRUCTURE);
        }
        let mut seen = BTreeSet::new();
        for (period, lines) in &spec.periods {
            if period.is_empty() || period.len() > 64 || !seen.insert(period.as_str()) {
                return Err(code::STRUCTURE);
            }
            if full {
                check_balance_lines(lines)?;
            } else {
                check_trial_balance(lines)?;
            }
        }
        if let Some(f) = &spec.full_detail {
            check_balance_lines(&f.detail_base)?;
        }
        let year_start = self
            .calendar
            .fiscal_year_of(spec.opening_date)
            .and_then(|fy| self.calendar.year_bounds(fy))
            .map(|(start, _)| start);
        if year_start.ok() != Some(spec.opening_date) {
            return Err(code::STRUCTURE);
        }
        if !ops.iter().any(|o| o == "migrate") {
            return Err(code::CAPABILITY);
        }
        if let Some((content, run)) = self.control_keys.get(control_key) {
            return if *content == ControlContent::Open(spec.clone()) {
                Ok(*run)
            } else {
                Err(code::IDEMPOTENCY_CONFLICT)
            };
        }
        if self.run_keys.contains_key(&spec.key) {
            return Err(code::IDEMPOTENCY_CONFLICT);
        }
        // A PeriodBalances run names exactly the elapsed periods from its
        // opening date to the book's, in calendar order, each created and
        // born Historical.
        if !spec.periods.is_empty() {
            let Some(go_live) = self.opening_date else {
                return Err(code::STRUCTURE);
            };
            // PeriodBalances from the run's opening date; FullDetail from
            // its first declared period, on or before the opening date
            // unless the run is the sole source.
            let start = if spec.full_detail.is_some() {
                let Some((def, _)) = self.periods.get(&spec.periods[0].0) else {
                    return Err(code::STRUCTURE);
                };
                if !spec.sole() && def.start > spec.opening_date {
                    return Err(code::STRUCTURE);
                }
                def.start
            } else {
                spec.opening_date
            };
            let (Ok(first), Ok(last)) = (
                self.calendar.fiscal_year_of(start),
                self.calendar.fiscal_year_of(go_live),
            ) else {
                return Err(code::STRUCTURE);
            };
            let mut expected = Vec::new();
            for fy in first..=last {
                for p in self.calendar.periods_for_year(fy).expect("periods") {
                    if p.kind == PeriodKind::Normal && p.start >= start && p.end <= go_live {
                        expected.push(p.code);
                    }
                }
            }
            let named: Vec<&String> = spec.periods.iter().map(|(code, _)| code).collect();
            if named != expected.iter().collect::<Vec<_>>() {
                return Err(code::STRUCTURE);
            }
            if expected.iter().any(|code| {
                self.periods
                    .get(code)
                    .is_none_or(|(d, _)| d.kind != PeriodKind::Historical)
            }) {
                return Err(code::STRUCTURE);
            }
        }
        let run = self.runs.len();
        self.runs.push(Run {
            spec: spec.clone(),
            state: RunState::Open,
            chunks: Vec::new(),
            finalized: None,
        });
        self.run_keys.insert(spec.key.clone(), run);
        self.control_keys.insert(
            control_key.to_vec(),
            (ControlContent::Open(spec.clone()), run),
        );
        self.run_controls.push(self.journal.len());
        Ok(run)
    }

    /// Post a chunk into `run` (a `Migration` entry naming it).
    pub fn post_migration(&mut self, run: usize, intent: &Intent) -> Verdict {
        self.post_inner(intent, None, None, None, Some(run), &PostClaims::default())
    }

    /// Finalize `run`, planned over `planned_chunks` chunks.
    pub fn finalize_run(
        &mut self,
        run: usize,
        planned_chunks: usize,
        control_key: &[u8],
        ops: &[String],
        approvals: usize,
    ) -> Result<(), &'static str> {
        self.transition_run(run, true, planned_chunks, control_key, ops, approvals)
    }

    /// Abandon `run`, planned over `planned_chunks` chunks.
    pub fn abandon_run(
        &mut self,
        run: usize,
        planned_chunks: usize,
        control_key: &[u8],
        ops: &[String],
    ) -> Result<(), &'static str> {
        self.transition_run(run, false, planned_chunks, control_key, ops, 0)
    }

    pub fn run_state(&self, run: usize) -> Option<RunState> {
        self.runs.get(run).map(|r| r.state)
    }

    pub fn run_chunks(&self, run: usize) -> usize {
        self.runs.get(run).map_or(0, |r| r.chunks.len())
    }

    /// The kernel's order: `migrate` held, the control's identity, the run
    /// known and Open, the fold equal to the declared lines (Finalize), the
    /// chunk set the one planned, two approvals (Finalize).
    fn transition_run(
        &mut self,
        run: usize,
        finalize: bool,
        planned_chunks: usize,
        control_key: &[u8],
        ops: &[String],
        approvals: usize,
    ) -> Result<(), &'static str> {
        if !ops.iter().any(|o| o == "migrate") {
            return Err(code::CAPABILITY);
        }
        let content = ControlContent::Transition {
            run,
            finalize,
            chunks: planned_chunks,
        };
        if let Some((recorded, _)) = self.control_keys.get(control_key) {
            return if *recorded == content {
                Ok(())
            } else {
                Err(code::IDEMPOTENCY_CONFLICT)
            };
        }
        let Some(r) = self.runs.get(run) else {
            return Err(code::MIGRATION_OUTSIDE_RUN);
        };
        if r.state != RunState::Open {
            return Err(code::RUN_NOT_OPEN);
        }
        if finalize && !self.ties_out(run) {
            return Err(code::TIE_OUT_MISMATCH);
        }
        if r.chunks.len() != planned_chunks {
            return Err(code::CONFLICT);
        }
        if finalize && approvals < 2 {
            return Err(code::APPROVALS);
        }
        let control = self.run_controls.len();
        self.run_controls.push(self.journal.len());
        let r = &mut self.runs[run];
        if finalize {
            r.state = RunState::Finalized;
            r.finalized = Some(control);
        } else {
            r.state = RunState::Abandoned;
        }
        self.control_keys
            .insert(control_key.to_vec(), (content, run));
        Ok(())
    }

    /// The run's chunks tie out, per (account, unit) in debit sign: the
    /// chunks outside its declared periods to its opening lines exactly, and
    /// for each declared period `p` in order, those plus every declared
    /// period's chunks through `p` to `p`'s cumulative lines.
    fn ties_out(&self, run: usize) -> bool {
        let r = &self.runs[run];
        let own_opening = self
            .calendar
            .periods_for_year(
                self.calendar
                    .fiscal_year_of(r.spec.opening_date)
                    .expect("fiscal year"),
            )
            .expect("periods")
            .into_iter()
            .find(|p| p.kind == PeriodKind::Opening)
            .expect("an Opening period")
            .code;
        let mut cumulative: BTreeMap<(String, u32), Int> = BTreeMap::new();
        for i in &r.chunks {
            if self.journal[*i].period == own_opening {
                self.fold_legs(*i, &mut cumulative);
            }
        }
        if !Self::same_balance(&cumulative, &r.spec.lines) {
            return false;
        }
        if let Some(f) = &r.spec.full_detail {
            // The FullDetail chain from detail_base; unless sole, the
            // opening lines equal it at the run's opening date.
            let mut chain: BTreeMap<(String, u32), Int> = f
                .detail_base
                .iter()
                .map(|(a, u, m)| ((a.clone(), *u), Int::from_i128(*m)))
                .collect();
            let from = self.periods[&r.spec.periods[0].0].0.start;
            let to = self.periods[&r.spec.periods[r.spec.periods.len() - 1].0]
                .0
                .end;
            let rank = |k: PeriodKind| match k {
                PeriodKind::Opening => 0u8,
                PeriodKind::Normal | PeriodKind::Historical => 1,
                PeriodKind::Adjustment => 2,
                PeriodKind::Closing => 3,
            };
            let mut order: Vec<&PeriodDef> = self
                .periods
                .values()
                .map(|(d, _)| d)
                .filter(|d| d.start >= from && d.end <= to && d.code != own_opening)
                .collect();
            order.sort_by_key(|d| (d.start, rank(d.kind)));
            let mut opening_checked = f.sole;
            for q in order {
                if !opening_checked && q.start >= r.spec.opening_date {
                    if !Self::same_balance(&chain, &r.spec.lines) {
                        return false;
                    }
                    opening_checked = true;
                }
                for i in &r.chunks {
                    if self.journal[*i].period == q.code {
                        self.fold_legs(*i, &mut chain);
                    }
                }
                if let Some((_, lines)) = r.spec.periods.iter().find(|(c, _)| *c == q.code)
                    && !Self::same_balance(&chain, lines)
                {
                    return false;
                }
            }
            return opening_checked || Self::same_balance(&chain, &r.spec.lines);
        }
        for (period, lines) in &r.spec.periods {
            for i in &r.chunks {
                if self.journal[*i].period == *period {
                    self.fold_legs(*i, &mut cumulative);
                }
            }
            if !Self::same_balance(&cumulative, lines) {
                return false;
            }
        }
        true
    }

    /// Add journal entry `index`'s legs to `into`, per (account, unit) in
    /// debit sign.
    fn fold_legs(&self, index: usize, into: &mut BTreeMap<(String, u32), Int>) {
        for l in &self.journal[index].legs {
            let e = into
                .entry((l.account.clone(), l.unit))
                .or_insert_with(Int::zero);
            let m = Int::from_i128(l.mantissa);
            *e = match l.side {
                Side::Debit => e.add(&m),
                Side::Credit => e.sub(&m),
            };
        }
    }

    /// A fold equals declared lines exactly (zero cells are absent lines).
    fn same_balance(folded: &BTreeMap<(String, u32), Int>, lines: &[(String, u32, i128)]) -> bool {
        let nonzero: BTreeMap<(String, u32), Int> = folded
            .iter()
            .filter(|(_, v)| !v.is_zero())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let declared: BTreeMap<(String, u32), Int> = lines
            .iter()
            .map(|(a, u, m)| ((a.clone(), *u), Int::from_i128(*m)))
            .collect();
        nonzero == declared
    }

    /// The literal fold of one period: `(account, unit) → cell`.
    #[must_use]
    pub fn fold(&self, period: &str) -> BTreeMap<(String, u32), Cell> {
        self.activity_known(&[period], self.known())
    }

    /// Stock from inception through an inclusive effective day, as known after
    /// `accepted_prefix` accepted monetary entries. This is an oracle journal
    /// count, not a substrate commit sequence: controls and metadata do not
    /// advance it. Tests must record the correspondence at each observation.
    ///
    /// Panics if the requested prefix extends beyond the oracle's journal.
    #[must_use]
    pub fn stock_at(&self, day: DateDay, accepted_prefix: usize) -> BTreeMap<(String, u32), Cell> {
        self.stock_known(day, self.known_after(accepted_prefix))
    }

    /// [`Self::stock_at`] at an explicit coordinate: the migration predicate
    /// needs the run controls accepted by then, not only the entries.
    #[must_use]
    pub fn stock_known(&self, day: DateDay, known: Known) -> BTreeMap<(String, u32), Cell> {
        Self::fold_entries(
            self.journal[..known.entries]
                .iter()
                .filter(|entry| entry.date <= day && self.visible(entry, known)),
        )
    }

    /// Flow through the same independent journal prefix, restricted to the
    /// named period identities. A repeated period selects no additional rows;
    /// periods sharing one civil date remain separate activity buckets.
    ///
    /// Panics if the requested prefix extends beyond the oracle's journal.
    #[must_use]
    pub fn activity_at(
        &self,
        periods: &[&str],
        accepted_prefix: usize,
    ) -> BTreeMap<(String, u32), Cell> {
        self.activity_known(periods, self.known_after(accepted_prefix))
    }

    /// [`Self::activity_at`] at an explicit coordinate.
    #[must_use]
    pub fn activity_known(&self, periods: &[&str], known: Known) -> BTreeMap<(String, u32), Cell> {
        Self::fold_entries(
            self.journal[..known.entries].iter().filter(|entry| {
                periods.contains(&entry.period.as_str()) && self.visible(entry, known)
            }),
        )
    }

    /// Monetary trial-balance footing over a fold's `cells` (`fa-a57x`):
    /// sums `(debits, credits)` per unit across monetary (`stock` and `flow`)
    /// accounts, excluding `Memo` (`6`) and `Statistical` (`7`) accounts.
    #[must_use]
    pub fn trial_balance_totals(
        &self,
        cells: &BTreeMap<(String, u32), Cell>,
    ) -> BTreeMap<u32, (i128, i128)> {
        let mut totals: BTreeMap<u32, (i128, i128)> = BTreeMap::new();
        for ((code, unit), cell) in cells {
            if self.is_memo_account(code) {
                continue;
            }
            let slot = totals.entry(*unit).or_insert((0, 0));
            slot.0 += cell.debits.to_i128().expect("fits i128");
            slot.1 += cell.credits.to_i128().expect("fits i128");
        }
        totals
    }

    /// The model's head coordinate.
    #[must_use]
    pub fn known(&self) -> Known {
        Known {
            entries: self.journal.len(),
            controls: self.run_controls.len(),
        }
    }

    /// Accepted journal entries in commit order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.journal
    }

    /// The coordinate just before entry `accepted_prefix` was accepted: every
    /// run control accepted while the journal held at most that many entries.
    #[must_use]
    pub fn known_after(&self, accepted_prefix: usize) -> Known {
        Known {
            entries: accepted_prefix,
            controls: self
                .run_controls
                .iter()
                .filter(|at| **at <= accepted_prefix)
                .count(),
        }
    }

    /// The FA-INV-07 migration predicate: a chunk is selected iff its run's
    /// Finalize is among the controls accepted by `known`.
    #[must_use]
    pub fn visible(&self, e: &Entry, known: Known) -> bool {
        match e.run {
            None => true,
            Some(r) => {
                let run = &self.runs[r];
                run.finalized
                    .is_some_and(|control| control < known.controls)
                    && run.spec.counts_from().is_none_or(|day| e.date >= day)
            }
        }
    }

    fn fold_entries<'a>(entries: impl Iterator<Item = &'a Entry>) -> BTreeMap<(String, u32), Cell> {
        let mut cells: BTreeMap<(String, u32), Cell> = BTreeMap::new();
        // A Pending reserves and never posts (plan §5.4); its legs live in
        // the pending fold, not here.
        for e in entries.filter(|e| e.class != "Pending") {
            let mut touched: Vec<(String, u32)> = Vec::new();
            for l in &e.legs {
                let key = (l.account.clone(), l.unit);
                let c = cells.entry(key.clone()).or_insert(Cell {
                    debits: Int::zero(),
                    credits: Int::zero(),
                    entry_count: 0,
                });
                let m = Int::from_i128(l.mantissa);
                match l.side {
                    Side::Debit => c.debits = c.debits.add(&m),
                    Side::Credit => c.credits = c.credits.add(&m),
                }
                if !touched.contains(&key) {
                    touched.push(key);
                }
            }
            for key in touched {
                if let Some(c) = cells.get_mut(&key) {
                    c.entry_count += 1;
                }
            }
        }
        cells
    }

    /// The pending fold of one period: the legs of every `Pending` entry in
    /// that period that has no resolution in the first `accepted_prefix`
    /// entries. A resolution releases the full original pending amount
    /// exactly once, whatever its own period.
    #[must_use]
    pub fn pending_at(
        &self,
        period: &str,
        accepted_prefix: usize,
    ) -> BTreeMap<(String, u32), Cell> {
        Self::fold_entries(
            self.journal[..accepted_prefix]
                .iter()
                .enumerate()
                .filter(|(i, e)| {
                    e.class == "Pending"
                        && e.period == period
                        && !self
                            .resolved
                            .get(i)
                            .is_some_and(|(r, _)| *r < accepted_prefix)
                })
                .map(|(_, e)| e)
                // fold_entries skips Pending; present them as what they are
                // here: reserved legs.
                .map(|e| Entry {
                    class: "Reserved".into(),
                    ..e.clone()
                })
                .collect::<Vec<_>>()
                .iter(),
        )
    }

    #[must_use]
    pub fn pending_fold(&self, period: &str) -> BTreeMap<(String, u32), Cell> {
        self.pending_at(period, self.journal.len())
    }

    /// Posted classes carry open items: a hold reserves, a release posts
    /// nothing, and a reversal's legs negate.
    /// A migrated chunk carries open items once its run is Finalized and
    /// the chunk counts (ruling 3733 C1): the migration predicate at head.
    fn carries_open_items(&self, e: &Entry) -> bool {
        self.carries_open_items_at(e, self.known())
    }

    /// Whether `e` carries open items at `known`.
    #[must_use]
    pub fn carries_open_items_at(&self, e: &Entry, known: Known) -> bool {
        !e.legs.is_empty()
            && self.visible(e, known)
            && matches!(
                e.class.as_str(),
                "Original"
                    | "Resolution"
                    | "Replacement"
                    | "Reclassification"
                    | "Adjusting"
                    | "Closing"
                    | "Allocation"
                    | "Revaluation"
                    | "Elimination"
                    | "Migration"
                    | "Revision"
                    | "Restatement"
                    | "PriorPeriodAdjustment"
            )
    }

    /// Live unless a live reversal targets it (a reversed reversal revives).
    fn is_live(&self, index: usize) -> bool {
        match self.reversed.get(&index) {
            None => true,
            Some((reversal, _)) => !self.is_live(*reversal),
        }
    }

    /// Bitemporal liveness of `index` at `(accepted_prefix, effective_through)`:
    /// a reversal only cancels `index` if the reversal itself is within
    /// `..accepted_prefix`, has `date <= effective_through`, and is bitemporally live.
    #[must_use]
    pub fn is_live_at(
        &self,
        index: usize,
        accepted_prefix: usize,
        effective_through: DateDay,
    ) -> bool {
        match self.reversed.get(&index) {
            None => true,
            Some((reversal, _)) => {
                if *reversal >= accepted_prefix || self.journal[*reversal].date > effective_through
                {
                    true
                } else {
                    !self.is_live_at(*reversal, accepted_prefix, effective_through)
                }
            }
        }
    }

    /// The sum of live applications against `target`'s leg `ordinal`, using the oracle's own limb arithmetic.
    fn applied_to_int(&self, target: usize, ordinal: usize) -> Int {
        let mut sum = Int::zero();
        for (_, e) in self
            .journal
            .iter()
            .enumerate()
            .filter(|(i, e)| self.carries_open_items(e) && self.is_live(*i))
        {
            for s in e
                .settles
                .iter()
                .filter(|s| s.target == target && s.ordinal == ordinal)
            {
                sum = sum.add(&Int::from_i128(s.mantissa));
            }
        }
        sum
    }

    /// The sum of live applications against `target`'s leg `ordinal`.
    fn applied_to(&self, target: usize, ordinal: usize) -> i128 {
        self.applied_to_int(target, ordinal)
            .to_i128()
            .unwrap_or(i128::MAX)
    }

    /// The literal open-item fold: every leg of every live posted entry →
    /// `(original, applied against it, applied out of it)`.
    #[must_use]
    pub fn open_items(&self) -> BTreeMap<(usize, usize), (i128, i128, i128)> {
        let mut out = BTreeMap::new();
        for (i, e) in self.journal.iter().enumerate() {
            if !self.carries_open_items(e) || !self.is_live(i) {
                continue;
            }
            for (o, leg) in e.legs.iter().enumerate() {
                let mut out_of = Int::zero();
                for s in e.settles.iter().filter(|s| s.leg == o) {
                    out_of = out_of.add(&Int::from_i128(s.mantissa));
                }
                out.insert(
                    (i, o),
                    (
                        leg.mantissa,
                        self.applied_to(i, o),
                        out_of.to_i128().unwrap_or(i128::MAX),
                    ),
                );
            }
        }
        out
    }

    #[must_use]
    pub fn journal_len(&self) -> usize {
        self.journal.len()
    }

    /// The literal availability fold of one account over the whole journal:
    /// posted legs of posting entries, legs of holds with no resolution yet,
    /// and the count of entries that posted, reserved, or released on it.
    #[must_use]
    pub fn availability(&self, account: &str) -> Availability {
        self.availability_in(account, None)
    }

    /// [`Self::availability`] restricted to one period's cell (a budget cap,
    /// plan §5.5): entries effective in `period` post and reserve there, and
    /// a resolution releases in its hold's period. `None` is the lifetime
    /// cell.
    #[must_use]
    pub fn availability_in(&self, account: &str, period: Option<&str>) -> Availability {
        let in_period = |e: &Entry| period.is_none_or(|p| e.period == p);
        let mut a = Availability {
            debits_posted: Int::zero(),
            credits_posted: Int::zero(),
            debits_pending: Int::zero(),
            credits_pending: Int::zero(),
            generation: 0,
        };
        for (i, e) in self.journal.iter().enumerate() {
            let mut touched = false;
            for l in e
                .legs
                .iter()
                .filter(|l| l.account == account && in_period(e))
            {
                touched = true;
                let m = Int::from_i128(l.mantissa);
                let slot = match (e.class.as_str(), l.side) {
                    ("Pending", _) if self.resolved.contains_key(&i) => continue,
                    ("Pending", Side::Debit) => &mut a.debits_pending,
                    ("Pending", Side::Credit) => &mut a.credits_pending,
                    (_, Side::Debit) => &mut a.debits_posted,
                    (_, Side::Credit) => &mut a.credits_posted,
                };
                *slot = slot.add(&m);
            }
            // A resolution moves the cell of every account its hold reserved on.
            if let Some(t) = e.resolves
                && in_period(&self.journal[t])
                && self.journal[t].legs.iter().any(|l| l.account == account)
            {
                touched = true;
            }
            if touched {
                a.generation += 1;
            }
        }
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fa-g23: the oracle's literal copy is the registry's table, row for row.
    #[test]
    fn control_kinds_mirror_the_registry() {
        let classes = EntryClasses::embedded().unwrap();
        let reg = fa_registry::ControlKinds::embedded(&classes).unwrap();
        let mut rows: Vec<(u16, &str, &str)> = reg
            .rows
            .iter()
            .map(|r| (r.id, r.name.as_str(), r.class.as_str()))
            .collect();
        rows.sort_unstable();
        assert_eq!(rows, CONTROL_KINDS);
        for r in &reg.reserved {
            assert_eq!(control_kind_class(r.id), None, "{} is reserved", r.name);
        }
    }

    #[test]
    fn limb_arithmetic_agrees_with_i128_on_the_edges() {
        let cases = [
            0i128,
            1,
            -1,
            i128::MAX,
            i128::MIN + 1,
            i128::MIN,
            1 << 32,
            -(1 << 32),
            (1 << 64) + 7,
            -((1 << 96) + 3),
        ];
        for &a in &cases {
            assert_eq!(Int::from_i128(a).to_i128(), Some(a), "{a}");
            for &b in &cases {
                if let Some(s) = a.checked_add(b) {
                    assert_eq!(
                        Int::from_i128(a).add(&Int::from_i128(b)).to_i128(),
                        Some(s),
                        "{a} + {b}"
                    );
                }
                if let Some(d) = a.checked_sub(b) {
                    assert_eq!(
                        Int::from_i128(a).sub(&Int::from_i128(b)).to_i128(),
                        Some(d),
                        "{a} - {b}"
                    );
                }
                if let Some(p) = a.checked_mul(b) {
                    assert_eq!(
                        Int::from_i128(a).mul(&Int::from_i128(b)).to_i128(),
                        Some(p),
                        "{a} * {b}"
                    );
                }
                if b != 0 && !(a == i128::MIN && b == -1) {
                    let (q, r) = Int::from_i128(a).div_rem(&Int::from_i128(b)).unwrap();
                    assert_eq!(q.to_i128(), Some(a / b), "{a} / {b}");
                    assert_eq!(r.to_i128(), Some(a % b), "{a} % {b}");
                }
            }
        }
        assert_eq!(Int::from_i128(7).div_rem(&Int::zero()), None);
        // i128::MIN / -1 overflows i128, but succeeds in Int and round-trips to u128.
        let (q_min, r_min) = Int::from_i128(i128::MIN)
            .div_rem(&Int::from_i128(-1))
            .unwrap();
        assert_eq!(q_min.to_i128(), None);
        assert_eq!(q_min.to_u128(), Some(1u128 << 127));
        assert!(r_min.is_zero());

        // Multi-limb exact product & division beyond 128 bits.
        let max_u128 = Int::from_u128(u128::MAX);
        let prod = max_u128.mul(&max_u128);
        let (q_back, r_back) = prod.div_rem(&max_u128).unwrap();
        assert_eq!(q_back, max_u128);
        assert!(r_back.is_zero());

        let big = Int::from_i128(i128::MAX).add(&Int::from_i128(i128::MAX));
        assert_eq!(big.to_i128(), None);
        assert_eq!(
            big.sub(&Int::from_i128(i128::MAX)).to_i128(),
            Some(i128::MAX)
        );
    }

    #[test]
    fn the_model_posts_refuses_reverses_and_folds_in_the_obvious_way() {
        let cal = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let mut o = Oracle::new(cal);
        o.add_account(Account {
            code: "1000".into(),
            is_leaf: true,
            unit: Some(1),
        });
        o.add_account(Account {
            code: "6000".into(),
            is_leaf: true,
            unit: Some(1),
        });
        o.add_account(Account {
            code: "1".into(),
            is_leaf: false,
            unit: Some(1),
        });
        o.create_periods(2026);
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        let legs = |d: i128, c: i128| {
            vec![
                Leg {
                    side: Side::Debit,
                    account: "6000".into(),
                    unit: 1,
                    entity: None,
                    mantissa: d,
                },
                Leg {
                    side: Side::Credit,
                    account: "1000".into(),
                    unit: 1,
                    entity: None,
                    mantissa: c,
                },
            ]
        };
        let intent = |class: &str, legs: Vec<Leg>, key: &[u8], reverses: Option<usize>| Intent {
            class: class.into(),
            date: day,
            discriminator: None,
            legs,
            key: key.to_vec(),
            ops: vec!["post".into()],
            approvals: 0,
            reverses,
            supersession_reason: 1,
            resolves: None,
            settles: Vec::new(),
        };
        assert_eq!(
            o.post(&intent("Original", legs(5, 5), b"a", None)),
            Verdict::Refused {
                code: code::PERIOD_LAW
            }
        );
        let march = "FY2026-P03".to_string();
        assert_eq!(
            o.transition(&march, PeriodTransition::Open),
            Ok((PeriodState::Future, PeriodState::Open))
        );
        assert_eq!(
            o.post(&intent("Original", legs(5, 5), b"a", None)),
            Verdict::Posted {
                index: 0,
                period: march.clone()
            }
        );
        // Identical retry: recorded. Same key, different content: conflict.
        assert_eq!(
            o.post(&intent("Original", legs(5, 5), b"a", None)),
            Verdict::Recorded { index: 0 }
        );
        assert_eq!(
            o.post(&intent("Original", legs(9, 9), b"a", None)),
            Verdict::Refused {
                code: code::IDEMPOTENCY_CONFLICT
            }
        );
        assert_eq!(
            o.post(&intent("Original", legs(5, 4), b"b", None)),
            Verdict::Refused {
                code: code::UNBALANCED
            }
        );
        // fa-ih4: a fiscal year nobody created, and a unit id units.toml
        // does not register, are refusals of their own.
        let mut ahead = intent("Original", legs(5, 5), b"ahead", None);
        ahead.date = DateDay::from_ymd(2028, 2, 10).unwrap();
        assert_eq!(
            o.post(&ahead),
            Verdict::Refused {
                code: code::PERIOD_UNKNOWN
            }
        );
        let mut raw = intent("Original", legs(5, 5), b"raw-unit", None);
        for leg in &mut raw.legs {
            leg.unit = 4242;
        }
        assert_eq!(
            o.post(&raw),
            Verdict::Refused {
                code: code::UNIT_UNREGISTERED
            }
        );
        assert_eq!(
            o.post(&intent("Replacement", legs(5, 5), b"c", None)),
            Verdict::Refused {
                code: code::REPLACEMENT_UNPAIRED
            }
        );
        // Reversal: exact side-swap only, one per target.
        let swapped = vec![
            Leg {
                side: Side::Credit,
                account: "6000".into(),
                unit: 1,
                entity: None,
                mantissa: 5,
            },
            Leg {
                side: Side::Debit,
                account: "1000".into(),
                unit: 1,
                entity: None,
                mantissa: 5,
            },
        ];
        assert_eq!(
            o.post(&intent("Reversal", swapped.clone(), b"r0", None)),
            Verdict::Refused {
                code: code::REVERSAL_TARGET
            }
        );
        assert_eq!(
            o.post(&intent("Reversal", legs(5, 5), b"r1", Some(0))),
            Verdict::Refused {
                code: code::REVERSAL_SHAPE
            }
        );
        assert_eq!(
            o.post(&intent("Reversal", swapped.clone(), b"r1", Some(0))),
            Verdict::Posted {
                index: 1,
                period: march.clone()
            }
        );
        assert_eq!(
            o.post(&intent("Reversal", swapped.clone(), b"r1", Some(0))),
            Verdict::Recorded { index: 1 }
        );
        let mut later = intent("Reversal", swapped, b"r2", Some(0));
        later.date = DateDay::from_ymd(2026, 3, 20).unwrap();
        assert_eq!(
            o.post(&later),
            Verdict::Refused {
                code: code::ALREADY_REVERSED
            }
        );
        let f = o.fold(&march);
        assert_eq!(f[&("1000".to_string(), 1)].credits, Int::from_i128(5));
        assert_eq!(f[&("1000".to_string(), 1)].debits, Int::from_i128(5));
        assert_eq!(f[&("6000".to_string(), 1)].entry_count, 2);
        assert_eq!(o.entry(0).unwrap().date, day);
        assert!(o.stock_at(day.pred().unwrap(), o.journal_len()).is_empty());
        let original = o.stock_at(day, 1);
        assert_eq!(original[&("6000".to_string(), 1)].debits, Int::from_i128(5));
        assert_eq!(original[&("6000".to_string(), 1)].credits, Int::zero());
        assert_eq!(o.stock_at(day, 2), f);
        assert_eq!(o.activity_at(&[&march, &march], 1), original);
        assert_eq!(
            o.transition(&march, PeriodTransition::Lock),
            Err(code::TRANSITION)
        );
    }

    /// Period authority in the obvious way (plan §14.2, Appendix C): the
    /// authority is judged before the period exists for the oracle, Lock and
    /// SoftClosed→Reopen need one Human approver who is not the preparer,
    /// a stale approval refuses before the rule, and a case-bound reopen
    /// fails closed.
    #[test]
    fn period_authority_in_the_obvious_way() {
        let cal = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let mut o = Oracle::new(cal);
        o.create_periods(2026);
        let march = "FY2026-P03";
        let full = Authority {
            token: 1,
            holder: 7,
            profile: "Human".into(),
            ops: vec!["close".into(), "reopen".into()],
            books: Some(vec![9]),
            expires_at: Some(10),
        };
        let human = |p: u128, epoch: u64| Recorded {
            approval: sod::Approval {
                principal: p,
                profile: "Human".into(),
                op: "approve".into(),
            },
            epoch,
        };
        let open = PeriodTransition::Open;
        // Authority first: an unknown period is never reached.
        let reopen_only = Authority {
            ops: vec!["reopen".into()],
            ..full.clone()
        };
        let cases: [(Authority, u128, u128, u64, &str); 5] = [
            (full.clone(), 8, 9, 0, code::CAPABILITY),
            (reopen_only, 7, 9, 0, code::CAPABILITY),
            (full.clone(), 7, 4, 0, code::CAPABILITY),
            (full.clone(), 7, 9, 10, code::EXPIRED),
            (
                Authority {
                    profile: "Agent".into(),
                    ..full.clone()
                },
                7,
                9,
                0,
                code::AGENT_TRUNK,
            ),
        ];
        for (authority, actor, book, at, want) in cases {
            assert_eq!(
                o.transition_under("FY2099-P01", open, actor, &authority, book, at, &[]),
                Err(want),
                "{authority:?} actor {actor} book {book} at {at}"
            );
        }
        let under = |o: &mut Oracle, t, approvals: &[Recorded]| {
            o.transition_under(march, t, 7, &full, 9, 3, approvals)
        };
        assert_eq!(
            under(&mut o, open, &[]),
            Ok((PeriodState::Future, PeriodState::Open))
        );
        assert_eq!(
            under(&mut o, PeriodTransition::Close, &[]),
            Ok((PeriodState::Open, PeriodState::Closed))
        );
        assert_eq!(
            under(&mut o, PeriodTransition::Lock, &[]),
            Err(code::APPROVALS)
        );
        assert_eq!(
            under(&mut o, PeriodTransition::Lock, &[human(7, 0)]),
            Err(code::SOD)
        );
        let early = human(8, 0);
        o.activate_policy();
        assert_eq!(
            under(&mut o, PeriodTransition::Lock, &[early]),
            Err(code::STALE_APPROVAL)
        );
        assert_eq!(
            under(&mut o, PeriodTransition::Lock, &[human(8, 1)]),
            Ok((PeriodState::Closed, PeriodState::Locked))
        );
        let reopen = PeriodTransition::Reopen {
            to: PeriodState::Open,
        };
        assert_eq!(
            under(&mut o, reopen, &[human(8, 1), human(9, 1)]),
            Err(code::SOD),
            "Locked -> Reopen is case-bound and fails closed"
        );
        assert_eq!(
            under(&mut o, PeriodTransition::Close, &[]),
            Err(code::TRANSITION)
        );
        o.revoke(1);
        assert_eq!(under(&mut o, reopen, &[]), Err(code::REVOKED));
        // The main walk's entry point: the rule's approvers are supplied, a
        // case-bound reopen still refuses.
        let april = "FY2026-P04";
        assert!(o.transition(april, open).is_ok());
        assert!(o.transition(april, PeriodTransition::SoftClose).is_ok());
        assert_eq!(
            o.transition(april, reopen),
            Ok((PeriodState::SoftClosed, PeriodState::Open))
        );
        assert!(o.transition(april, PeriodTransition::Close).is_ok());
        assert_eq!(o.transition(april, reopen), Err(code::SOD));
    }

    /// The fa-ctf example (plan §5.4): cash 100 with a floor of 0; a pending
    /// outflow of 80 blocks a second 80 and an unrelated posted 30, a pending
    /// inflow never finances, and resolving the hold releases all of it.
    #[test]
    fn reserved_availability_in_the_obvious_way() {
        let cal = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let mut o = Oracle::new(cal);
        for code in ["1000", "3000", "6000"] {
            o.add_account(Account {
                code: code.into(),
                is_leaf: true,
                unit: Some(1),
            });
        }
        o.set_limit(
            "1000",
            Limit {
                normal: Side::Debit,
                lower: Some(0),
                upper: Some(1_000),
                per_period: false,
            },
        );
        o.create_periods(2026);
        o.transition("FY2026-P03", PeriodTransition::Open).unwrap();
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        let mv = |dr: &str, cr: &str, m: i128| {
            vec![
                Leg {
                    side: Side::Debit,
                    account: dr.into(),
                    unit: 1,
                    entity: None,
                    mantissa: m,
                },
                Leg {
                    side: Side::Credit,
                    account: cr.into(),
                    unit: 1,
                    entity: None,
                    mantissa: m,
                },
            ]
        };
        let intent = |class: &str, legs: Vec<Leg>, key: &[u8], resolves: Option<Resolve>| Intent {
            class: class.into(),
            date: day,
            discriminator: None,
            legs,
            key: key.to_vec(),
            ops: vec!["post".into()],
            approvals: 0,
            reverses: None,
            supersession_reason: 1,
            resolves,
            settles: Vec::new(),
        };
        let refused = |code| Verdict::Refused { code };
        // Funding 100 is an inflow; an outflow of 101 breaches the floor.
        assert!(matches!(
            o.post(&intent("Original", mv("1000", "3000", 100), b"fund", None)),
            Verdict::Posted { index: 0, .. }
        ));
        assert_eq!(
            o.post(&intent("Original", mv("6000", "1000", 101), b"over", None)),
            refused(code::AVAILABILITY_LOWER)
        );
        // A hold of 80 out reserves; a second 80 and a posted 30 are refused.
        assert!(matches!(
            o.post(&intent("Pending", mv("6000", "1000", 80), b"hold", None)),
            Verdict::Posted { index: 1, .. }
        ));
        assert_eq!(
            o.post(&intent("Pending", mv("6000", "1000", 80), b"hold2", None)),
            refused(code::AVAILABILITY_LOWER)
        );
        assert_eq!(
            o.post(&intent("Original", mv("6000", "1000", 30), b"spend", None)),
            refused(code::AVAILABILITY_LOWER)
        );
        // A pending inflow of 500 does not finance the 30.
        assert!(matches!(
            o.post(&intent("Pending", mv("1000", "3000", 500), b"in", None)),
            Verdict::Posted { index: 2, .. }
        ));
        assert_eq!(
            o.post(&intent("Original", mv("6000", "1000", 30), b"spend", None)),
            refused(code::AVAILABILITY_LOWER)
        );
        // …but it does count against the cap: 100 + 500 + 401 > 1000.
        assert_eq!(
            o.post(&intent("Original", mv("1000", "3000", 401), b"cap", None)),
            refused(code::AVAILABILITY_UPPER)
        );
        // Posting 60 of the 80 hold releases all 80: pending −80, posted +60,
        // and is admitted although it moves value out.
        let posts = Resolve {
            target: 1,
            posts: Some(vec![0, 1]),
        };
        assert!(matches!(
            o.post(&intent(
                "Resolution",
                mv("6000", "1000", 60),
                b"r",
                Some(posts)
            )),
            Verdict::Posted { index: 3, .. }
        ));
        let a = o.availability("1000");
        assert_eq!(
            (
                a.debits_posted.to_i128(),
                a.credits_posted.to_i128(),
                a.debits_pending.to_i128(),
                a.credits_pending.to_i128(),
                a.generation
            ),
            (Some(100), Some(60), Some(500), Some(0), 4)
        );
        // Now 40 is available: 40 posts, 41 does not.
        assert_eq!(
            o.post(&intent("Original", mv("6000", "1000", 41), b"41", None)),
            refused(code::AVAILABILITY_LOWER)
        );
        assert!(matches!(
            o.post(&intent("Original", mv("6000", "1000", 40), b"40", None)),
            Verdict::Posted { index: 4, .. }
        ));
        // Voiding the pending inflow is always admissible.
        let void = Resolve {
            target: 2,
            posts: None,
        };
        assert!(matches!(
            o.post(&intent("Resolution", Vec::new(), b"v", Some(void))),
            Verdict::Posted { index: 5, .. }
        ));
        assert_eq!(o.availability("1000").debits_pending.to_i128(), Some(0));
    }

    /// Plan §5.4, §7.1a in the model: strictly increasing ticks, the anchor
    /// is the latest tick when the hold posts, due at equality, Posts refused
    /// once due (Voids not), and the sweep's batches walk the due holds in
    /// journal order behind a cursor that restarts with a new tick.
    #[test]
    fn ticks_anchor_timed_holds_and_the_sweep_batches_behind_a_cursor() {
        let cal = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let mut o = Oracle::new(cal);
        for code in ["1000", "6000"] {
            o.add_account(Account {
                code: code.into(),
                is_leaf: true,
                unit: Some(1),
            });
        }
        o.create_periods(2026);
        o.transition("FY2026-P03", PeriodTransition::Open).unwrap();
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        let hold_legs = vec![
            Leg {
                side: Side::Debit,
                account: "6000".into(),
                unit: 1,
                entity: None,
                mantissa: 10,
            },
            Leg {
                side: Side::Credit,
                account: "1000".into(),
                unit: 1,
                entity: None,
                mantissa: 10,
            },
        ];
        let intent = |class: &str, legs: Vec<Leg>, key: &[u8], resolves: Option<Resolve>| Intent {
            class: class.into(),
            date: day,
            discriminator: None,
            legs,
            key: key.to_vec(),
            ops: vec!["post".into()],
            approvals: 0,
            reverses: None,
            supersession_reason: 1,
            resolves,
            settles: Vec::new(),
        };
        let refused = |code| Verdict::Refused { code };
        // No tick yet: a timed hold has nothing to anchor on.
        assert_eq!(
            o.post_timed(&intent("Pending", hold_legs.clone(), b"h0", None), 5),
            refused(code::TICK_MISSING)
        );
        assert_eq!(o.record_tick(100), Ok(0));
        assert_eq!(o.record_tick(100), Err(code::TICK_ORDER));
        assert_eq!(o.record_tick(99), Err(code::TICK_ORDER));
        assert_eq!(
            o.post_timed(&intent("Pending", hold_legs.clone(), b"h0", None), u64::MAX),
            refused(code::DEADLINE_OVERFLOW)
        );
        // Holds 0..4 anchored at 100 with timeouts 5, 10, 10, 20; hold 4 untimed.
        for (i, t) in [5u64, 10, 10, 20].iter().enumerate() {
            let key = format!("h{i}").into_bytes();
            assert!(matches!(
                o.post_timed(&intent("Pending", hold_legs.clone(), &key, None), *t),
                Verdict::Posted { index, .. } if index == i
            ));
        }
        assert!(matches!(
            o.post(&intent("Pending", hold_legs.clone(), b"h4", None)),
            Verdict::Posted { index: 4, .. }
        ));
        assert_eq!(o.deadline(1), Some(110));
        assert_eq!(o.deadline(4), None);
        // Tick 105: hold 0 is due at equality; the Posts on it is refused.
        o.record_tick(105).unwrap();
        assert_eq!(o.due(), vec![0]);
        let posts = |target| Resolve {
            target,
            posts: Some(vec![0, 1]),
        };
        assert_eq!(
            o.post(&intent(
                "Resolution",
                hold_legs.clone(),
                b"p0",
                Some(posts(0))
            )),
            refused(code::HOLD_DUE)
        );
        // Tick 110: holds 0, 1, 2 are due; batches of 2 walk them.
        o.record_tick(110).unwrap();
        assert_eq!(o.due(), vec![0, 1, 2]);
        let b1 = o.sweep_batch(2).unwrap().unwrap();
        assert_eq!(b1.tick, 110);
        assert_eq!(b1.expired, vec![(0, 5), (1, 6)]);
        assert_eq!(b1.remaining_due, 1);
        // Due-but-unswept stays pending; a manual Voids on it still wins.
        assert_eq!(o.due(), vec![2]);
        assert!(matches!(
            o.post(&intent(
                "Resolution",
                Vec::new(),
                b"v2",
                Some(Resolve {
                    target: 2,
                    posts: None
                })
            )),
            Verdict::Posted { index: 7, .. }
        ));
        assert_eq!(o.sweep_batch(2).unwrap(), None);
        // A manual void of an expired hold is the one-resolution conflict.
        assert_eq!(
            o.post(&intent(
                "Resolution",
                Vec::new(),
                b"v0",
                Some(Resolve {
                    target: 0,
                    posts: None
                })
            )),
            refused(code::ALREADY_RESOLVED)
        );
        // A new tick restarts the epoch: hold 3 (deadline 120) is due.
        o.record_tick(120).unwrap();
        let b2 = o.sweep_batch(2).unwrap().unwrap();
        assert_eq!(b2.expired, vec![(3, 8)]);
        assert_eq!(b2.remaining_due, 0);
        assert!(o.due().is_empty());
        assert_eq!(o.availability("1000").credits_pending.to_i128(), Some(10));
    }

    #[test]
    fn time_tick_rejects_out_of_range_and_recovers_from_uncorroborated_forward_jump() {
        let cal = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let mut o = Oracle::new(cal);
        for code in ["1000", "3000", "6000"] {
            o.add_account(Account {
                code: code.into(),
                is_leaf: true,
                unit: Some(1),
            });
        }
        o.create_periods(2026);
        o.transition("FY2026-P03", PeriodTransition::Open).unwrap();
        let day = DateDay::from_ymd(2026, 3, 15).unwrap();
        let leg = |side, account: &str, mantissa| Leg {
            side,
            account: account.into(),
            unit: 1,
            entity: None,
            mantissa,
        };
        let intent = |class: &str, legs: Vec<Leg>, key: &[u8], resolves| Intent {
            class: class.into(),
            date: day,
            discriminator: None,
            legs,
            key: key.to_vec(),
            ops: vec!["post".into()],
            approvals: 0,
            reverses: None,
            supersession_reason: 1,
            resolves,
            settles: Vec::new(),
        };
        assert!(matches!(
            o.post(&intent(
                "Original",
                vec![
                    leg(Side::Debit, "1000", 100),
                    leg(Side::Credit, "3000", 100)
                ],
                b"fund",
                None,
            )),
            Verdict::Posted { .. }
        ));
        assert_eq!(o.record_tick(u64::MAX), Err(code::STRUCTURE));
        assert_eq!(o.record_tick(MAX_TICK_UTC_NS + 1), Err(code::STRUCTURE));
        assert_eq!(o.record_tick(1_000), Ok(0));
        assert_eq!(o.latest_corroborated_tick(), Some(1_000));

        let hold_legs = vec![leg(Side::Debit, "6000", 10), leg(Side::Credit, "1000", 10)];
        assert!(matches!(
            o.post_timed(&intent("Pending", hold_legs.clone(), b"h0", None), 20),
            Verdict::Posted { index: 1, .. }
        ));
        assert_eq!(o.deadline(1), Some(1_020));

        // A jump beyond MAX_CLOCK_SKEW_NS is downgraded to uncorroborated even if
        // the caller requests monotonic_ok = true.
        let jumped = 1_000 + MAX_CLOCK_SKEW_NS + 500;
        assert_eq!(o.record_tick(jumped), Ok(1));
        assert_eq!(o.latest_tick(), Some(jumped));
        assert_eq!(o.latest_corroborated_tick(), Some(1_000));
        assert_eq!(o.sweep_batch(1), Err(code::TICK_UNCORROBORATED));
        assert_eq!(o.sweep_reversals_batch(1), Err(code::TICK_UNCORROBORATED));

        // A timed hold posted after the uncorroborated jump still anchors on the
        // latest corroborated tick (1_000), and subsequent honest ticks (> 1_000)
        // are admitted and restore sweep eligibility.
        assert!(matches!(
            o.post_timed(&intent("Pending", hold_legs, b"h1", None), 30),
            Verdict::Posted { index: 2, .. }
        ));
        assert_eq!(o.deadline(2), Some(1_030));
        assert_eq!(o.record_tick(1_000), Err(code::TICK_ORDER));
        assert_eq!(o.record_tick(1_020), Ok(2));
        assert_eq!(o.latest_corroborated_tick(), Some(1_020));
        let swept = o.sweep_batch(2).unwrap().unwrap();
        assert_eq!(swept.tick, 1_020);
        assert_eq!(swept.expired, vec![(1, 3)]);
    }

    #[test]
    fn oracle_transition_table_matches_fa_time_exhaustively() {
        let states = [
            PeriodState::Future,
            PeriodState::Open,
            PeriodState::SoftClosed,
            PeriodState::Closed,
            PeriodState::Locked,
        ];
        let mut transitions = vec![
            PeriodTransition::Open,
            PeriodTransition::SoftClose,
            PeriodTransition::Close,
            PeriodTransition::Lock,
        ];
        for &to in &states {
            transitions.push(PeriodTransition::Reopen { to });
        }
        for &from in &states {
            for &t in &transitions {
                assert_eq!(
                    admissibility::oracle_transition(from, t),
                    fa_time::period::transition(from, t).map_err(|_| ()),
                    "mismatch on ({from:?}, {t:?})"
                );
            }
        }
    }
}
