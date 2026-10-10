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

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use fa_registry::{Admissibility, Decision, EntryClasses};
use fa_time::period::transition;
use fa_time::{DateDay, FiscalCalendar, PeriodDef, PeriodState, PeriodTransition, resolve_period};

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
        let negated = Self {
            neg: !rhs.neg,
            mag: rhs.mag.clone(),
        }
        .trim();
        self.add(&negated)
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limit {
    pub normal: Side,
    pub lower: Option<i128>,
    pub upper: Option<i128>,
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
    pub const PERIOD_LAW: &str = "FA-REF-010";
    pub const CAPABILITY: &str = "FA-REF-011";
    pub const APPROVALS: &str = "FA-REF-012";
    pub const PERIOD_RESOLVE: &str = "FA-REF-020";
    pub const PERIOD_UNKNOWN: &str = "FA-REF-021";
    pub const IDEMPOTENCY_CONFLICT: &str = "FA-REF-032";
    pub const TRANSITION: &str = "FA-REF-040";
    pub const REVERSAL_TARGET: &str = "FA-REF-050";
    pub const REVERSAL_SHAPE: &str = "FA-REF-051";
    pub const ALREADY_REVERSED: &str = "FA-REF-052";
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
    pub const STRUCTURE: &str = "FA-REF-100";
    pub const CONTROL_VIA_POST: &str = "FA-REF-101";
    pub const CLASS_NOT_IMPLEMENTED: &str = "FA-REF-102";
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
    resolves: Option<Resolve>,
    settles: Vec<Settle>,
    key: Vec<u8>,
}

impl Content {
    fn of(i: &Intent) -> Self {
        Self {
            class: i.class.clone(),
            date: i.date,
            discriminator: i.discriminator.clone(),
            legs: i.legs.clone(),
            reverses: i.reverses,
            resolves: i.resolves.clone(),
            settles: i.settles.clone(),
            key: i.key.clone(),
        }
    }
}

/// One cell of the oracle's fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    pub debits: Int,
    pub credits: Int,
    pub entry_count: u64,
}

pub struct Oracle {
    calendar: FiscalCalendar,
    accounts: BTreeMap<String, Account>,
    /// Period code → (definition, state). Only created periods exist.
    periods: BTreeMap<String, (PeriodDef, PeriodState)>,
    journal: Vec<Entry>,
    /// Key → (journal index, content) for key-identified entries.
    keys: BTreeMap<Vec<u8>, (usize, Content)>,
    /// Reversed target index → (reversal index, content).
    reversed: BTreeMap<usize, (usize, Content)>,
    /// Resolved pending index → (resolution index, content).
    resolved: BTreeMap<usize, (usize, Content)>,
    /// Limited account code → its limit.
    limits: BTreeMap<String, Limit>,
    classes: EntryClasses,
    matrix: Admissibility,
}

impl Oracle {
    pub fn new(calendar: FiscalCalendar) -> Self {
        let classes = EntryClasses::embedded().expect("entry_classes.toml");
        let matrix = Admissibility::embedded(&classes).expect("admissibility.toml");
        Self {
            calendar,
            accounts: BTreeMap::new(),
            periods: BTreeMap::new(),
            journal: Vec::new(),
            keys: BTreeMap::new(),
            reversed: BTreeMap::new(),
            resolved: BTreeMap::new(),
            limits: BTreeMap::new(),
            classes,
            matrix,
        }
    }

    pub fn add_account(&mut self, a: Account) {
        self.accounts.insert(a.code.clone(), a);
    }

    /// Give an account a balance limit (plan §5.4); the chart declares it.
    pub fn set_limit(&mut self, code: &str, limit: Limit) {
        self.limits.insert(code.to_string(), limit);
    }

    /// Create a fiscal year's periods in `Future`.
    pub fn create_periods(&mut self, fy: i32) {
        for p in self.calendar.periods_for_year(fy).expect("periods") {
            self.periods
                .insert(p.code.clone(), (p, PeriodState::Future));
        }
    }

    pub fn period_state(&self, code: &str) -> Option<PeriodState> {
        self.periods.get(code).map(|(_, s)| *s)
    }

    pub fn entry(&self, index: usize) -> Option<&Entry> {
        self.journal.get(index)
    }

    pub fn transition(
        &mut self,
        code: &str,
        t: PeriodTransition,
    ) -> Result<(PeriodState, PeriodState), &'static str> {
        let Some((_, state)) = self.periods.get_mut(code) else {
            return Err(code::PERIOD_UNKNOWN);
        };
        let to = transition(*state, t).map_err(|_| code::TRANSITION)?;
        let from = *state;
        *state = to;
        Ok((from, to))
    }

    pub fn post(&mut self, intent: &Intent) -> Verdict {
        // 1. Structure.
        let Some(class) = self.classes.by_name(&intent.class) else {
            return Verdict::Refused {
                code: code::STRUCTURE,
            };
        };
        let is_resolution = intent.class == "Resolution";
        let is_release =
            is_resolution && intent.resolves.as_ref().is_some_and(|r| r.posts.is_none());
        let shape_ok = match (&intent.resolves, is_resolution) {
            (None, false) => intent.legs.len() >= 2,
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
            || intent.legs.iter().any(|l| l.mantissa < 0)
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
        // 1b. The supported subset, and a Reversal's target presence.
        let is_reversal = intent.class == "Reversal";
        if !matches!(
            intent.class.as_str(),
            "Original" | "Adjusting" | "Reversal" | "Pending" | "Resolution"
        ) {
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
                "Reversal" => {
                    return Verdict::Refused {
                        code: code::SETTLE_SHAPE,
                    };
                }
                _ => {
                    return Verdict::Refused {
                        code: code::CLASS_NOT_IMPLEMENTED,
                    };
                }
            }
            let mut named = BTreeSet::new();
            let mut sum: i128 = 0;
            for s in mine {
                if s.mantissa <= 0 || !named.insert((s.target, s.ordinal)) {
                    return Verdict::Refused {
                        code: code::SETTLE_SHAPE,
                    };
                }
                sum = match sum.checked_add(s.mantissa) {
                    Some(v) => v,
                    None => {
                        return Verdict::Refused {
                            code: code::SETTLE_SHAPE,
                        };
                    }
                };
            }
            if sum > leg.mantissa {
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
        // 2. Balance per unit.
        let mut per_unit: BTreeMap<u32, (Int, Int)> = BTreeMap::new();
        for l in &intent.legs {
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
        let Ok(period) = resolve_period(&defs, intent.date, intent.discriminator.as_deref()) else {
            return Verdict::Refused {
                code: code::PERIOD_RESOLVE,
            };
        };
        let period = period.code.clone();
        // 4. Identity: the recorded outcome when the content is the same,
        //    a conflict when it is not — before any law is re-checked.
        let content = Content::of(intent);
        let existing = match (intent.reverses, &intent.resolves) {
            (Some(target), _) => self.reversed.get(&target),
            (None, Some(r)) => self.resolved.get(&r.target),
            (None, None) => self.keys.get(&intent.key),
        };
        if let Some((index, recorded)) = existing {
            return if *recorded == content {
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
        // 5. Period law against the period's current state (Future when never created).
        let state = self.period_state(&period).unwrap_or(PeriodState::Future);
        match self
            .matrix
            .decide_disposition(&intent.class, state, is_release)
        {
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
            if a.unit.is_some_and(|u| u != l.unit) {
                return Verdict::Refused {
                    code: code::UNIT_POLICY,
                };
            }
        }
        // 7a. Application law (plan §5.7): a witnessed, live, posted target
        //     leg on the same account and unit with the opposite side, within
        //     its open amount (counting earlier settlements of this intent).
        let mut used: BTreeMap<(usize, usize), i128> = BTreeMap::new();
        for s in &intent.settles {
            let leg = &intent.legs[s.leg];
            let Some(target) = self.journal.get(s.target) else {
                return Verdict::Refused {
                    code: code::SETTLE_TARGET,
                };
            };
            if !Self::carries_open_items(target) || !self.is_live(s.target) {
                return Verdict::Refused {
                    code: code::SETTLE_TARGET,
                };
            }
            let Some(tl) = target.legs.get(s.ordinal) else {
                return Verdict::Refused {
                    code: code::SETTLE_SHAPE,
                };
            };
            if tl.account != leg.account || tl.unit != leg.unit || tl.side == leg.side {
                return Verdict::Refused {
                    code: code::SETTLE_SHAPE,
                };
            }
            let before = used.get(&(s.target, s.ordinal)).copied().unwrap_or(0);
            let consumed: i128 = target
                .settles
                .iter()
                .filter(|t| t.leg == s.ordinal)
                .map(|t| t.mantissa)
                .sum();
            let open = tl.mantissa - consumed - self.applied_to(s.target, s.ordinal) - before;
            if s.mantissa > open {
                return Verdict::Refused {
                    code: code::OVER_APPLICATION,
                };
            }
            used.insert((s.target, s.ordinal), before + s.mantissa);
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
                "Original" | "Adjusting" | "Reversal"
            ) || (original.class == "Resolution" && !original.legs.is_empty());
            if !reversible {
                return Verdict::Refused {
                    code: code::REVERSAL_TARGET,
                };
            }
            let swapped = original.legs.len() == intent.legs.len()
                && original.legs.iter().zip(&intent.legs).all(|(o, r)| {
                    o.account == r.account
                        && o.unit == r.unit
                        && o.mantissa == r.mantissa
                        && o.side.flipped() == r.side
                });
            if !swapped {
                return Verdict::Refused {
                    code: code::REVERSAL_SHAPE,
                };
            }
            // 7c. Application effects (plan §5.7, §8.2): an item with live
            //     applications is not reversed; re-applying by reversing a
            //     reversal waits for the full netting law.
            for i in 0..original.legs.len() {
                if self.applied_to(target, i) != 0 {
                    return Verdict::Refused {
                        code: code::LIVE_APPLICATIONS,
                    };
                }
            }
            if original.class == "Reversal"
                && original
                    .reverses
                    .and_then(|g| self.journal.get(g))
                    .is_some_and(|g| !g.settles.is_empty())
            {
                return Verdict::Refused {
                    code: code::CLASS_NOT_IMPLEMENTED,
                };
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
        // 7d. Reserved availability (plan §5.4): each limited account the
        //     entry moves, in order of first appearance (the entry's legs,
        //     then a resolved hold's legs), judged on the literal fold.
        let released: Vec<Leg> = intent
            .resolves
            .as_ref()
            .and_then(|r| self.journal.get(r.target))
            .map(|t| t.legs.clone())
            .unwrap_or_default();
        let mut order: Vec<&str> = Vec::new();
        for l in intent.legs.iter().chain(&released) {
            if self.limits.contains_key(&l.account) && !order.contains(&l.account.as_str()) {
                order.push(&l.account);
            }
        }
        for account in order {
            let limit = &self.limits[account];
            let before = self.availability(account);
            let mut after = before.clone();
            let bump = |slot: &mut Int, m: i128, sign: bool| {
                let m = Int::from_i128(m);
                *slot = if sign { slot.add(&m) } else { slot.sub(&m) };
            };
            for l in intent.legs.iter().filter(|l| l.account == account) {
                match (intent.class.as_str(), l.side) {
                    ("Pending", Side::Debit) => bump(&mut after.debits_pending, l.mantissa, true),
                    ("Pending", Side::Credit) => bump(&mut after.credits_pending, l.mantissa, true),
                    (_, Side::Debit) => bump(&mut after.debits_posted, l.mantissa, true),
                    (_, Side::Credit) => bump(&mut after.credits_posted, l.mantissa, true),
                }
            }
            for l in released.iter().filter(|l| l.account == account) {
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
            legs: intent.legs.clone(),
            key: intent.key.clone(),
            reverses: intent.reverses,
            resolves: intent.resolves.as_ref().map(|r| r.target),
            settles: intent.settles.clone(),
        });
        match (intent.reverses, &intent.resolves) {
            (Some(target), _) => {
                self.reversed.insert(target, (index, content));
            }
            (None, Some(r)) => {
                self.resolved.insert(r.target, (index, content));
            }
            (None, None) => {
                self.keys.insert(intent.key.clone(), (index, content));
            }
        }
        Verdict::Posted { index, period }
    }

    /// The literal fold of one period: `(account, unit) → cell`.
    #[must_use]
    pub fn fold(&self, period: &str) -> BTreeMap<(String, u32), Cell> {
        self.activity_at(&[period], self.journal.len())
    }

    /// Stock from inception through an inclusive effective day, as known after
    /// `accepted_prefix` accepted monetary entries. This is an oracle journal
    /// count, not a substrate commit sequence: controls and metadata do not
    /// advance it. Tests must record the correspondence at each observation.
    ///
    /// Panics if the requested prefix extends beyond the oracle's journal.
    #[must_use]
    pub fn stock_at(&self, day: DateDay, accepted_prefix: usize) -> BTreeMap<(String, u32), Cell> {
        Self::fold_entries(
            self.journal[..accepted_prefix]
                .iter()
                .filter(|entry| entry.date <= day),
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
        Self::fold_entries(
            self.journal[..accepted_prefix]
                .iter()
                .filter(|entry| periods.contains(&entry.period.as_str())),
        )
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
    fn carries_open_items(e: &Entry) -> bool {
        matches!(e.class.as_str(), "Original" | "Adjusting")
            || (e.class == "Resolution" && !e.legs.is_empty())
    }

    /// Live unless a live reversal targets it (a reversed reversal revives).
    fn is_live(&self, index: usize) -> bool {
        match self.reversed.get(&index) {
            None => true,
            Some((reversal, _)) => !self.is_live(*reversal),
        }
    }

    /// The sum of live applications against `target`'s leg `ordinal`.
    fn applied_to(&self, target: usize, ordinal: usize) -> i128 {
        self.journal
            .iter()
            .enumerate()
            .filter(|(i, e)| Self::carries_open_items(e) && self.is_live(*i))
            .flat_map(|(_, e)| e.settles.iter())
            .filter(|s| s.target == target && s.ordinal == ordinal)
            .map(|s| s.mantissa)
            .sum()
    }

    /// The literal open-item fold: every leg of every live posted entry →
    /// `(original, applied against it, applied out of it)`.
    #[must_use]
    pub fn open_items(&self) -> BTreeMap<(usize, usize), (i128, i128, i128)> {
        let mut out = BTreeMap::new();
        for (i, e) in self.journal.iter().enumerate() {
            if !Self::carries_open_items(e) || !self.is_live(i) {
                continue;
            }
            for (o, leg) in e.legs.iter().enumerate() {
                let out_of: i128 = e
                    .settles
                    .iter()
                    .filter(|s| s.leg == o)
                    .map(|s| s.mantissa)
                    .sum();
                out.insert((i, o), (leg.mantissa, self.applied_to(i, o), out_of));
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
        let mut a = Availability {
            debits_posted: Int::zero(),
            credits_posted: Int::zero(),
            debits_pending: Int::zero(),
            credits_pending: Int::zero(),
            generation: 0,
        };
        for (i, e) in self.journal.iter().enumerate() {
            let mut touched = false;
            for l in e.legs.iter().filter(|l| l.account == account) {
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
            }
        }
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
                    mantissa: d,
                },
                Leg {
                    side: Side::Credit,
                    account: "1000".into(),
                    unit: 1,
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
        assert_eq!(
            o.post(&intent("Replacement", legs(5, 5), b"c", None)),
            Verdict::Refused {
                code: code::CLASS_NOT_IMPLEMENTED
            }
        );
        // Reversal: exact side-swap only, one per target.
        let swapped = vec![
            Leg {
                side: Side::Credit,
                account: "6000".into(),
                unit: 1,
                mantissa: 5,
            },
            Leg {
                side: Side::Debit,
                account: "1000".into(),
                unit: 1,
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
                    mantissa: m,
                },
                Leg {
                    side: Side::Credit,
                    account: cr.into(),
                    unit: 1,
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
}
