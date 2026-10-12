//! The reference oracle (plan §16.2).
//!
//! Everything here is the *obvious* implementation: canonical maps, linear
//! scans, and sign-magnitude limb integers written from scratch so that a
//! shared arithmetic bug in `fa-money` cannot make the differential green.
//! The oracle follows the specified refusal precedence — structure, control,
//! supported subset, balance, period resolution, identity (recorded outcome
//! or conflict), period law, accounts, reversal shape, resolution shape — and
//! returns the same
//! refusal codes as independent string constants, so a renumbering on either
//! side is a differential failure, never a silent agreement.
//!
//! Boundary: `std`, `fa-time`, and the registries. No `fa-money`, no
//! `fa-model`, no substrate.
//! Admission, transition and period lookup decisions are literal local
//! implementations of Appendix C and §7. Calendar generation walks civil
//! days independently; primitive date conversion and policy parsing still
//! share production code, so full oracle independence remains bounded.
//!
//! Period authority (plan §14.2, Appendix C PeriodControl) is modelled the
//! same way: an [`Authority`] is the plan's caveat list in plain values, the
//! admission point is an explicit input, revocations and the security policy
//! epoch are the oracle's own state, and the transition's SoD rule is looked
//! up literally in `sod_policy.toml` and judged by [`sod::verdict`].

#![forbid(unsafe_code)]
// Production decisions belong only in the comparison side of tests. The
// normal library build forbids them even through aliases or re-exports;
// statement-level expectations below pin all eight configured methods.
#![cfg_attr(not(test), forbid(clippy::disallowed_methods))]

pub mod evidence;
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
use fa_registry::{Admissibility, EntryClasses};
use fa_time::{
    CalendarKind, DateDay, DateError, FiscalCalendar, PeriodDef, PeriodKind, PeriodState,
    PeriodTransition, WeekPattern, YearEndRule,
};
use temporal::resolve as resolve_period;

// ---------------------------------------------------------------------------
// Literal period law (plan Appendix C). These decisions must not call the
// production matrix or state machine; changing either must break a test.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
    Admit,
    With(&'static str, u8),
    Refuse,
}

// Columns: Future, Open, SoftClosed, Closed, Locked. The Resolution row is
// Posts; the separate release row below covers Voids and Expires. Case,
// migration-run and rule requirements are additional class-specific laws.
const ADMISSION_ROWS: [(&str, [Admission; 5]); 15] = {
    use Admission::{Admit as A, Refuse as R, With as W};
    [
        ("Original", [R, A, W("post_softclosed", 0), R, R]),
        ("Pending", [R, A, W("post_softclosed", 0), R, R]),
        ("Resolution", [R, A, A, W("post_closed", 0), R]),
        ("Reversal", [R, A, A, W("post_closed", 0), R]),
        ("Replacement", [R, A, A, W("post_closed", 1), R]),
        ("Reclassification", [R, A, A, W("post_closed", 1), R]),
        ("Adjusting", [R, A, A, W("post_closed", 1), R]),
        (
            "Closing",
            [
                R,
                W("close", 0),
                W("close", 0),
                W("close", 1),
                W("restate", 2),
            ],
        ),
        ("Allocation", [R, A, A, W("post_closed", 1), R]),
        ("Revaluation", [R, A, A, W("post_closed", 1), R]),
        ("Elimination", [R, A, A, W("post_closed", 1), R]),
        ("Migration", [R, R, R, R, W("migrate", 2)]),
        ("Revision", [R, R, R, W("restate", 1), W("restate", 2)]),
        ("Restatement", [R, R, R, W("restate", 2), W("restate", 2)]),
        (
            "PriorPeriodAdjustment",
            [R, W("restate", 2), W("restate", 2), R, R],
        ),
    ]
};

const RELEASE_ROW: [Admission; 5] = [
    Admission::Refuse,
    Admission::Admit,
    Admission::Admit,
    Admission::Admit,
    Admission::Admit,
];

fn state_column(state: PeriodState) -> usize {
    match state {
        PeriodState::Future => 0,
        PeriodState::Open => 1,
        PeriodState::SoftClosed => 2,
        PeriodState::Closed => 3,
        PeriodState::Locked => 4,
    }
}

fn admission(class: &str, state: PeriodState, release: bool) -> Admission {
    let column = state_column(state);
    if class == "Resolution" && release {
        return RELEASE_ROW[column];
    }
    ADMISSION_ROWS
        .iter()
        .find(|(name, _)| *name == class)
        .map_or(Admission::Refuse, |(_, row)| row[column])
}

fn special(kind: PeriodKind) -> bool {
    matches!(
        kind,
        PeriodKind::Opening | PeriodKind::Adjustment | PeriodKind::Closing
    )
}

fn pre_opening(kind: PeriodKind, end: DateDay, opening: Option<DateDay>) -> bool {
    special(kind) && opening.is_some_and(|day| end <= day)
}

fn kind_admits(
    special_periods: &temporal::SpecialPeriods,
    kind: PeriodKind,
    end: DateDay,
    opening: Option<DateDay>,
    class: &str,
) -> bool {
    if kind == PeriodKind::Historical || pre_opening(kind, end, opening) {
        return class == "Migration";
    }
    special_periods.admits(kind, class)
}

fn next_state(from: PeriodState, transition: PeriodTransition) -> Option<PeriodState> {
    use PeriodState::{Closed, Future, Locked, Open, SoftClosed};
    use PeriodTransition as T;
    // §7.3: Reopen from Closed/Locked can target Open or SoftClosed.
    // SoD and case authorization are evaluated separately after this table.
    const EDGES: [(PeriodState, PeriodTransition, PeriodState); 10] = [
        (Future, T::Open, Open),
        (Open, T::SoftClose, SoftClosed),
        (Open, T::Close, Closed),
        (SoftClosed, T::Close, Closed),
        (Closed, T::Lock, Locked),
        (SoftClosed, T::Reopen { to: Open }, Open),
        (Closed, T::Reopen { to: Open }, Open),
        (Closed, T::Reopen { to: SoftClosed }, SoftClosed),
        (Locked, T::Reopen { to: Open }, Open),
        (Locked, T::Reopen { to: SoftClosed }, SoftClosed),
    ];
    EDGES
        .iter()
        .find_map(|&(state, action, to)| (state == from && action == transition).then_some(to))
}

// Calendar decisions are local too. Only the primitive civil-day type,
// conversions, successor and weekday are shared with fa-time. In particular,
// do not use its month arithmetic, year-end selection or fiscal-year lookup.
fn valid_calendar(calendar: &FiscalCalendar) -> bool {
    let month = match calendar.kind {
        CalendarKind::Monthly12 { year_start_month } => year_start_month,
        CalendarKind::Weeks { end_rule, .. } | CalendarKind::Week5253 { end_rule } => {
            match end_rule {
                YearEndRule::LastWeekdayOfMonth { month, .. }
                | YearEndRule::WeekdayNearestEnd { month, .. } => month,
            }
        }
    };
    (1..=12).contains(&month) && calendar.adjustment_periods <= 4
}

fn calendar_year_end(rule: YearEndRule, year: i32) -> Option<DateDay> {
    let (weekday, month) = match rule {
        YearEndRule::LastWeekdayOfMonth { weekday, month }
        | YearEndRule::WeekdayNearestEnd { weekday, month } => (weekday, month),
    };
    // Try actual civil dates to locate month end. OutOfRange is not a short
    // month: accepting a clipped month at DateDay::MAX would move year end.
    let mut last = None;
    for day in (28..=31).rev() {
        match DateDay::from_ymd(year, month, day) {
            Ok(date) => {
                last = Some(date);
                break;
            }
            Err(DateError::InvalidYmd { .. }) => {}
            Err(_) => return None,
        }
    }
    let last = last?;
    match rule {
        YearEndRule::LastWeekdayOfMonth { .. } => {
            let mut chosen = None;
            // Enumerate the month, including a partly representable month
            // at DateDay::MIN; the last matching weekday is the answer.
            for day in 1..=last.ymd().2 {
                if let Ok(date) = DateDay::from_ymd(year, month, day)
                    && date.weekday() == weekday
                {
                    chosen = Some(date);
                }
            }
            chosen
        }
        YearEndRule::WeekdayNearestEnd { .. } => {
            // Exactly one of these seven days has the requested weekday.
            // If that day is outside DateDay, no farther day substitutes.
            for offset in -3..=3 {
                if let Some(day) = last.0.checked_add(offset)
                    && DateDay(day).weekday() == weekday
                {
                    return Some(DateDay(day));
                }
            }
            None
        }
    }
}

/// Inclusive fiscal-year bounds, found without production calendar helpers.
fn calendar_year_bounds(calendar: &FiscalCalendar, fy: i32) -> Option<(DateDay, DateDay)> {
    if !valid_calendar(calendar) {
        return None;
    }
    match calendar.kind {
        CalendarKind::Monthly12 { year_start_month } => {
            let year = if year_start_month == 1 {
                fy
            } else {
                fy.checked_sub(1)?
            };
            let start = DateDay::from_ymd(year, year_start_month, 1).ok()?;
            let mut day = start;
            let mut months = 0;
            loop {
                let next = day.succ().ok()?;
                if next.ymd().2 == 1 {
                    months += 1;
                    if months == 12 {
                        return Some((start, day));
                    }
                }
                day = next;
            }
        }
        CalendarKind::Weeks { end_rule, .. } | CalendarKind::Week5253 { end_rule } => {
            let previous = calendar_year_end(end_rule, fy.checked_sub(1)?)?;
            let start = previous.succ().ok()?;
            let end = calendar_year_end(end_rule, fy)?;
            (start <= end).then_some((start, end))
        }
    }
}

fn containing_fiscal_year(calendar: &FiscalCalendar, day: DateDay) -> Option<i32> {
    if !valid_calendar(calendar) {
        return None;
    }
    // A fiscal year is named by its ending civil year; a nearest-weekday
    // December end may cross into January. Scan neighboring year labels
    // and test their actual bounds rather than guessing from a start month.
    for offset in -1..=1 {
        let fy = day.ymd().0.checked_add(offset)?;
        if let Some((start, end)) = calendar_year_bounds(calendar, fy)
            && start <= day
            && day <= end
        {
            return Some(fy);
        }
    }
    None
}

fn calendar_periods(calendar: &FiscalCalendar, fy: i32) -> Option<Vec<PeriodDef>> {
    let (start, last) = calendar_year_bounds(calendar, fy)?;
    let mut periods = Vec::new();
    let mut cursor = start;
    let mut add_normal = |start, end| -> Option<()> {
        let ordinal = u16::try_from(periods.len()).ok()?.checked_add(1)?;
        periods.push(PeriodDef {
            code: format!("FY{fy}-P{ordinal:02}"),
            fiscal_year: fy,
            ordinal,
            kind: PeriodKind::Normal,
            start,
            end,
        });
        Some(())
    };
    match calendar.kind {
        CalendarKind::Monthly12 { .. } => {
            let mut period_start = start;
            while cursor <= last {
                cursor = cursor.succ().ok()?;
                if cursor.ymd().2 == 1 {
                    add_normal(period_start, cursor)?;
                    period_start = cursor;
                }
            }
        }
        CalendarKind::Weeks { .. } | CalendarKind::Week5253 { .. } => {
            let widths: &[u16] = match calendar.kind {
                CalendarKind::Weeks { pattern, .. } => match pattern {
                    WeekPattern::W445 => &[4, 4, 5, 4, 4, 5, 4, 4, 5, 4, 4, 5],
                    WeekPattern::W454 => &[4, 5, 4, 4, 5, 4, 4, 5, 4, 4, 5, 4],
                    WeekPattern::W544 => &[5, 4, 4, 5, 4, 4, 5, 4, 4, 5, 4, 4],
                },
                CalendarKind::Week5253 { .. } => &[4; 13],
                CalendarKind::Monthly12 { .. } => return None,
            };
            for (index, weeks) in widths.iter().enumerate() {
                let period_start = cursor;
                let regular_days = weeks * 7;
                let final_period = index + 1 == widths.len();
                let mut days = 0;
                // The final period consumes the remainder of the year;
                // its only permitted extra duration is the 53rd week.
                while cursor <= last && (final_period || days < regular_days) {
                    cursor = cursor.succ().ok()?;
                    days += 1;
                }
                if days != regular_days && !(final_period && days == regular_days + 7) {
                    return None;
                }
                add_normal(period_start, cursor)?;
            }
        }
    }
    let normal_count = u16::try_from(periods.len()).ok()?;
    let end = last.succ().ok()?;
    periods.push(PeriodDef {
        code: format!("FY{fy}-OPEN"),
        fiscal_year: fy,
        ordinal: normal_count + 1,
        kind: PeriodKind::Opening,
        start,
        end: start.succ().ok()?,
    });
    for adjustment in 1..=calendar.adjustment_periods {
        periods.push(PeriodDef {
            code: format!("FY{fy}-A{adjustment}"),
            fiscal_year: fy,
            ordinal: normal_count + 1 + u16::from(adjustment),
            kind: PeriodKind::Adjustment,
            start: last,
            end,
        });
    }
    periods.push(PeriodDef {
        code: format!("FY{fy}-CLOSE"),
        fiscal_year: fy,
        ordinal: normal_count + 2 + u16::from(calendar.adjustment_periods),
        kind: PeriodKind::Closing,
        start: last,
        end,
    });
    Some(periods)
}

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
    pub const REVERSAL_TARGET: &str = "FA-REF-050";
    pub const REVERSAL_SHAPE: &str = "FA-REF-051";
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
    pub const RUN_NOT_OPEN: &str = "FA-REF-130";
    pub const TIE_OUT_MISMATCH: &str = "FA-REF-131";
    pub const MIGRATION_OUTSIDE_RUN: &str = "FA-REF-132";
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

/// Period creation is atomic: neither an invalid calendar range nor an
/// existing period may overwrite a definition or its transitioned state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeriodCreationError {
    InvalidCalendar,
    AlreadyExists(String),
}

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
    /// Committed TimeEvidence ticks, strictly increasing (plan §7.1a).
    ticks: Vec<u64>,
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
    special_periods: temporal::SpecialPeriods,
    sod: SodPolicy,
    /// Tokens of revoked capabilities.
    revoked: BTreeSet<u64>,
    /// The security policy epoch: the number of activations so far.
    epoch: u64,
}

impl Oracle {
    pub fn new(calendar: FiscalCalendar) -> Self {
        let classes = EntryClasses::embedded().expect("entry_classes.toml");
        let matrix = Admissibility::embedded(&classes).expect("admissibility.toml");
        Self::from_policy_data(calendar, classes, matrix)
    }

    // The matrix is used only to validate policy data, never for admission.
    // Tests supply a valid but incorrect matrix through this same path: the
    // oracle must still enforce the independently transcribed Appendix C.
    fn from_policy_data(
        calendar: FiscalCalendar,
        classes: EntryClasses,
        matrix: Admissibility,
    ) -> Self {
        let sod = SodPolicy::embedded(&classes, &matrix).expect("sod_policy.toml");
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
            deadlines: BTreeMap::new(),
            cursor: None,
            tz_declared: false,
            schedules: BTreeMap::new(),
            entities: Vec::new(),
            schedule_cursor: None,
            runs: Vec::new(),
            run_keys: BTreeMap::new(),
            run_controls: Vec::new(),
            control_keys: BTreeMap::new(),
            migration_keys: BTreeMap::new(),
            classes,
            special_periods: temporal::SpecialPeriods::embedded(),
            sod,
            revoked: BTreeSet::new(),
            epoch: 0,
        }
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
    pub fn create_periods(&mut self, fy: i32) -> Result<(), PeriodCreationError> {
        let periods =
            calendar_periods(&self.calendar, fy).ok_or(PeriodCreationError::InvalidCalendar)?;
        if let Some(p) = periods.iter().find(|p| self.periods.contains_key(&p.code)) {
            return Err(PeriodCreationError::AlreadyExists(p.code.clone()));
        }
        for mut p in periods {
            let state = match self.opening_date {
                Some(day) if p.kind == PeriodKind::Normal && p.end <= day => {
                    p.kind = PeriodKind::Historical;
                    PeriodState::Locked
                }
                _ if pre_opening(p.kind, p.end, self.opening_date) => PeriodState::Locked,
                _ => PeriodState::Future,
            };
            self.periods.insert(p.code.clone(), (p, state));
        }
        Ok(())
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
            && next_state(*from, t).is_some()
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
        // Appendix C: Historical and pre-opening special periods never
        // transition, whatever state is presented.
        if def.kind == PeriodKind::Historical || pre_opening(def.kind, def.end, self.opening_date) {
            return Err(code::TRANSITION);
        }
        let from = *state;
        let to = next_state(from, t).ok_or(code::TRANSITION)?;
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
        match self.post_inner(&intent, None, None, None, None, &PostClaims::default()) {
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
                    Some(state) => match admission("Reversal", state, false) {
                        Admission::Admit | Admission::With("post", _) => Reached::Due,
                        _ => Reached::Blocked,
                    },
                };
                let live_applications = (0..self.journal[*target].legs.len())
                    .any(|i| !self.applied_to(*target, i).is_zero());
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

    /// Journal a TimeEvidence tick (plan §7.1a): strictly after the latest.
    /// `Ok(tick index)`.
    pub fn record_tick(&mut self, observed_utc_ns: u64) -> Result<usize, &'static str> {
        if self.ticks.last().is_some_and(|t| observed_utc_ns <= *t) {
            return Err(code::TICK_ORDER);
        }
        self.ticks.push(observed_utc_ns);
        Ok(self.ticks.len() - 1)
    }

    /// The latest committed tick's instant.
    #[must_use]
    pub fn latest_tick(&self) -> Option<u64> {
        self.ticks.last().copied()
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
            // Appendix C admits releases in every state except Future.
            if admission("Resolution", state, true) != Admission::Admit {
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
            "Original" | "Adjusting" | "Reversal" | "Pending" | "Resolution" | "Migration"
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
            let resolved = containing_fiscal_year(&self.calendar, reverse_on)
                .and_then(|fy| calendar_periods(&self.calendar, fy))
                .and_then(|defs| resolve_period(&defs, reverse_on, None).map(|p| p.code.clone()));
            let Some(p) = resolved else {
                return Verdict::Refused {
                    code: code::PERIOD_RESOLVE,
                };
            };
            schedule_period = Some(p);
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
        // 2'. Balance per (unit, legal entity) (FA-INV-01 `per-entity`).
        let mut per_entity: BTreeMap<(u32, Option<String>), (Int, Int)> = BTreeMap::new();
        for l in &intent.legs {
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
        let Some(fy) = containing_fiscal_year(&self.calendar, intent.date) else {
            return Verdict::Refused {
                code: code::PERIOD_RESOLVE,
            };
        };
        let Some(defs) = calendar_periods(&self.calendar, fy) else {
            return Verdict::Refused {
                code: code::PERIOD_RESOLVE,
            };
        };
        let Some(period) = resolve_period(&defs, intent.date, intent.discriminator.as_deref())
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
        if is_reversal {
            let reasons =
                fa_registry::reason_codes::ReasonCodes::embedded().expect("reason registry");
            if !reasons
                .rows
                .iter()
                .any(|row| row.scope == "supersession" && row.code == intent.supersession_reason)
            {
                return Verdict::Refused {
                    code: code::SUPERSESSION_REASON,
                };
            }
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
        // 5. Period law against the period's current state (Future when
        //    never created) and its born kind: a Historical period admits
        //    only Migration.
        let born = self.periods.get(&period).map(|(d, _)| d.kind);
        if born.is_some_and(|kind| {
            !kind_admits(
                &self.special_periods,
                kind,
                period_end,
                self.opening_date,
                &intent.class,
            )
        }) {
            return Verdict::Refused {
                code: code::PERIOD_LAW,
            };
        }
        let state = self.period_state(&period).unwrap_or(PeriodState::Future);
        match admission(&intent.class, state, is_release) {
            Admission::Admit => {}
            Admission::With(op, approvals) => {
                if !intent.ops.iter().any(|held| held == op) {
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
            Admission::Refuse => {
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
            if tl.account != leg.account || tl.unit != leg.unit || tl.side == leg.side {
                return Verdict::Refused {
                    code: code::SETTLE_SHAPE,
                };
            }
            let before = used
                .get(&(s.target, s.ordinal))
                .cloned()
                .unwrap_or_else(Int::zero);
            let consumed = target
                .settles
                .iter()
                .filter(|t| t.leg == s.ordinal)
                .fold(Int::zero(), |sum, t| sum.add(&Int::from_i128(t.mantissa)));
            let open = Int::from_i128(tl.mantissa)
                .sub(&consumed)
                .sub(&self.applied_to(s.target, s.ordinal))
                .sub(&before);
            let applied = Int::from_i128(s.mantissa);
            if open.sub(&applied).is_negative() {
                return Verdict::Refused {
                    code: code::OVER_APPLICATION,
                };
            }
            used.insert((s.target, s.ordinal), before.add(&applied));
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
            // Every ancestor changes liveness, not just the immediate
            // reversal target. A revived invoice may have received new
            // applications that must be undone before it can disappear.
            let mut affected = target;
            loop {
                let entry = &self.journal[affected];
                if (0..entry.legs.len()).any(|i| !self.applied_to(affected, i).is_zero()) {
                    return Verdict::Refused {
                        code: code::LIVE_APPLICATIONS,
                    };
                }
                if entry.class != "Reversal" {
                    break;
                }
                let parent = entry.reverses.expect("an admitted reversal has a target");
                assert!(parent < affected, "reversal targets precede their entries");
                if !self.journal[parent].settles.is_empty() {
                    return Verdict::Refused {
                        code: code::CLASS_NOT_IMPLEMENTED,
                    };
                }
                affected = parent;
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
        //     latest tick has reached is refused (Voids is not).
        let mut deadline = None;
        if let Some(t) = timeout {
            let Some(anchor) = self.latest_tick() else {
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
            && let (Some(d), Some(now)) = (self.deadlines.get(target), self.latest_tick())
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
        let year_start = containing_fiscal_year(&self.calendar, spec.opening_date)
            .and_then(|fy| calendar_year_bounds(&self.calendar, fy))
            .map(|(start, _)| start);
        if year_start != Some(spec.opening_date) {
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
            let (Some(first), Some(last)) = (
                containing_fiscal_year(&self.calendar, start),
                containing_fiscal_year(&self.calendar, go_live),
            ) else {
                return Err(code::STRUCTURE);
            };
            let mut expected = Vec::new();
            for fy in first..=last {
                for p in calendar_periods(&self.calendar, fy).ok_or(code::STRUCTURE)? {
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
        let Some(own_opening) = containing_fiscal_year(&self.calendar, r.spec.opening_date)
            .and_then(|fy| calendar_periods(&self.calendar, fy))
            .and_then(|periods| periods.into_iter().find(|p| p.kind == PeriodKind::Opening))
            .map(|p| p.code)
        else {
            return false;
        };
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

    /// The model's head coordinate.
    #[must_use]
    pub fn known(&self) -> Known {
        Known {
            entries: self.journal.len(),
            controls: self.run_controls.len(),
        }
    }

    /// The coordinate just before entry `accepted_prefix` was accepted: every
    /// run control accepted while the journal held at most that many entries.
    fn known_after(&self, accepted_prefix: usize) -> Known {
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
    fn visible(&self, e: &Entry, known: Known) -> bool {
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
        matches!(e.class.as_str(), "Original" | "Adjusting")
            || (e.class == "Resolution" && !e.legs.is_empty())
            || (e.class == "Migration" && self.visible(e, self.known()))
    }

    /// Live unless a live reversal targets it (a reversed reversal revives).
    fn is_live(&self, index: usize) -> bool {
        match self.reversed.get(&index) {
            None => true,
            Some((reversal, _)) => !self.is_live(*reversal),
        }
    }

    /// The sum of live applications against `target`'s leg `ordinal`.
    fn applied_to(&self, target: usize, ordinal: usize) -> Int {
        self.journal
            .iter()
            .enumerate()
            .filter(|(i, e)| self.carries_open_items(e) && self.is_live(*i))
            .flat_map(|(_, e)| e.settles.iter())
            .filter(|s| s.target == target && s.ordinal == ordinal)
            .fold(Int::zero(), |sum, s| sum.add(&Int::from_i128(s.mantissa)))
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
                let out_of = e
                    .settles
                    .iter()
                    .filter(|s| s.leg == o)
                    .fold(Int::zero(), |sum, s| sum.add(&Int::from_i128(s.mantissa)));
                // Admission bounds each total by the original i128 leg.
                // Narrow only the public result, after the independent fold.
                out.insert(
                    (i, o),
                    (
                        leg.mantissa,
                        self.applied_to(i, o)
                            .to_i128()
                            .expect("applications fit admitted target"),
                        out_of.to_i128().expect("applications fit admitted source"),
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

    #[test]
    fn invalid_period_creation_preserves_existing_definitions_and_states() {
        let mut oracle = Oracle::new(FiscalCalendar::monthly("cal", 1, 1).unwrap());
        oracle.create_periods(2026).unwrap();
        oracle
            .transition("FY2026-P03", PeriodTransition::Open)
            .unwrap();
        let periods = oracle.periods.clone();
        let known = oracle.known();
        for year in [i32::MIN, i32::MAX] {
            assert_eq!(
                oracle.create_periods(year),
                Err(PeriodCreationError::InvalidCalendar)
            );
            assert_eq!(oracle.periods, periods);
            assert_eq!(oracle.known(), known);
        }
    }

    fn check_calendar(calendar: &FiscalCalendar, fy: i32) -> Option<i64> {
        let bounds = calendar_year_bounds(calendar, fy);
        #[expect(clippy::disallowed_methods, reason = "pin the year-bounds boundary")]
        let production_bounds = calendar.year_bounds(fy).ok();
        assert_eq!(bounds, production_bounds, "{calendar:?} / FY{fy}");
        let periods = calendar_periods(calendar, fy);
        #[expect(clippy::disallowed_methods, reason = "pin the generation boundary")]
        let production_periods = calendar.periods_for_year(fy).ok();
        assert_eq!(periods, production_periods, "{calendar:?} / FY{fy}");
        let (start, last) = bounds?;
        for day in [start, last] {
            assert_eq!(
                containing_fiscal_year(calendar, day),
                Some(fy),
                "{calendar:?} / {day:?}"
            );
        }
        for day in [start.0.checked_sub(1), last.0.checked_add(1)]
            .into_iter()
            .flatten()
        {
            #[expect(clippy::disallowed_methods, reason = "pin fiscal-year selection")]
            let production_year = calendar.fiscal_year_of(DateDay(day)).ok();
            assert_eq!(
                containing_fiscal_year(calendar, DateDay(day)),
                production_year,
                "{calendar:?} / boundary {day}"
            );
        }
        if let Some(periods) = periods {
            let count = if matches!(calendar.kind, CalendarKind::Week5253 { .. }) {
                13
            } else {
                12
            };
            assert_eq!(
                periods.len(),
                count + usize::from(calendar.adjustment_periods) + 2
            );
            let mut next = start;
            for (index, period) in periods[..count].iter().enumerate() {
                assert_eq!(period.kind, PeriodKind::Normal);
                assert_eq!(period.ordinal, index as u16 + 1);
                assert_eq!(period.start, next);
                assert!(period.start < period.end);
                assert_eq!(resolve_period(&periods, period.start, None), Some(period));
                assert_eq!(
                    resolve_period(&periods, DateDay(period.end.0 - 1), None),
                    Some(period)
                );
                next = period.end;
            }
            assert_eq!(next, last.succ().unwrap());
            assert_eq!(periods[count].kind, PeriodKind::Opening);
            assert_eq!(periods[count].start, start);
            assert_eq!(periods[count].end, start.succ().unwrap());
            for period in &periods[count + 1..] {
                assert_eq!((period.start, period.end), (last, next));
                assert_eq!(
                    resolve_period(&periods, last, Some(&period.code)),
                    Some(period)
                );
            }
        }
        Some(i64::from(last.0) - i64::from(start.0) + 1)
    }

    fn week_kinds(rule: YearEndRule) -> [CalendarKind; 4] {
        [
            CalendarKind::Weeks {
                pattern: WeekPattern::W445,
                end_rule: rule,
            },
            CalendarKind::Weeks {
                pattern: WeekPattern::W454,
                end_rule: rule,
            },
            CalendarKind::Weeks {
                pattern: WeekPattern::W544,
                end_rule: rule,
            },
            CalendarKind::Week5253 { end_rule: rule },
        ]
    }

    #[test]
    fn day_walking_monthly_calendars_match_across_starts_and_gregorian_boundaries() {
        for year in [
            -400, -1, 0, 1, 1899, 1900, 1999, 2000, 2024, 2025, 2026, 2099, 2100, 2400,
        ] {
            for month in 1..=12 {
                for adjustments in 0..=4 {
                    let calendar = FiscalCalendar {
                        id: "monthly".into(),
                        kind: CalendarKind::Monthly12 {
                            year_start_month: month,
                        },
                        adjustment_periods: adjustments,
                    };
                    assert!(matches!(check_calendar(&calendar, year), Some(365 | 366)));
                }
            }
        }
        // Independent civil-date anchors, including the century exception.
        let calendar = FiscalCalendar::monthly("calendar", 1, 1).unwrap();
        for (year, february_days) in [(0, 29), (1900, 28), (2000, 29), (2100, 28), (2400, 29)] {
            let periods = calendar_periods(&calendar, year).unwrap();
            assert_eq!(periods[1].end.0 - periods[1].start.0, february_days);
        }
        let october = FiscalCalendar::monthly("october", 10, 1).unwrap();
        assert_eq!(
            calendar_year_bounds(&october, 2026),
            Some((
                DateDay::from_ymd(2025, 10, 1).unwrap(),
                DateDay::from_ymd(2026, 9, 30).unwrap()
            ))
        );
    }

    #[test]
    fn day_walking_week_calendars_match_every_rule_and_put_week_53_last() {
        use fa_time::Weekday::{Friday, Monday, Saturday, Sunday, Thursday, Tuesday, Wednesday};
        for month in 1..=12 {
            for weekday in [
                Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday,
            ] {
                for rule in [
                    YearEndRule::LastWeekdayOfMonth { weekday, month },
                    YearEndRule::WeekdayNearestEnd { weekday, month },
                ] {
                    for kind in week_kinds(rule) {
                        let mut lengths = BTreeSet::new();
                        for (index, year) in [
                            -400, -1, 0, 1, 1900, 2000, 2020, 2021, 2022, 2023, 2024, 2025, 2026,
                            2027, 2028, 2029, 2030, 2031, 2100, 2400,
                        ]
                        .into_iter()
                        .enumerate()
                        {
                            let calendar = FiscalCalendar {
                                id: "weeks".into(),
                                kind: kind.clone(),
                                adjustment_periods: (index % 5) as u8,
                            };
                            let days = check_calendar(&calendar, year).unwrap();
                            assert!(matches!(days, 364 | 371));
                            lengths.insert(days);
                            let periods = calendar_periods(&calendar, year).unwrap();
                            let normals: Vec<_> = periods
                                .iter()
                                .filter(|p| p.kind == PeriodKind::Normal)
                                .collect();
                            let ordinary_last = match kind {
                                CalendarKind::Weeks {
                                    pattern: WeekPattern::W445,
                                    ..
                                } => 35,
                                _ => 28,
                            };
                            let last = normals.last().unwrap();
                            assert_eq!(
                                last.end.0 - last.start.0,
                                ordinary_last + if days == 371 { 7 } else { 0 }
                            );
                            assert_eq!(DateDay(last.end.0 - 1).weekday(), weekday);
                        }
                        assert_eq!(lengths, BTreeSet::from([364, 371]), "{kind:?}");
                    }
                }
            }
        }
        let calendar = FiscalCalendar {
            id: "retail".into(),
            kind: CalendarKind::Weeks {
                pattern: WeekPattern::W445,
                end_rule: YearEndRule::WeekdayNearestEnd {
                    weekday: Saturday,
                    month: 12,
                },
            },
            adjustment_periods: 0,
        };
        assert_eq!(
            calendar_year_bounds(&calendar, 2025).unwrap().1,
            DateDay::from_ymd(2026, 1, 3).unwrap()
        );
        assert_eq!(
            containing_fiscal_year(&calendar, DateDay::from_ymd(2026, 1, 3).unwrap()),
            Some(2025)
        );
        assert_eq!(
            containing_fiscal_year(&calendar, DateDay::from_ymd(2026, 1, 4).unwrap()),
            Some(2026)
        );
    }

    #[test]
    fn day_walking_calendars_refuse_invalid_definitions_and_preserve_date_endpoints() {
        use fa_time::Weekday;
        for month in [0, 13, u8::MAX] {
            let kinds = [CalendarKind::Monthly12 {
                year_start_month: month,
            }]
            .into_iter()
            .chain(week_kinds(YearEndRule::LastWeekdayOfMonth {
                weekday: Weekday::Monday,
                month,
            }))
            .chain(week_kinds(YearEndRule::WeekdayNearestEnd {
                weekday: Weekday::Sunday,
                month,
            }));
            for kind in kinds {
                let calendar = FiscalCalendar {
                    id: "invalid month".into(),
                    kind,
                    adjustment_periods: 0,
                };
                assert!(!valid_calendar(&calendar));
                assert_eq!(calendar_periods(&calendar, 2026), None);
                assert_eq!(calendar_year_bounds(&calendar, 2026), None);
                assert_eq!(containing_fiscal_year(&calendar, DateDay::EPOCH), None);
                #[expect(clippy::disallowed_methods, reason = "compare invalid month refusal")]
                let production = calendar.periods_for_year(2026);
                assert!(production.is_err());
            }
        }
        let kinds = [CalendarKind::Monthly12 {
            year_start_month: 1,
        }]
        .into_iter()
        .chain(week_kinds(YearEndRule::WeekdayNearestEnd {
            weekday: Weekday::Saturday,
            month: 12,
        }));
        for kind in kinds {
            for adjustments in [5, u8::MAX] {
                let calendar = FiscalCalendar {
                    id: "invalid adjustments".into(),
                    kind: kind.clone(),
                    adjustment_periods: adjustments,
                };
                assert_eq!(calendar_periods(&calendar, 2026), None);
                assert_eq!(containing_fiscal_year(&calendar, DateDay::EPOCH), None);
                #[expect(clippy::disallowed_methods, reason = "compare adjustment bounds")]
                let production = calendar.periods_for_year(2026);
                assert!(production.is_err());
            }
        }
        let mut calendars: Vec<_> = (1..=12)
            .map(|month| FiscalCalendar {
                id: "endpoint monthly".into(),
                kind: CalendarKind::Monthly12 {
                    year_start_month: month,
                },
                adjustment_periods: 4,
            })
            .collect();
        for month in [1, 6, 12] {
            for weekday in [
                Weekday::Monday,
                Weekday::Tuesday,
                Weekday::Wednesday,
                Weekday::Thursday,
                Weekday::Friday,
                Weekday::Saturday,
                Weekday::Sunday,
            ] {
                for rule in [
                    YearEndRule::LastWeekdayOfMonth { weekday, month },
                    YearEndRule::WeekdayNearestEnd { weekday, month },
                ] {
                    calendars.extend(week_kinds(rule).map(|kind| FiscalCalendar {
                        id: "endpoint weeks".into(),
                        kind,
                        adjustment_periods: 4,
                    }));
                }
            }
        }
        for calendar in calendars {
            for year in [i32::MIN, i32::MAX] {
                assert_eq!(calendar_periods(&calendar, year), None);
                #[expect(clippy::disallowed_methods, reason = "compare out-of-range refusal")]
                let production = calendar.periods_for_year(year);
                assert!(production.is_err());
            }
            for endpoint in [DateDay(i32::MIN), DateDay(i32::MAX)] {
                for offset in -1..=1 {
                    let _ = check_calendar(&calendar, endpoint.ymd().0 + offset);
                }
                for offset in 0..=7 {
                    let day = if endpoint.0 == i32::MIN {
                        DateDay(endpoint.0 + offset)
                    } else {
                        DateDay(endpoint.0 - offset)
                    };
                    #[expect(clippy::disallowed_methods, reason = "compare endpoint selection")]
                    let production = calendar.fiscal_year_of(day).ok();
                    assert_eq!(
                        containing_fiscal_year(&calendar, day),
                        production,
                        "{calendar:?} / endpoint {day:?}"
                    );
                }
            }
        }
    }

    const STATES: [PeriodState; 5] = [
        PeriodState::Future,
        PeriodState::Open,
        PeriodState::SoftClosed,
        PeriodState::Closed,
        PeriodState::Locked,
    ];

    fn registry_decision(value: Admission) -> fa_registry::Decision {
        match value {
            Admission::Admit => fa_registry::Decision::Admit,
            Admission::With(op, approvals) => fa_registry::Decision::With {
                op: op.into(),
                approvals,
            },
            Admission::Refuse => fa_registry::Decision::Refuse,
        }
    }

    #[test]
    fn literal_appendix_c_agrees_with_every_production_cell_and_disposition() {
        let classes = EntryClasses::embedded().unwrap();
        let matrix = Admissibility::embedded(&classes).unwrap();
        let actual: BTreeSet<&str> = classes
            .rows
            .iter()
            .filter(|r| r.kind == fa_registry::ClassKind::Posting)
            .map(|r| r.name.as_str())
            .collect();
        let expected: BTreeSet<&str> = ADMISSION_ROWS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            actual, expected,
            "every posting class has an independent row"
        );
        assert_eq!(matrix.len(), 75);
        for class in actual {
            for state in STATES {
                for release in [false, true] {
                    #[expect(clippy::disallowed_methods, reason = "pin disposition admission")]
                    let production = matrix.decide_disposition(class, state, release);
                    assert_eq!(
                        production,
                        Some(registry_decision(admission(class, state, release))),
                        "{class} / {state:?} / release={release}"
                    );
                }
            }
        }
        for state in STATES {
            #[expect(clippy::disallowed_methods, reason = "pin expiry admission")]
            let production = matrix.decide_expires(state);
            assert_eq!(
                production,
                Some(&registry_decision(admission("Resolution", state, true))),
                "Expires / {state:?}"
            );
        }
    }

    #[test]
    fn literal_kind_restrictions_agree_at_each_opening_boundary() {
        let classes = EntryClasses::embedded().unwrap();
        let matrix = Admissibility::embedded(&classes).unwrap();
        let special_periods = temporal::SpecialPeriods::embedded();
        for kind in [
            PeriodKind::Normal,
            PeriodKind::Historical,
            PeriodKind::Opening,
            PeriodKind::Adjustment,
            PeriodKind::Closing,
        ] {
            for opening in [
                None,
                Some(DateDay(99)),
                Some(DateDay(100)),
                Some(DateDay(101)),
            ] {
                let end = DateDay(100);
                let pre = matrix.pre_opening().unwrap();
                assert_eq!(
                    pre.governs(kind, end, opening),
                    pre_opening(kind, end, opening)
                );
                for (class, _) in ADMISSION_ROWS {
                    let registered = matrix.kind_rule(kind).is_none_or(|r| r.admits(class))
                        && (!pre.governs(kind, end, opening) || pre.admits(class))
                        && matrix
                            .special_period_rule(kind)
                            .is_none_or(|rule| rule.admits(class));
                    assert_eq!(
                        registered,
                        kind_admits(&special_periods, kind, end, opening, class),
                        "{kind:?} / {class} / opening={opening:?}"
                    );
                }
            }
        }
        assert_eq!(matrix.pre_opening().unwrap().born, PeriodState::Locked);
        assert_eq!(
            matrix.pre_opening().unwrap().transition_refusal,
            code::TRANSITION
        );
        assert_eq!(matrix.pre_opening().unwrap().refusal, code::PERIOD_LAW);
        let historical = matrix.kind_rule(PeriodKind::Historical).unwrap();
        assert_eq!(historical.transition_refusal, code::TRANSITION);
        assert_eq!(historical.refusal, code::PERIOD_LAW);
    }

    #[test]
    fn literal_state_machine_agrees_on_all_45_actions() {
        use fa_time::period::transition as production_transition;

        for from in STATES {
            let mut actions = vec![
                PeriodTransition::Open,
                PeriodTransition::SoftClose,
                PeriodTransition::Close,
                PeriodTransition::Lock,
            ];
            actions.extend(STATES.map(|to| PeriodTransition::Reopen { to }));
            for action in actions {
                #[expect(clippy::disallowed_methods, reason = "pin aliased transition calls")]
                let production = production_transition(from, action).ok();
                assert_eq!(
                    production,
                    next_state(from, action),
                    "{from:?} / {action:?}"
                );
            }
        }
    }

    #[test]
    fn literal_resolution_preserves_half_open_boundaries_and_special_selection() {
        let def = |code: &str, ordinal, kind, start, end| PeriodDef {
            code: code.into(),
            fiscal_year: 2026,
            ordinal,
            kind,
            start: DateDay(start),
            end: DateDay(end),
        };
        // Put specials first so default resolution cannot accidentally
        // succeed by returning the first containing definition.
        let periods = vec![
            def("opening", 0, PeriodKind::Opening, 0, 1),
            def("adjustment", 3, PeriodKind::Adjustment, 29, 30),
            def("closing", 4, PeriodKind::Closing, 20, 30),
            def("normal", 1, PeriodKind::Normal, 0, 30),
            def("historical", 2, PeriodKind::Historical, 30, 60),
        ];
        for day in -1..=60 {
            let expected = match day {
                0..=29 => Some("normal"),
                30..=59 => Some("historical"),
                _ => None,
            };
            assert_eq!(
                resolve_period(&periods, DateDay(day), None).map(|p| p.code.as_str()),
                expected
            );
            for selected in [
                None,
                Some("opening"),
                Some("adjustment"),
                Some("closing"),
                Some("normal"),
                Some("historical"),
                Some("absent"),
            ] {
                #[expect(clippy::disallowed_methods, reason = "pin re-exported resolution")]
                let production = fa_time::resolve_period(&periods, DateDay(day), selected).ok();
                assert_eq!(
                    resolve_period(&periods, DateDay(day), selected),
                    production,
                    "day={day} / selected={selected:?}"
                );
            }
        }
    }

    #[test]
    fn oracle_rejects_original_despite_a_planted_production_admission_cell() {
        const ORIGINAL: &str =
            "class = \"Original\"\nstate = \"SoftClosed\"\ndecision = \"with:post_softclosed\"";
        const WRONG: &str = "class = \"Original\"\nstate = \"SoftClosed\"\ndecision = \"admit\"";
        let text = include_str!("../../../registries/admissibility.toml");
        assert_eq!(text.matches(ORIGINAL).count(), 1, "plant exactly one cell");
        let mutated = Admissibility::parse(
            &EntryClasses::embedded().unwrap(),
            &text.replacen(ORIGINAL, WRONG, 1),
        )
        .unwrap();
        #[expect(clippy::disallowed_methods, reason = "pin direct admission lookup")]
        let planted = mutated.decide("Original", PeriodState::SoftClosed);
        assert_eq!(planted, Some(&fa_registry::Decision::Admit));
        #[expect(clippy::disallowed_methods, reason = "compare planted disposition")]
        let planted = mutated.decide_disposition("Original", PeriodState::SoftClosed, false);
        assert_eq!(planted, Some(fa_registry::Decision::Admit));

        let mut oracle = Oracle::from_policy_data(
            FiscalCalendar::monthly("cal", 1, 1).unwrap(),
            EntryClasses::embedded().unwrap(),
            mutated,
        );
        for account in ["cash", "expense"] {
            oracle.add_account(Account {
                code: account.into(),
                is_leaf: true,
                unit: Some(1),
            });
        }
        oracle.create_periods(2026).unwrap();
        oracle
            .transition("FY2026-P03", PeriodTransition::Open)
            .unwrap();
        oracle
            .transition("FY2026-P03", PeriodTransition::SoftClose)
            .unwrap();
        let mut intent = Intent {
            class: "Original".into(),
            date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            discriminator: None,
            legs: vec![
                Leg {
                    side: Side::Debit,
                    account: "expense".into(),
                    unit: 1,
                    entity: None,
                    mantissa: 700,
                },
                Leg {
                    side: Side::Credit,
                    account: "cash".into(),
                    unit: 1,
                    entity: None,
                    mantissa: 700,
                },
            ],
            key: b"wrong-cell".to_vec(),
            ops: vec!["post".into()],
            approvals: 0,
            reverses: None,
            supersession_reason: 1,
            resolves: None,
            settles: Vec::new(),
        };
        let before = oracle.known();
        assert_eq!(
            oracle.post(&intent),
            Verdict::Refused { code: "FA-REF-011" }
        );
        assert_eq!(oracle.known(), before);
        assert_eq!(oracle.journal_len(), 0);
        intent.ops.push("post_softclosed".into());
        assert!(matches!(
            oracle.post(&intent),
            Verdict::Posted { index: 0, .. }
        ));
        assert_eq!(
            oracle.fold("FY2026-P03")[&("expense".into(), 1)].debits,
            Int::from_i128(700)
        );
    }

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
    fn application_laws_use_exact_intermediates_at_the_leg_boundary() {
        let mut oracle = Oracle::new(FiscalCalendar::monthly("cal", 1, 0).unwrap());
        for account in ["receivable", "income", "cash"] {
            oracle.add_account(Account {
                code: account.into(),
                is_leaf: true,
                unit: Some(1),
            });
        }
        oracle.create_periods(2026).unwrap();
        oracle
            .transition("FY2026-P03", PeriodTransition::Open)
            .unwrap();
        let leg = |side, account: &str, mantissa| Leg {
            side,
            account: account.into(),
            unit: 1,
            entity: None,
            mantissa,
        };
        let intent = |key: &[u8], legs, settles| Intent {
            class: "Original".into(),
            date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            discriminator: None,
            legs,
            key: key.to_vec(),
            ops: vec!["post".into()],
            approvals: 0,
            reverses: None,
            supersession_reason: 1,
            resolves: None,
            settles,
        };
        let invoice = intent(
            b"invoice",
            vec![
                leg(Side::Debit, "receivable", i128::MAX),
                leg(Side::Credit, "income", i128::MAX),
            ],
            vec![],
        );
        assert!(matches!(
            oracle.post(&invoice),
            Verdict::Posted { index: 0, .. }
        ));
        // Each settlement fits its own source leg. Only the combined use
        // of the same target exceeds its budget; no shape check masks it.
        let payment = |last| {
            intent(
                b"payment",
                vec![
                    leg(Side::Credit, "receivable", i128::MAX - 1),
                    leg(Side::Credit, "receivable", last),
                    leg(Side::Debit, "cash", i128::MAX - 1),
                    leg(Side::Debit, "cash", last),
                ],
                vec![
                    Settle {
                        leg: 0,
                        target: 0,
                        ordinal: 0,
                        mantissa: i128::MAX - 1,
                    },
                    Settle {
                        leg: 1,
                        target: 0,
                        ordinal: 0,
                        mantissa: last,
                    },
                ],
            )
        };
        let before = oracle.known();
        assert_eq!(
            oracle.post(&payment(2)),
            Verdict::Refused {
                code: code::OVER_APPLICATION
            }
        );
        assert_eq!(oracle.known(), before);
        assert_eq!(oracle.open_items()[&(0, 0)], (i128::MAX, 0, 0));
        assert!(matches!(
            oracle.post(&payment(1)),
            Verdict::Posted { index: 1, .. }
        ));
        let items = oracle.open_items();
        assert_eq!(items[&(0, 0)], (i128::MAX, i128::MAX, 0));
        assert_eq!(items[&(1, 0)], (i128::MAX - 1, 0, i128::MAX - 1));
        assert_eq!(items[&(1, 1)], (1, 0, 1));
        let before = oracle.known();
        // A payment leg that applied all its value out cannot itself be
        // consumed by a later entry; its open amount includes applied-out.
        let consume_payment = intent(
            b"consumed-source",
            vec![
                leg(Side::Debit, "receivable", 1),
                leg(Side::Credit, "cash", 1),
            ],
            vec![Settle {
                leg: 0,
                target: 1,
                ordinal: 0,
                mantissa: 1,
            }],
        );
        assert_eq!(
            oracle.post(&consume_payment),
            Verdict::Refused {
                code: code::OVER_APPLICATION
            }
        );
        assert_eq!(oracle.known(), before);
        assert_eq!(oracle.open_items(), items);
        // The independent structural sum exceeds i128; this is an exact
        // comparison to the source leg, not checked-add agreement with the
        // production implementation. Distinct targets avoid duplicate-law
        // masking, and target lookup comes later than this shape refusal.
        let too_much = intent(
            b"wide-shape",
            vec![
                leg(Side::Credit, "receivable", i128::MAX),
                leg(Side::Debit, "cash", i128::MAX),
            ],
            vec![
                Settle {
                    leg: 0,
                    target: 0,
                    ordinal: 0,
                    mantissa: i128::MAX,
                },
                Settle {
                    leg: 0,
                    target: 1,
                    ordinal: 0,
                    mantissa: i128::MAX,
                },
            ],
        );
        assert_eq!(
            oracle.post(&too_much),
            Verdict::Refused {
                code: code::SETTLE_SHAPE
            }
        );
        assert_eq!(oracle.known(), before);
        assert_eq!(oracle.open_items(), items);
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
        o.create_periods(2026).unwrap();
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
        o.create_periods(2026).unwrap();
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
        o.create_periods(2026).unwrap();
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
        o.create_periods(2026).unwrap();
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
}
