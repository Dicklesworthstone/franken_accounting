//! Almanac — FrankenAccounting's time model (plan §7).
//!
//! **Effective** time is the civil-date axis every period-scoped entry is
//! anchored to and every period is sliced on. **Known-at** system time is
//! the substrate's `CommitSeq`, assigned solely by its commit stream.
//! This crate resolves explicit instant selectors over retained
//! `TimeEvidence` values (§7.1a); it never journals a tick, assigns a
//! recorded sequence, or reads a clock. It has no notion of "now".
//!
//! - [`DateDay`]: days since 1970-01-01, proleptic Gregorian, exact.
//! - [`FiscalCalendar`]: generates [`PeriodDef`]s deterministically from its
//!   kind, including adjustment, opening, closing, and historical periods that
//!   share civil dates with normal periods and are selected only through the
//!   `effective_period` discriminator (§7.3).
//! - [`BusinessCalendar`]: explicit workweeks, holiday tables, checked
//!   business-day offsets, and named date adjustments (§7.7).
//! - [`MonthlyRecurrence`]: anchor-preserving monthly dates with an explicit
//!   end-of-month law and stable occurrence indices (§7.6–§7.7).
//! - [`PeriodState`]: the state machine whose transitions are control entries.
//! - [`EffectiveSelector`]: `All`, `Period`, `Range`, `AsOf`, `YearToDate`,
//!   `InceptionToDate` (§4.8).
//! - [`UtcInstant`]: exact RFC 3339 input in TimeEvidence's nanosecond domain.
//! - [`resolve_instant`]: frontier-bound tick buckets and retained brackets.

#![forbid(unsafe_code)]

pub mod business;
pub mod calendar;
pub mod date;
pub mod instant;
pub mod period;
pub mod recurrence;
pub mod selector;

pub use business::{AdjustedOccurrence, BusinessCalendar, BusinessDayConvention, BusinessDayError};
pub use calendar::{CalendarKind, FiscalCalendar, WeekPattern, YearEndRule};
pub use date::{DateDay, DateError, MonthEndPolicy, Weekday};
pub use instant::{
    InstantParseError, InstantResolution, InstantResolutionError, TimeObservation, UtcInstant,
    resolve_instant, resolve_instant_with_genesis,
};
pub use period::{
    PeriodDef, PeriodKind, PeriodState, PeriodTransition, ResolveError, TransitionError,
    resolve_period,
};
pub use recurrence::{MonthlyOccurrence, MonthlyOccurrences, MonthlyRecurrence, RecurrenceError};
pub use selector::{EffectiveSelector, SelectorError};
