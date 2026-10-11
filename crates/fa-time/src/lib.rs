//! Almanac — FrankenAccounting's time model (plan §7).
//!
//! Two axes, one of which lives here: **effective** time is the civil-date
//! axis every entry is anchored to and every period is sliced on. Known-at
//! (system time) is the substrate's `CommitSeq` and never appears in this
//! crate; wall-clock instants enter the book only as journaled `TimeEvidence`
//! control entries (§7.1a), also not here. This crate therefore has no notion
//! of "now".
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

#![forbid(unsafe_code)]

pub mod business;
pub mod calendar;
pub mod date;
pub mod period;
pub mod recurrence;
pub mod selector;

pub use business::{AdjustedOccurrence, BusinessCalendar, BusinessDayConvention, BusinessDayError};
pub use calendar::{CalendarKind, FiscalCalendar, WeekPattern, YearEndRule};
pub use date::{DateDay, DateError, MonthEndPolicy, Weekday};
pub use period::{
    PeriodDef, PeriodKind, PeriodState, PeriodTransition, ResolveError, TransitionError,
    resolve_period,
};
pub use recurrence::{MonthlyOccurrence, MonthlyOccurrences, MonthlyRecurrence, RecurrenceError};
pub use selector::{EffectiveSelector, SelectorError};
