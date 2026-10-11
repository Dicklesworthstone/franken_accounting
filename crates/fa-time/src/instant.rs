//! Exact RFC 3339 selectors and journal-tick resolution (plan §7.1a).
//!
//! Instants are explicit inputs in the journal's u64 Unix-nanosecond
//! domain. This module never reads a clock or assigns a recorded sequence.
//! Resolution interprets the latest tick at each commit in a saved prefix;
//! it makes no claim about an entry's exact physical commit time.

use core::{fmt, str::FromStr};

use crate::{DateDay, DateError};

const NS_PER_SECOND: u64 = 1_000_000_000;
const SECONDS_PER_DAY: u64 = 86_400;
const NS_PER_DAY: u64 = SECONDS_PER_DAY * NS_PER_SECOND;

/// An explicit instant in TimeEvidence's u64 Unix-nanosecond domain.
///
/// Display is canonical UTC, with an uppercase T/Z and exactly nine
/// fractional digits. The type has no ambient-clock constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcInstant(u64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstantParseError {
    Malformed,
    InvalidDate(DateError),
    InvalidTime,
    InvalidOffset,
    LeapSecondUnsupported,
    UnknownOffsetUnsupported,
    PrecisionUnsupported,
    OutOfRange,
}

impl fmt::Display for InstantParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str(
                "malformed instant; expected YYYY-MM-DDTHH:MM:SS[.fffffffff]Z or a numeric offset",
            ),
            Self::InvalidDate(error) => write!(f, "invalid instant date: {error}"),
            Self::InvalidTime => {
                f.write_str("invalid instant time; hours must be 00..23 and minutes/seconds 00..59")
            }
            Self::InvalidOffset => f.write_str(
                "invalid UTC offset; expected +HH:MM or -HH:MM with HH <= 23 and MM <= 59",
            ),
            Self::LeapSecondUnsupported => f.write_str(
                "leap-second instants are unsupported by the Unix-nanosecond tick domain",
            ),
            Self::UnknownOffsetUnsupported => {
                f.write_str("the RFC 3339 -00:00 unknown-local-offset convention is unsupported")
            }
            Self::PrecisionUnsupported => f.write_str(
                "more than nine fractional digits are unsupported; no rounding is applied",
            ),
            Self::OutOfRange => {
                f.write_str("instant is outside the supported 0..=u64::MAX Unix-nanosecond domain")
            }
        }
    }
}

impl core::error::Error for InstantParseError {}

impl UtcInstant {
    pub const fn from_unix_ns(ns: u64) -> Self {
        Self(ns)
    }

    pub const fn unix_ns(self) -> u64 {
        self.0
    }

    /// Parse the RFC 3339 §5.6 grammar with an explicit UTC/numeric offset.
    ///
    /// The supported precision is zero through nine fractional digits.
    /// Lowercase t/z is accepted as RFC 3339 permits; whitespace, an absent
    /// offset, leap seconds, -00:00, and values outside the tick domain are
    /// refused. Offsets are applied before the domain check, so a local date
    /// before 1970 is admissible when its UTC instant is representable.
    pub fn parse(text: &str) -> Result<Self, InstantParseError> {
        let bytes = text.as_bytes();
        if bytes.len() < 20
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || !matches!(bytes[10], b'T' | b't')
            || bytes[13] != b':'
            || bytes[16] != b':'
        {
            return Err(InstantParseError::Malformed);
        }
        // Each pair is bounded by 99; the year is therefore at most 9999.
        let year = i32::from(pair(&bytes[..2])?) * 100 + i32::from(pair(&bytes[2..4])?);
        let month = pair(&bytes[5..7])?;
        let day = pair(&bytes[8..10])?;
        let hour = pair(&bytes[11..13])?;
        let minute = pair(&bytes[14..16])?;
        let second = pair(&bytes[17..19])?;

        let mut cursor = 19;
        let mut fraction_ns = 0u64;
        if bytes.get(cursor) == Some(&b'.') {
            cursor += 1;
            let start = cursor;
            while let Some(&digit) = bytes.get(cursor) {
                if !digit.is_ascii_digit() {
                    break;
                }
                if cursor - start == 9 {
                    return Err(InstantParseError::PrecisionUnsupported);
                }
                // At most nine decimal digits, so this remains below 10^9.
                fraction_ns = fraction_ns * 10 + u64::from(digit - b'0');
                cursor += 1;
            }
            if cursor == start {
                return Err(InstantParseError::Malformed);
            }
            for _ in (cursor - start)..9 {
                fraction_ns *= 10;
            }
        }

        let offset_seconds = match bytes.get(cursor) {
            Some(b'Z' | b'z') if cursor + 1 == bytes.len() => 0i32,
            Some(b'+' | b'-')
                if cursor + 6 == bytes.len() && bytes[cursor + 3] == b':' =>
            {
                let hours = pair(&bytes[cursor + 1..cursor + 3])?;
                let minutes = pair(&bytes[cursor + 4..cursor + 6])?;
                if hours > 23 || minutes > 59 {
                    return Err(InstantParseError::InvalidOffset);
                }
                let magnitude = i32::from(hours) * 3600 + i32::from(minutes) * 60;
                if bytes[cursor] == b'-' {
                    if magnitude == 0 {
                        return Err(InstantParseError::UnknownOffsetUnsupported);
                    }
                    -magnitude
                } else {
                    magnitude
                }
            }
            _ => return Err(InstantParseError::Malformed),
        };
        if hour > 23 || minute > 59 || second > 60 {
            return Err(InstantParseError::InvalidTime);
        }
        if second == 60 {
            return Err(InstantParseError::LeapSecondUnsupported);
        }
        let date = DateDay::from_ymd(year, month, day).map_err(InstantParseError::InvalidDate)?;
        let local_seconds = i128::from(date.0)
            .checked_mul(i128::from(SECONDS_PER_DAY))
            .and_then(|seconds| seconds.checked_add(i128::from(hour) * 3600))
            .and_then(|seconds| seconds.checked_add(i128::from(minute) * 60))
            .and_then(|seconds| seconds.checked_add(i128::from(second)))
            .ok_or(InstantParseError::OutOfRange)?;
        let utc_ns = local_seconds
            .checked_sub(i128::from(offset_seconds))
            .and_then(|seconds| seconds.checked_mul(i128::from(NS_PER_SECOND)))
            .and_then(|ns| ns.checked_add(i128::from(fraction_ns)))
            .ok_or(InstantParseError::OutOfRange)?;
        u64::try_from(utc_ns)
            .map(Self)
            .map_err(|_| InstantParseError::OutOfRange)
    }
}

impl FromStr for UtcInstant {
    type Err = InstantParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl fmt::Display for UtcInstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Even u64::MAX nanoseconds is fewer than i32::MAX civil days.
        let day = i32::try_from(self.0 / NS_PER_DAY).map_err(|_| fmt::Error)?;
        let date = DateDay(day);
        let seconds = (self.0 / NS_PER_SECOND) % SECONDS_PER_DAY;
        let hour = seconds / 3600;
        let minute = (seconds % 3600) / 60;
        let second = seconds % 60;
        let fraction = self.0 % NS_PER_SECOND;
        write!(f, "{date}T{hour:02}:{minute:02}:{second:02}.{fraction:09}Z")
    }
}

fn pair(bytes: &[u8]) -> Result<u8, InstantParseError> {
    let [high, low] = bytes else {
        return Err(InstantParseError::Malformed);
    };
    if !high.is_ascii_digit() || !low.is_ascii_digit() {
        return Err(InstantParseError::Malformed);
    }
    Ok((*high - b'0') * 10 + (*low - b'0'))
}

/// Values decoded from one committed TimeEvidence entry.
///
/// The adapter derives recorded_at from the entry's creating marker. It
/// must retain the entry identity beside these values in certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeObservation {
    pub recorded_at: u64,
    pub observed_utc_ns: u64,
    /// Source 0 is DaemonClock. Other sources require their evidence rules.
    pub source: u8,
    /// False remains admissible evidence for a read, with a weaker grade.
    pub monotonic_ok: bool,
}

/// The complete tick-bucket interpretation at one observed book frontier.
///
/// An absent upper tick means the bracket is open at this frontier. Replay
/// uses resolved_seq and the retained ticks rather than resolving at a new
/// head. A later frontier can resolve the same requested instant differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstantResolution {
    pub requested_utc_ns: u64,
    pub frontier: u64,
    pub resolved_seq: u64,
    pub lower: TimeObservation,
    pub upper: Option<TimeObservation>,
}

impl InstantResolution {
    /// Interpretation grade; this is not physical commit-time precision.
    pub const fn precision_grade(&self) -> &'static str {
        "tick_bucket"
    }

    /// The weakest source/corroboration grade among the saved brackets.
    /// Neither daemon-clock grade constitutes an external UTC attestation.
    pub fn source_grade(&self) -> &'static str {
        if self.lower.source != 0 || self.upper.is_some_and(|tick| tick.source != 0) {
            "unsupported_source"
        } else if self.lower.monotonic_ok && self.upper.is_none_or(|tick| tick.monotonic_ok) {
            "corroborated_daemon_clock"
        } else {
            "uncorroborated_daemon_clock"
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstantResolutionError {
    NoTicks {
        frontier: u64,
    },
    BeforeFirstTick {
        requested_utc_ns: u64,
        first: TimeObservation,
    },
    SequenceOrder {
        previous: u64,
        next: u64,
    },
    ObservationOrder {
        previous_utc_ns: u64,
        next_utc_ns: u64,
        recorded_at: u64,
    },
    UnsupportedSource {
        recorded_at: u64,
        source: u8,
    },
}

impl fmt::Display for InstantResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTicks { frontier } => {
                write!(f, "no TimeEvidence ticks exist at frontier {frontier}")
            }
            Self::BeforeFirstTick {
                requested_utc_ns,
                first,
            } => write!(
                f,
                "instant {requested_utc_ns} ns precedes the first TimeEvidence tick ({} ns at seq {})",
                first.observed_utc_ns, first.recorded_at,
            ),
            Self::SequenceOrder { previous, next } => write!(
                f,
                "TimeEvidence sequences are not strictly increasing: {previous}, {next}",
            ),
            Self::ObservationOrder {
                previous_utc_ns,
                next_utc_ns,
                recorded_at,
            } => write!(
                f,
                "TimeEvidence at seq {recorded_at} observes {next_utc_ns} ns after {previous_utc_ns} ns; observations must strictly increase",
            ),
            Self::UnsupportedSource {
                recorded_at,
                source,
            } => write!(
                f,
                "TimeEvidence source {source} at seq {recorded_at} lacks supported evidence rules",
            ),
        }
    }
}

impl core::error::Error for InstantResolutionError {}

/// Resolve an instant over an ordered, complete list of retained tick facts.
///
/// Only ticks at or below frontier participate; later ticks cannot close an
/// earlier frontier's open bracket. The complete visible list is validated,
/// even after the requested bucket is found, so malformed ordering is not
/// hidden by an early return. Missing ticks cannot be detected from values
/// alone: the storage/certificate adapter supplies and retains that closure.
///
/// A tick is its own latest observation. The result is immediately before
/// the first tick whose time exceeds the request, or frontier if no such
/// tick exists. Non-tick commits within the bucket therefore participate.
pub fn resolve_instant(
    observations: &[TimeObservation],
    requested_utc_ns: u64,
    frontier: u64,
) -> Result<InstantResolution, InstantResolutionError> {
    let mut first = None;
    let mut previous: Option<TimeObservation> = None;
    let mut lower = None;
    let mut upper = None;
    for tick in observations
        .iter()
        .copied()
        .filter(|tick| tick.recorded_at <= frontier)
    {
        if let Some(prev) = previous {
            if tick.recorded_at <= prev.recorded_at {
                return Err(InstantResolutionError::SequenceOrder {
                    previous: prev.recorded_at,
                    next: tick.recorded_at,
                });
            }
            if tick.observed_utc_ns <= prev.observed_utc_ns {
                return Err(InstantResolutionError::ObservationOrder {
                    previous_utc_ns: prev.observed_utc_ns,
                    next_utc_ns: tick.observed_utc_ns,
                    recorded_at: tick.recorded_at,
                });
            }
        }
        if tick.source != 0 {
            return Err(InstantResolutionError::UnsupportedSource {
                recorded_at: tick.recorded_at,
                source: tick.source,
            });
        }
        if first.is_none() {
            first = Some(tick);
        }
        previous = Some(tick);
        if tick.observed_utc_ns <= requested_utc_ns {
            lower = Some(tick);
        } else if upper.is_none() {
            upper = Some(tick);
        }
    }
    let first = first.ok_or(InstantResolutionError::NoTicks { frontier })?;
    let lower = lower.ok_or(InstantResolutionError::BeforeFirstTick {
        requested_utc_ns,
        first,
    })?;
    let resolved_seq = match upper {
        Some(tick) => tick.recorded_at.checked_sub(1).ok_or(
            InstantResolutionError::SequenceOrder {
                previous: lower.recorded_at,
                next: tick.recorded_at,
            },
        )?,
        None => frontier,
    };
    Ok(InstantResolution {
        requested_utc_ns,
        frontier,
        resolved_seq,
        lower,
        upper,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tick(recorded_at: u64, observed_utc_ns: u64) -> TimeObservation {
        TimeObservation {
            recorded_at,
            observed_utc_ns,
            source: 0,
            monotonic_ok: true,
        }
    }

    #[test]
    fn rfc3339_offsets_and_fractions_are_exact() {
        let epoch = UtcInstant::from_unix_ns(0);
        for input in [
            "1970-01-01T00:00:00Z",
            "1970-01-01t00:00:00z",
            "1970-01-01T00:00:00+00:00",
            "1969-12-31T19:00:00-05:00",
            "1970-01-01T05:30:00+05:30",
            "1970-01-01T23:59:00+23:59",
        ] {
            assert_eq!(UtcInstant::parse(input), Ok(epoch), "{input}");
        }
        for (input, expected) in [
            ("1970-01-01T00:00:00.1Z", 100_000_000),
            ("1970-01-01T00:00:00.000000001Z", 1),
            ("1970-01-01T00:00:00.0100Z", 10_000_000),
            ("1970-01-01T00:01:00.000000001+00:01", 1),
            ("2000-02-29T12:34:56.123456789Z", 951_827_696_123_456_789),
        ] {
            assert_eq!(
                UtcInstant::parse(input).unwrap().unix_ns(),
                expected,
                "{input}",
            );
        }
        assert_eq!(epoch.to_string(), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(
            UtcInstant::parse("2000-02-29T08:34:56.123456789-04:00").unwrap().to_string(),
            "2000-02-29T12:34:56.123456789Z",
        );
    }

    #[test]
    fn parser_refuses_malformed_dates_times_and_unsupported_precision() {
        for input in [
            "",
            "2026-10-11",
            "2026-10-11T12:00:00",
            " 2026-10-11T12:00:00Z",
            "2026-10-11T12:00:00Z\n",
            "2026-10-11 12:00:00Z",
            "2026-1-11T12:00:00Z",
            "+026-10-11T12:00:00Z",
            "2026-10-11T+2:00:00Z",
            "2026-10-11T12:00:00.Z",
            "2026-10-11T12:00:00,1Z",
            "2026-10-11T12:00:00+0000",
            "2026-10-11T12:00:00+00",
            "2026-10-11T12:00:00UTC",
            "2026-10-11T12:00:00Zignored",
            "２０２６-10-11T12:00:00Z",
            "2026-10-11T12:00:00.éZ",
        ] {
            assert!(UtcInstant::parse(input).is_err(), "accepted {input}");
        }
        for input in [
            "2026-02-29T12:00:00Z",
            "2100-02-29T12:00:00Z",
            "2026-00-01T12:00:00Z",
            "2026-04-31T12:00:00Z",
        ] {
            assert!(matches!(UtcInstant::parse(input), Err(InstantParseError::InvalidDate(_))));
        }
        for input in [
            "2026-10-11T24:00:00Z",
            "2026-10-11T12:60:00Z",
            "2026-10-11T12:00:61Z",
        ] {
            assert_eq!(UtcInstant::parse(input), Err(InstantParseError::InvalidTime));
        }
        for input in ["2026-10-11T12:00:00+24:00", "2026-10-11T12:00:00-00:60"] {
            assert_eq!(UtcInstant::parse(input), Err(InstantParseError::InvalidOffset));
        }
        assert_eq!(
            UtcInstant::parse("2016-12-31T23:59:60Z"),
            Err(InstantParseError::LeapSecondUnsupported),
        );
        assert_eq!(
            UtcInstant::parse("2026-10-11T12:00:00-00:00"),
            Err(InstantParseError::UnknownOffsetUnsupported),
        );
        assert_eq!(
            UtcInstant::parse("2026-10-11T12:00:00.0000000000Z"),
            Err(InstantParseError::PrecisionUnsupported),
        );
    }

    #[test]
    fn tick_domain_boundaries_never_wrap_or_round() {
        let last = "2554-07-21T23:34:33.709551615Z";
        assert_eq!(UtcInstant::parse(last).unwrap().unix_ns(), u64::MAX);
        assert_eq!(UtcInstant::from_unix_ns(u64::MAX).to_string(), last);
        assert_eq!(
            UtcInstant::parse("2554-07-22T00:34:33.709551615+01:00").unwrap().unix_ns(),
            u64::MAX,
        );
        for input in [
            "1969-12-31T23:59:59.999999999Z",
            "1970-01-01T00:00:00.000000001+00:01",
            "2554-07-21T23:34:33.709551616Z",
            "2554-07-21T23:34:33.709551615-00:01",
            "0000-01-01T00:00:00Z",
            "9999-12-31T23:59:59Z",
        ] {
            assert_eq!(UtcInstant::parse(input), Err(InstantParseError::OutOfRange), "{input}");
        }
        for ns in [
            0, 1, 999_999_999, 1_000_000_000, NS_PER_DAY - 1, NS_PER_DAY,
            951_827_696_123_456_789, u64::MAX - 1, u64::MAX,
        ] {
            let instant = UtcInstant::from_unix_ns(ns);
            assert_eq!(instant.to_string().parse::<UtcInstant>(), Ok(instant));
        }
    }

    #[test]
    fn plan_golden_vectors_resolve_the_whole_tick_bucket() {
        let ticks = [tick(10, 100), tick(13, 110)];
        for (frontier, expected) in [(11, 11), (12, 12), (13, 12)] {
            let got = resolve_instant(&ticks, 105, frontier).unwrap();
            assert_eq!(got.requested_utc_ns, 105);
            assert_eq!(got.frontier, frontier);
            assert_eq!(got.resolved_seq, expected);
            assert_eq!(got.lower, ticks[0]);
            assert_eq!(got.upper, (frontier >= 13).then_some(ticks[1]));
            assert_eq!(got.precision_grade(), "tick_bucket");
        }
    }

    #[test]
    fn exact_tick_boundaries_and_open_brackets_are_explicit() {
        let ticks = [tick(10, 100), tick(13, 110), tick(20, 120)];
        for (instant, frontier, seq, lower, upper) in [
            (100, 10, 10, 0, None),
            (100, 20, 12, 0, Some(1)),
            (109, 20, 12, 0, Some(1)),
            (110, 13, 13, 1, None),
            (110, 20, 19, 1, Some(2)),
            (119, 20, 19, 1, Some(2)),
            (120, 25, 25, 2, None),
            (u64::MAX, 25, 25, 2, None),
        ] {
            let got = resolve_instant(&ticks, instant, frontier).unwrap();
            assert_eq!(got.resolved_seq, seq, "instant {instant}, frontier {frontier}");
            assert_eq!(got.lower, ticks[lower]);
            assert_eq!(got.upper, upper.map(|index| ticks[index]));
        }
        let at_end = [tick(u64::MAX - 1, 100), tick(u64::MAX, 110)];
        assert_eq!(resolve_instant(&at_end, 105, u64::MAX).unwrap().resolved_seq, u64::MAX - 1);
        assert_eq!(resolve_instant(&at_end, 110, u64::MAX).unwrap().resolved_seq, u64::MAX);
    }

    #[test]
    fn no_tick_and_before_first_tick_have_distinct_refusals() {
        let ticks = [tick(10, 100)];
        assert_eq!(
            resolve_instant(&[], 105, 20),
            Err(InstantResolutionError::NoTicks { frontier: 20 }),
        );
        assert_eq!(
            resolve_instant(&ticks, 105, 9),
            Err(InstantResolutionError::NoTicks { frontier: 9 }),
        );
        assert_eq!(
            resolve_instant(&ticks, 99, 20),
            Err(InstantResolutionError::BeforeFirstTick {
                requested_utc_ns: 99,
                first: ticks[0],
            }),
        );
    }

    #[test]
    fn all_visible_evidence_is_checked_even_after_an_upper_bracket() {
        for ticks in [
            [tick(10, 100), tick(13, 110), tick(12, 120)],
            [tick(10, 100), tick(13, 110), tick(13, 120)],
        ] {
            assert!(matches!(
                resolve_instant(&ticks, 105, 20),
                Err(InstantResolutionError::SequenceOrder { .. }),
            ));
        }
        for ticks in [
            [tick(10, 100), tick(13, 110), tick(14, 110)],
            [tick(10, 100), tick(13, 110), tick(14, 99)],
        ] {
            assert!(matches!(
                resolve_instant(&ticks, 105, 20),
                Err(InstantResolutionError::ObservationOrder { .. }),
            ));
        }
        let mut unsupported = tick(15, 120);
        unsupported.source = 1;
        assert_eq!(
            resolve_instant(&[tick(10, 100), unsupported], 105, 20),
            Err(InstantResolutionError::UnsupportedSource {
                recorded_at: 15,
                source: 1,
            }),
        );
        // Future corruption has no bearing on a saved, earlier prefix.
        assert_eq!(
            resolve_instant(&[tick(10, 100), tick(13, 99), unsupported], 105, 12),
            resolve_instant(&[tick(10, 100)], 105, 12),
        );
    }

    #[test]
    fn uncorroborated_ticks_remain_evidence_with_their_weaker_grade() {
        let lower = tick(10, 100);
        let mut upper = tick(13, 110);
        upper.monotonic_ok = false;
        let closed = resolve_instant(&[lower, upper], 105, 20).unwrap();
        assert_eq!(closed.upper, Some(upper));
        assert_eq!(closed.source_grade(), "uncorroborated_daemon_clock");
        let open = resolve_instant(&[lower, upper], 105, 12).unwrap();
        assert_eq!(open.source_grade(), "corroborated_daemon_clock");
        let latest = resolve_instant(&[lower, upper], 110, 20).unwrap();
        assert_eq!(latest.lower, upper);
        assert_eq!(latest.source_grade(), "uncorroborated_daemon_clock");
        assert_eq!(latest.resolved_seq, 20);
    }
}
