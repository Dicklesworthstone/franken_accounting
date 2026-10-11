//! Independent temporal admission for the reference engine. Only registry
//! text and civil/calendar data are shared with production: this reader does
//! not call Admissibility's class decisions or fa-time's period resolver.

use std::collections::{BTreeMap, BTreeSet};

use fa_registry::toml::{self, Value};
use fa_time::{DateDay, PeriodDef, PeriodKind};

#[derive(Clone, Debug)]
pub(super) struct SpecialPeriods(BTreeMap<String, BTreeSet<String>>);

impl SpecialPeriods {
    pub(super) fn embedded() -> Self {
        Self::parse(include_str!("../../../registries/admissibility.toml"))
            .expect("reference special-period registry")
    }

    fn parse(text: &str) -> Result<Self, &'static str> {
        let doc = toml::parse(text).map_err(|_| "invalid registry syntax")?;
        let tables = doc
            .arrays
            .get("special_period_classes")
            .ok_or("missing special-period rules")?;
        let mut result = BTreeMap::new();
        for table in tables {
            let kind = table
                .get("kind")
                .and_then(Value::as_str)
                .ok_or("missing period kind")?;
            if !["Opening", "Adjustment", "Closing"].contains(&kind) {
                return Err("not a special period kind");
            }
            if table.get("refusal").and_then(Value::as_str) != Some("FA-REF-010") {
                return Err("unexpected special-period refusal");
            }
            let names = table
                .get("admits")
                .and_then(Value::as_array)
                .ok_or("missing admitted classes")?;
            let mut classes = BTreeSet::new();
            for name in names {
                let class = name.as_str().ok_or("class is not a name")?;
                if !classes.insert(class.to_owned()) {
                    return Err("duplicate class");
                }
            }
            if classes.is_empty() || result.insert(kind.into(), classes).is_some() {
                return Err("empty or repeated rule");
            }
        }
        if result.len() != 3 {
            return Err("missing special-period kind");
        }
        Ok(Self(result))
    }

    pub(super) fn admits(&self, kind: PeriodKind, class: &str) -> bool {
        let name = match kind {
            PeriodKind::Opening => "Opening",
            PeriodKind::Adjustment => "Adjustment",
            PeriodKind::Closing => "Closing",
            PeriodKind::Normal | PeriodKind::Historical => return true,
        };
        self.0.get(name).is_some_and(|names| names.contains(class))
    }
}

/// Literal uniqueness check over the definitions. An explicit code selects
/// that period only when its civil interval contains the posting day.
pub(super) fn resolve<'a>(
    definitions: &'a [PeriodDef],
    day: DateDay,
    discriminator: Option<&str>,
) -> Option<&'a PeriodDef> {
    let mut found = None;
    for period in definitions {
        if day < period.start || day >= period.end {
            continue;
        }
        let selected = match discriminator {
            Some(code) => period.code == code,
            None => matches!(period.kind, PeriodKind::Normal | PeriodKind::Historical),
        };
        if selected && found.replace(period).is_some() {
            return None;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_special_kind_restricts_classes_in_the_reference() {
        let rules = SpecialPeriods::embedded();
        for kind in [
            PeriodKind::Opening,
            PeriodKind::Adjustment,
            PeriodKind::Closing,
        ] {
            for class in [
                "Adjusting",
                "Closing",
                "Elimination",
                "Revision",
                "Restatement",
                "Migration",
            ] {
                assert!(rules.admits(kind, class), "{kind:?} {class}");
            }
            for class in [
                "Original",
                "Pending",
                "Resolution",
                "Reversal",
                "Replacement",
                "Reclassification",
                "Allocation",
                "Revaluation",
                "PriorPeriodAdjustment",
            ] {
                assert!(!rules.admits(kind, class), "{kind:?} {class}");
            }
        }
        let text = include_str!("../../../registries/admissibility.toml");
        assert!(
            SpecialPeriods::parse(&text.replacen("kind = \"Opening\"", "kind = \"Normal\"", 1))
                .is_err()
        );
        assert!(
            SpecialPeriods::parse(&text.replacen("kind = \"Opening\"", "kind = \"Closing\"", 1))
                .is_err()
        );
    }

    #[test]
    fn reference_period_selection_checks_discriminators_and_unique_defaults() {
        let calendar = fa_time::FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let mut definitions = calendar.periods_for_year(2026).unwrap();
        let day = DateDay::parse("2026-12-31").unwrap();
        assert_eq!(resolve(&definitions, day, None).unwrap().code, "FY2026-P12");
        assert_eq!(
            resolve(&definitions, day, Some("FY2026-A1")).unwrap().kind,
            PeriodKind::Adjustment
        );
        assert!(resolve(&definitions, day, Some("FY2026-P11")).is_none());
        let duplicate = definitions
            .iter()
            .find(|p| p.code == "FY2026-P12")
            .unwrap()
            .clone();
        definitions.push(duplicate);
        assert!(resolve(&definitions, day, None).is_none());
    }
}

#[cfg(test)]
mod instant_tests {
    use std::collections::BTreeMap;

    use fa_time::{
        InstantResolution, InstantResolutionError, TimeObservation, resolve_instant,
    };

    /// Deliberately literal oracle: at every commit position, look up its
    /// latest retained observation and apply the request's time predicate.
    /// This walks the commit domain instead of deriving a bucket's end from
    /// the next tick. The fixtures keep that domain small; the production
    /// resolver must also support sparse u64 sequence numbers.
    fn literal_resolution(
        ticks: &[TimeObservation],
        requested_utc_ns: u64,
        frontier: u64,
    ) -> Result<InstantResolution, InstantResolutionError> {
        let visible: Vec<_> = ticks
            .iter()
            .copied()
            .filter(|tick| tick.recorded_at <= frontier)
            .collect();
        for pair in visible.windows(2) {
            if pair[0].recorded_at >= pair[1].recorded_at {
                return Err(InstantResolutionError::SequenceOrder {
                    previous: pair[0].recorded_at,
                    next: pair[1].recorded_at,
                });
            }
            if pair[0].observed_utc_ns >= pair[1].observed_utc_ns {
                return Err(InstantResolutionError::ObservationOrder {
                    previous_utc_ns: pair[0].observed_utc_ns,
                    next_utc_ns: pair[1].observed_utc_ns,
                    recorded_at: pair[1].recorded_at,
                });
            }
        }
        if let Some(tick) = visible.iter().find(|tick| tick.source != 0) {
            return Err(InstantResolutionError::UnsupportedSource {
                recorded_at: tick.recorded_at,
                source: tick.source,
            });
        }
        let by_sequence: BTreeMap<_, _> = visible
            .iter()
            .map(|tick| (tick.recorded_at, *tick))
            .collect();
        let first = visible
            .first()
            .copied()
            .ok_or(InstantResolutionError::NoTicks { frontier })?;
        let mut selected = None;
        for seq in 0..=frontier {
            if let Some((_, observation)) = by_sequence.range(..=seq).next_back()
                && observation.observed_utc_ns <= requested_utc_ns
            {
                selected = Some((seq, *observation));
            }
        }
        let (resolved_seq, lower) =
            selected.ok_or(InstantResolutionError::BeforeFirstTick {
                requested_utc_ns,
                first,
            })?;
        let upper = by_sequence
            .values()
            .find(|tick| tick.recorded_at > resolved_seq)
            .copied();
        Ok(InstantResolution {
            requested_utc_ns,
            frontier,
            resolved_seq,
            lower,
            upper,
        })
    }

    fn observation(recorded_at: u64, observed_utc_ns: u64) -> TimeObservation {
        TimeObservation {
            recorded_at,
            observed_utc_ns,
            source: 0,
            monotonic_ok: true,
        }
    }

    #[test]
    fn instant_resolution_matches_a_literal_commit_walk() {
        // Every subset of seven possible tick positions, with non-tick
        // commits before/between/after observations. Time advances by an
        // independent ordinal, not by sequence. Both corroboration grades
        // appear, and every possible frontier cuts a different prefix.
        for mask in 0u16..(1 << 7) {
            let mut ticks = Vec::new();
            let mut observed_utc_ns = 4;
            for recorded_at in 1..=7 {
                if mask & (1 << (recorded_at - 1)) != 0 {
                    let mut tick = observation(recorded_at, observed_utc_ns);
                    tick.monotonic_ok = (recorded_at + u64::from(mask)) % 3 != 0;
                    ticks.push(tick);
                    observed_utc_ns += 3;
                }
            }
            for frontier in 0..=9 {
                for requested_utc_ns in 0..=26 {
                    assert_eq!(
                        resolve_instant(&ticks, requested_utc_ns, frontier),
                        literal_resolution(&ticks, requested_utc_ns, frontier),
                        "mask {mask}, instant {requested_utc_ns}, frontier {frontier}",
                    );
                }
            }
        }
    }

    #[test]
    fn literal_oracle_checks_the_plan_frontier_vectors_and_negative_histories() {
        let ticks = [observation(10, 100), observation(13, 110)];
        for (frontier, expected) in [(11, 11), (12, 12), (13, 12)] {
            let result = literal_resolution(&ticks, 105, frontier).unwrap();
            assert_eq!(result.resolved_seq, expected);
            assert_eq!(resolve_instant(&ticks, 105, frontier), Ok(result));
        }
        for ticks in [
            vec![],
            vec![observation(10, 106)],
            vec![observation(10, 100), observation(9, 110)],
            vec![observation(10, 100), observation(10, 110)],
            vec![observation(10, 100), observation(13, 100)],
            vec![observation(10, 100), observation(13, 90)],
            vec![TimeObservation {
                source: 2,
                ..observation(10, 100)
            }],
        ] {
            let reference = literal_resolution(&ticks, 105, 20);
            assert!(reference.is_err(), "negative fixture unexpectedly resolved");
            assert_eq!(resolve_instant(&ticks, 105, 20), reference, "{ticks:?}");
        }
    }
}
