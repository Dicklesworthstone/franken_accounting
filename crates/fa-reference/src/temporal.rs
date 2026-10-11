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
