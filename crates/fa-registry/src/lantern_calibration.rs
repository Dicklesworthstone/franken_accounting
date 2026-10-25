//! `registries/lantern_calibration.toml`: the measured precision and recall of
//! every Lantern procedure an `fa-gen` scenario labels (plan §11.10, G3; bead
//! fa-4psc). A procedure registered with `calibration = "corpus"` has exactly
//! one row here, under its own FA-EVID-L id; a row names a `corpus`
//! procedure. fa-lantern's `labeled_procedures_measure_what_the_calibration_registry_pins`
//! re-runs the measurement over the same seeds and fails on any drift, so a
//! row is never more than what the procedure does today.

use std::collections::BTreeSet;

use crate::procedures::{Calibration, Procedures};
use crate::toml::Table;
use crate::{RegistryError, invalid, load, req_int, req_str};

const LANTERN_CALIBRATION: &str = include_str!("../../../registries/lantern_calibration.toml");
const R: &str = "lantern_calibration.toml";

/// The fewest seeds a measurement may rest on (fa-4psc: ">= 30 seeds").
pub const MIN_SEEDS: u64 = 30;

const ROW_KEYS: [&str; 15] = [
    "id",
    "evidence",
    "true_positives",
    "false_positives",
    "false_negatives",
    "precision_bps",
    "precision_lower_bps",
    "precision_upper_bps",
    "recall_bps",
    "recall_lower_bps",
    "recall_upper_bps",
    "clean_entries",
    "clean_flagged",
    "clean_rate_bps",
    "clean_rate_upper_bps",
];

/// One procedure's measurement. Counts are entries: a flagged entry is one a
/// finding cites. Over the fraud scenarios a flagged labeled entry is a true
/// positive, a flagged unlabeled one a false positive and a missed labeled
/// one a false negative; over the clean scenario every flag counts toward
/// the clean rate. Every `_bps` figure is a 95% Wilson interval in basis
/// points (0..=10000).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalibrationRow {
    pub id: String,
    pub evidence: String,
    pub true_positives: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub precision_bps: u32,
    pub precision_lower_bps: u32,
    pub precision_upper_bps: u32,
    pub recall_bps: u32,
    pub recall_lower_bps: u32,
    pub recall_upper_bps: u32,
    pub clean_entries: u64,
    pub clean_flagged: u64,
    pub clean_rate_bps: u32,
    pub clean_rate_upper_bps: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanternCalibration {
    /// Seeds `1..=seeds` of every scenario were measured.
    pub seeds: u64,
    /// The `fa-gen` volume multiplier the corpora were generated at.
    pub scale: u64,
    /// Optional work-witness artifact (`FA-ART-*`) backing this calibration table.
    pub artifact: Option<String>,
    /// Ascending by procedure id.
    pub rows: Vec<CalibrationRow>,
}

impl LanternCalibration {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_text(LANTERN_CALIBRATION, &Procedures::embedded()?)
    }

    pub fn from_text(text: &str, procedures: &Procedures) -> Result<Self, RegistryError> {
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        if let Some(key) = doc.root.keys().find(|k| {
            !matches!(
                k.as_str(),
                "schema_version" | "seeds" | "scale" | "artifact"
            )
        }) {
            return Err(invalid(R, format!("unknown top-level key `{key}`")));
        }
        let artifact = match doc.root.get("artifact") {
            None => None,
            Some(v) => Some(
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| invalid(R, "`artifact` must be a string"))?,
            ),
        };
        if let Some(key) = doc.arrays.keys().find(|k| *k != "procedure") {
            return Err(invalid(R, format!("unknown table array `[[{key}]]`")));
        }
        if !doc.tables.is_empty() {
            return Err(invalid(R, "no `[table]` is defined"));
        }
        let seeds = count(&doc.root, "seeds", "the file")?;
        if seeds < MIN_SEEDS {
            return Err(invalid(
                R,
                format!("seeds is {seeds}; a measurement rests on at least {MIN_SEEDS} seeds"),
            ));
        }
        let scale = count(&doc.root, "scale", "the file")?;
        if scale == 0 {
            return Err(invalid(R, "scale must be at least 1"));
        }
        let empty = Vec::new();
        let mut rows: Vec<CalibrationRow> = Vec::new();
        for t in doc.arrays.get("procedure").unwrap_or(&empty) {
            if let Some(key) = t.keys().find(|k| !ROW_KEYS.contains(&k.as_str())) {
                return Err(invalid(
                    R,
                    format!("unknown key `{key}` in a [[procedure]] row"),
                ));
            }
            let row = parse_row(t)?;
            if let Some(last) = rows.last()
                && last.id >= row.id
            {
                return Err(invalid(
                    R,
                    format!(
                        "rows are strictly ascending by id: `{}` follows `{}`",
                        row.id, last.id
                    ),
                ));
            }
            let Some(procedure) = procedures.get(&row.id) else {
                return Err(invalid(
                    R,
                    format!("{}: not a registered procedure", row.id),
                ));
            };
            if procedure.calibration != Calibration::Corpus {
                return Err(invalid(
                    R,
                    format!(
                        "{}: measured here, but procedures.toml does not say calibration = \"corpus\"",
                        row.id
                    ),
                ));
            }
            if procedure.evidence != row.evidence {
                return Err(invalid(
                    R,
                    format!(
                        "{}: evidence `{}` is not the procedure's `{}`",
                        row.id, row.evidence, procedure.evidence
                    ),
                ));
            }
            rows.push(row);
        }
        let measured: BTreeSet<&str> = rows.iter().map(|r| r.id.as_str()).collect();
        if let Some(missing) = procedures
            .rows
            .iter()
            .find(|p| p.calibration == Calibration::Corpus && !measured.contains(p.id.as_str()))
        {
            return Err(invalid(
                R,
                format!(
                    "{}: procedures.toml says calibration = \"corpus\", but no row measures it",
                    missing.id
                ),
            ));
        }
        Ok(Self {
            seeds,
            scale,
            artifact,
            rows,
        })
    }

    #[must_use]
    pub fn row(&self, id: &str) -> Option<&CalibrationRow> {
        self.rows.iter().find(|r| r.id == id)
    }
}

fn count(t: &Table, key: &str, what: &str) -> Result<u64, RegistryError> {
    let value = req_int(R, t, key)?;
    u64::try_from(value).map_err(|_| {
        invalid(
            R,
            format!("{what}: {key} is {value}, not a non-negative count"),
        )
    })
}

/// A 95% interval `(point, lower, upper)` in basis points, ordered.
fn interval(t: &Table, id: &str, name: &str) -> Result<(u32, u32, u32), RegistryError> {
    let bps = |key: &str| -> Result<u32, RegistryError> {
        let value = req_int(R, t, key)?;
        u32::try_from(value)
            .ok()
            .filter(|v| *v <= 10_000)
            .ok_or_else(|| invalid(R, format!("{id}: {key} is {value}, not 0..=10000 bps")))
    };
    let point = bps(&format!("{name}_bps"))?;
    let lower = bps(&format!("{name}_lower_bps"))?;
    let upper = bps(&format!("{name}_upper_bps"))?;
    if !(lower <= point && point <= upper) {
        return Err(invalid(
            R,
            format!("{id}: {name} interval {lower}..{upper} does not hold its point {point}"),
        ));
    }
    Ok((point, lower, upper))
}

fn parse_row(t: &Table) -> Result<CalibrationRow, RegistryError> {
    let id = req_str(R, t, "id")?.to_string();
    let evidence = req_str(R, t, "evidence")?.to_string();
    let true_positives = count(t, "true_positives", &id)?;
    let false_negatives = count(t, "false_negatives", &id)?;
    if true_positives + false_negatives == 0 {
        return Err(invalid(
            R,
            format!("{id}: no labeled entry was planted for it, so it has no recall to report"),
        ));
    }
    let (precision_bps, precision_lower_bps, precision_upper_bps) = interval(t, &id, "precision")?;
    let (recall_bps, recall_lower_bps, recall_upper_bps) = interval(t, &id, "recall")?;
    let clean_rate_bps = u32::try_from(req_int(R, t, "clean_rate_bps")?)
        .ok()
        .filter(|v| *v <= 10_000)
        .ok_or_else(|| invalid(R, format!("{id}: clean_rate_bps is not 0..=10000 bps")))?;
    let clean_rate_upper_bps = u32::try_from(req_int(R, t, "clean_rate_upper_bps")?)
        .ok()
        .filter(|v| *v <= 10_000 && *v >= clean_rate_bps)
        .ok_or_else(|| {
            invalid(
                R,
                format!("{id}: clean_rate_upper_bps is not clean_rate_bps..=10000"),
            )
        })?;
    let clean_entries = count(t, "clean_entries", &id)?;
    if clean_entries == 0 {
        return Err(invalid(
            R,
            format!("{id}: the clean scenario contributed no entries"),
        ));
    }
    Ok(CalibrationRow {
        false_positives: count(t, "false_positives", &id)?,
        clean_flagged: count(t, "clean_flagged", &id)?,
        id,
        evidence,
        true_positives,
        false_negatives,
        precision_bps,
        precision_lower_bps,
        precision_upper_bps,
        recall_bps,
        recall_lower_bps,
        recall_upper_bps,
        clean_entries,
        clean_rate_bps,
        clean_rate_upper_bps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "schema_version = 1\nseeds = 30\nscale = 1\n";

    fn row(id: &str, evidence: &str) -> String {
        format!(
            "[[procedure]]\nid = \"{id}\"\nevidence = \"{evidence}\"\ntrue_positives = 9\nfalse_positives = 1\nfalse_negatives = 0\nprecision_bps = 9000\nprecision_lower_bps = 5958\nprecision_upper_bps = 9821\nrecall_bps = 10000\nrecall_lower_bps = 7009\nrecall_upper_bps = 10000\nclean_entries = 600\nclean_flagged = 0\nclean_rate_bps = 0\nclean_rate_upper_bps = 63\n"
        )
    }

    /// The embedded file loads against the embedded procedures, and every
    /// `corpus` procedure is measured there.
    #[test]
    fn the_embedded_calibration_loads_and_covers_every_corpus_procedure() {
        let procedures = Procedures::embedded().unwrap();
        let calibration = LanternCalibration::embedded().unwrap();
        assert!(calibration.seeds >= MIN_SEEDS);
        for p in procedures
            .rows
            .iter()
            .filter(|p| p.calibration == Calibration::Corpus)
        {
            assert_eq!(
                calibration.row(&p.id).map(|r| r.evidence.as_str()),
                Some(p.evidence.as_str())
            );
        }
    }

    /// Planted defects: too few seeds, a row for a procedure not registered
    /// as `corpus`, an unregistered procedure, another procedure's evidence,
    /// an interval that does not hold its point, rows out of order, and a
    /// `corpus` procedure with no row.
    #[test]
    fn malformed_calibrations_are_refused() {
        // Two procedures registered as `corpus` here, whatever the embedded
        // registry currently says, so every planted case has rows to break.
        let mut procedures = Procedures::embedded().unwrap();
        for p in procedures
            .rows
            .iter_mut()
            .filter(|p| p.id == "jet.round_amounts" || p.id == "jet.weekend")
        {
            p.calibration = Calibration::Corpus;
        }
        let mut corpus: Vec<_> = procedures
            .rows
            .iter()
            .filter(|p| p.calibration == Calibration::Corpus)
            .collect();
        corpus.sort_by(|a, b| a.id.cmp(&b.id));
        let planted = procedures
            .rows
            .iter()
            .find(|p| p.calibration != Calibration::Corpus)
            .unwrap();
        let all_rows = |skip: Option<&str>| -> String {
            corpus
                .iter()
                .filter(|p| Some(p.id.as_str()) != skip)
                .map(|p| row(&p.id, &p.evidence))
                .collect()
        };
        let good = format!("{HEAD}{}", all_rows(None));
        LanternCalibration::from_text(&good, &procedures).unwrap();
        let first = corpus.first().expect("at least one corpus procedure");
        // A row for a procedure not registered as `corpus`, in id order.
        let mut ids: Vec<(&str, &str)> = corpus
            .iter()
            .map(|p| (p.id.as_str(), p.evidence.as_str()))
            .chain([(planted.id.as_str(), planted.evidence.as_str())])
            .collect();
        ids.sort_unstable();
        let with_planted = format!(
            "{HEAD}{}",
            ids.iter().map(|(id, e)| row(id, e)).collect::<String>()
        );
        let mut cases = vec![
            (
                good.replace("seeds = 30", "seeds = 29"),
                "at least 30 seeds",
            ),
            (with_planted, "does not say calibration = \"corpus\""),
            (
                // Sorts first, so the order law is not what refuses it.
                good.replace(
                    &format!("id = \"{}\"", first.id),
                    "id = \"a.not_registered\"",
                ),
                "not a registered procedure",
            ),
            (
                good.replacen(
                    &format!("evidence = \"{}\"", first.evidence),
                    "evidence = \"FA-EVID-L99\"",
                    1,
                ),
                "is not the procedure's",
            ),
            (
                good.replacen(
                    "precision_lower_bps = 5958",
                    "precision_lower_bps = 9500",
                    1,
                ),
                "does not hold its point",
            ),
            (
                format!("{HEAD}{}", all_rows(Some(first.id.as_str()))),
                "no row measures it",
            ),
        ];
        if corpus.len() > 1 {
            let mut reversed: Vec<String> =
                corpus.iter().map(|p| row(&p.id, &p.evidence)).collect();
            reversed.reverse();
            cases.push((format!("{HEAD}{}", reversed.concat()), "strictly ascending"));
        }
        for (text, needle) in cases {
            let error = LanternCalibration::from_text(&text, &procedures).unwrap_err();
            assert!(error.to_string().contains(needle), "{needle}: {error}");
        }
    }
}
