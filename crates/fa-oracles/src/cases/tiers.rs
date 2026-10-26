//! The two-reader procedure tier table `data/case_procedure_tiers.toml`
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.5; bead fa-yugf.10, A4).
//!
//! A D verdict on a reconstructed book is admissible only if the
//! procedure's verdict on the target does not depend on data the record
//! does not give (§2.5). Each claimed procedure has one `[[tier]]` row that
//! two readers classified independently from code; on disagreement the row
//! takes the more conservative tier. A row is keyed by the procedure's id,
//! version and [`row_digest`], so a change to the procedure's registry row
//! invalidates it until it is read again (K-TIER).

use std::collections::BTreeMap;

use fa_registry::toml::{Document, Table, Value as TomlValue};

use super::error::{LoadError, LoadErrorKind};
use super::fields::Row;
use super::rows::row_line;
use crate::sha256;

const TABLE: &str = include_str!("../../data/case_procedure_tiers.toml");
/// The table's path, as errors name it.
pub const FILE: &str = "case_procedure_tiers.toml";

/// `registries/procedures.toml`, a declared input of this crate.
pub const PROCEDURES: &str = include_str!("../../../../registries/procedures.toml");

closed_set! {
    /// A procedure's dependence tier (§2.5), in increasing dependence: the
    /// order resolves a disagreement to the more conservative tier.
    Tier {
        L => "L",
        C => "C",
        SRel => "S-rel",
        SAcct => "S-acct",
        SParty => "S-party",
        G => "G",
        O => "O",
        P => "P",
        A => "A",
    }
}

impl Tier {
    /// Whether a D may rest on this tier without a sourced, complete
    /// comparison population (§2.5: P and A may not).
    #[must_use]
    pub const fn admissible_for_d(self) -> bool {
        !matches!(self, Self::P | Self::A)
    }
}

/// One `[[tier]]` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierRow {
    pub procedure: String,
    pub version: i128,
    pub row_digest: String,
    pub tier: Tier,
    /// The `file:line` at the pinned commit that justifies the tier.
    pub code_location: String,
    pub reader: String,
    pub reader_tier: Tier,
    pub second_reader: String,
    pub second_reader_tier: Tier,
    pub disagreement: bool,
    /// Whether the procedure reads an entry's evidence, documents or
    /// attestations: true if either reader says so.
    pub reads_evidence: bool,
    pub reader_reads_evidence: bool,
    pub second_reader_reads_evidence: bool,
    pub line: Option<usize>,
}

/// The loaded table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tiers {
    pub rows: Vec<TierRow>,
}

impl Tiers {
    /// The row for `procedure`, if any.
    #[must_use]
    pub fn get(&self, procedure: &str) -> Option<&TierRow> {
        self.rows.iter().find(|r| r.procedure == procedure)
    }

    /// Parses a copy of the table (tests pass edited copies).
    ///
    /// # Errors
    ///
    /// Every malformed row: a missing field, an unknown tier, a reader read
    /// twice, a tier or `reads_evidence` that is not the two readings'
    /// conservative choice, a `disagreement` that misstates them, a
    /// procedure listed twice.
    pub fn from_text(text: &str) -> Result<Self, Vec<LoadError>> {
        let doc = fa_registry::toml::parse(text).map_err(|e| {
            vec![LoadError {
                file: FILE.into(),
                line: Some(e.line),
                kind: LoadErrorKind::Toml,
                row: None,
                detail: e.message,
            }]
        })?;
        let mut errs = Vec::new();
        let mut rows = Vec::new();
        for (i, table) in doc
            .arrays
            .get("tier")
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .enumerate()
        {
            let id = table
                .get("procedure")
                .and_then(TomlValue::as_str)
                .map(str::to_string);
            let mut r = Row::new(FILE, row_line(text, "tier", i), table).with_id(id);
            let procedure = r.req_str("procedure", &mut errs);
            let version = r.req_int("version", &mut errs);
            let row_digest = r.req_str("row_digest", &mut errs);
            let tier = r.req_str("tier", &mut errs);
            let code_location = r.req_str("code_location", &mut errs);
            let reader = r.req_str("reader", &mut errs);
            let reader_tier = r.req_str("reader_tier", &mut errs);
            let second_reader = r.req_str("second_reader", &mut errs);
            let second_reader_tier = r.req_str("second_reader_tier", &mut errs);
            let disagreement = r.req_bool("disagreement", &mut errs);
            let reads_evidence = r.req_bool("reads_evidence", &mut errs);
            let reader_reads_evidence = r.req_bool("reader_reads_evidence", &mut errs);
            let second_reader_reads_evidence =
                r.req_bool("second_reader_reads_evidence", &mut errs);
            r.finish(&[], "", &mut errs);
            let line = r.line();
            let fail = |kind: LoadErrorKind, detail: String| LoadError {
                file: FILE.into(),
                line,
                kind,
                row: Some(procedure.clone()),
                detail,
            };
            let parse = |field: &str, s: &str, errs: &mut Vec<LoadError>| {
                Tier::parse(s).or_else(|| {
                    errs.push(fail(
                        LoadErrorKind::UnknownValue,
                        format!(
                            "`{field} = \"{s}\"` is one of L, C, S-rel, S-acct, S-party, G, O, P, A"
                        ),
                    ));
                    None
                })
            };
            let (Some(tier), Some(t1), Some(t2)) = (
                parse("tier", &tier, &mut errs),
                parse("reader_tier", &reader_tier, &mut errs),
                parse("second_reader_tier", &second_reader_tier, &mut errs),
            ) else {
                continue;
            };
            if reader.trim().is_empty() || second_reader.trim().is_empty() {
                errs.push(fail(
                    LoadErrorKind::MissingField,
                    "a tier row records two readers (reader and second_reader)".into(),
                ));
            } else if reader == second_reader {
                errs.push(fail(
                    LoadErrorKind::UnknownValue,
                    format!("`{reader}` is both readers; two readers classify independently"),
                ));
            }
            if tier != t1.max(t2) {
                errs.push(fail(
                    LoadErrorKind::UnknownValue,
                    format!(
                        "`tier = \"{}\"` is not the conservative choice of {} and {} ({})",
                        tier.as_str(),
                        t1.as_str(),
                        t2.as_str(),
                        t1.max(t2).as_str()
                    ),
                ));
            }
            if disagreement != (t1 != t2) {
                errs.push(fail(
                    LoadErrorKind::UnknownValue,
                    format!(
                        "`disagreement = {disagreement}`, but the readers read {} and {}",
                        t1.as_str(),
                        t2.as_str()
                    ),
                ));
            }
            if reads_evidence != (reader_reads_evidence || second_reader_reads_evidence) {
                errs.push(fail(
                    LoadErrorKind::UnknownValue,
                    "`reads_evidence` is true when either reader says so".into(),
                ));
            }
            if rows.iter().any(|x: &TierRow| x.procedure == procedure) {
                errs.push(fail(
                    LoadErrorKind::DuplicateId,
                    format!("`{procedure}` has a second tier row"),
                ));
            }
            rows.push(TierRow {
                procedure,
                version,
                row_digest,
                tier,
                code_location,
                reader,
                reader_tier: t1,
                second_reader,
                second_reader_tier: t2,
                disagreement,
                reads_evidence,
                reader_reads_evidence,
                second_reader_reads_evidence,
                line,
            });
        }
        if errs.is_empty() {
            Ok(Self { rows })
        } else {
            super::error::sort(&mut errs);
            Err(errs)
        }
    }
}

/// The committed table.
///
/// # Errors
///
/// Every malformed row.
pub fn tiers() -> Result<Tiers, Vec<LoadError>> {
    Tiers::from_text(TABLE)
}

/// A procedure's registry row: its `version` and the SHA-256 of the
/// canonical bytes (`Document::canonical_bytes`) of a document holding its
/// `[[procedure]]` row and, in file order, its `[[parameter]]` and `[[input]]`
/// rows. Comments and whitespace do not move the digest; any semantic edit
/// (version, summary, calibration, a parameter default, an input) does.
///
/// # Errors
///
/// When the text does not parse or names no such procedure.
pub fn registry_row(procedures_toml: &str, id: &str) -> Result<(i128, String), String> {
    let doc = fa_registry::toml::parse(procedures_toml)
        .map_err(|e| format!("registries/procedures.toml:{}: {}", e.line, e.message))?;
    let rows = |name: &str, key: &str| -> Vec<Table> {
        doc.arrays
            .get(name)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter(|t| t.get(key).and_then(TomlValue::as_str) == Some(id))
            .cloned()
            .collect()
    };
    let procedure = rows("procedure", "id");
    let [row] = procedure.as_slice() else {
        return Err(format!(
            "registries/procedures.toml has {} [[procedure]] row(s) with id `{id}`",
            procedure.len()
        ));
    };
    let version = row
        .get("version")
        .and_then(TomlValue::as_int)
        .ok_or_else(|| format!("procedure `{id}` has no integer version"))?;
    let mut arrays = BTreeMap::new();
    arrays.insert("procedure".to_string(), procedure.clone());
    arrays.insert("parameter".to_string(), rows("parameter", "procedure"));
    arrays.insert("input".to_string(), rows("input", "procedure"));
    let part = Document {
        root: Table::new(),
        tables: BTreeMap::new(),
        arrays,
    };
    Ok((
        version,
        sha256::hex(&sha256::digest(&part.canonical_bytes())),
    ))
}

/// The row digest of procedure `id` (see [`registry_row`]).
///
/// # Errors
///
/// When the text does not parse or names no such procedure.
pub fn row_digest(procedures_toml: &str, id: &str) -> Result<String, String> {
    registry_row(procedures_toml, id).map(|(_, d)| d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 19 procedures the cases claim (§15 A4).
    const SEEDED: [&str; 19] = [
        "expense.capitalization",
        "jet.round_amounts",
        "jet.self_approved",
        "jet.period_end_timing",
        "jet.post_closing",
        "jet.weekend",
        "jet.self_sourced_evidence",
        "cutoff.period_boundary",
        "events.subsequent",
        "ponzi.net_investment",
        "recon.assertion_drift",
        "damages.attested_baseline",
        "duplicates.same_same_same",
        "duplicates.same_same_different",
        "numbers.relative_size_factor",
        "numbers.round_amount_density",
        "benford.first_digit",
        "graph.related_party_exposure",
        "graph.party_circular_flows",
    ];

    #[test]
    fn every_seeded_row_matches_procedures_toml() {
        let t = tiers().expect("the committed tier table loads");
        assert_eq!(t.rows.len(), SEEDED.len());
        for id in SEEDED {
            let row = t.get(id).expect("a seeded row");
            let (version, digest) = registry_row(PROCEDURES, id).expect("a registry row");
            assert_eq!(row.version, version, "{id}");
            assert_eq!(row.row_digest, digest, "{id}");
            assert_ne!(row.reader, row.second_reader, "{id}");
            assert!(row.code_location.starts_with("crates/"), "{id}");
            println!(
                "TIER {id}@{} {} readers={}:{},{}:{} reads_evidence={}",
                row.version,
                row.tier.as_str(),
                row.reader,
                row.reader_tier.as_str(),
                row.second_reader,
                row.second_reader_tier.as_str(),
                row.reads_evidence
            );
        }
    }

    #[test]
    fn comment_only_edit_keeps_every_row_valid() {
        let edited = format!(
            "# an added comment line\n{}",
            PROCEDURES.replace("\nversion = ", "\nversion   =   ")
        );
        assert_ne!(edited, PROCEDURES);
        for id in SEEDED {
            assert_eq!(row_digest(&edited, id), row_digest(PROCEDURES, id), "{id}");
        }
    }

    #[test]
    fn parameter_default_change_invalidates_the_row() {
        let old = "procedure = \"jet.round_amounts\"\nname = \"round_power\"\ndefault = 3\n";
        assert_eq!(PROCEDURES.matches(old).count(), 1);
        let edited = PROCEDURES.replace(
            old,
            "procedure = \"jet.round_amounts\"\nname = \"round_power\"\ndefault = 4\n",
        );
        assert_ne!(
            row_digest(&edited, "jet.round_amounts"),
            row_digest(PROCEDURES, "jet.round_amounts")
        );
        assert_eq!(
            row_digest(&edited, "jet.weekend"),
            row_digest(PROCEDURES, "jet.weekend"),
            "another procedure's row is untouched"
        );
    }

    #[test]
    fn input_row_change_invalidates_the_row() {
        let old = "procedure = \"trace.libr\"\nname = \"account\"\nkind = \"account\"\n";
        assert_eq!(PROCEDURES.matches(old).count(), 1);
        let edited = PROCEDURES.replace(
            old,
            "procedure = \"trace.libr\"\nname = \"account\"\nkind = \"entry\"\n",
        );
        assert_ne!(
            row_digest(&edited, "trace.libr"),
            row_digest(PROCEDURES, "trace.libr")
        );
    }

    /// The committed table with `old`, which must occur exactly once inside
    /// `procedure`'s row, replaced by `new`.
    fn row_edit(procedure: &str, old: &str, new: &str) -> String {
        let start = TABLE
            .find(&format!("procedure = \"{procedure}\"\n"))
            .expect("the row");
        let end = TABLE[start..]
            .find("\n[[tier]]\n")
            .map_or(TABLE.len(), |n| start + n);
        assert_eq!(
            TABLE[start..end].matches(old).count(),
            1,
            "`{old}` in {procedure}"
        );
        format!(
            "{}{}{}",
            &TABLE[..start],
            TABLE[start..end].replacen(old, new, 1),
            &TABLE[end..]
        )
    }

    #[track_caller]
    fn refused(text: &str, kind: LoadErrorKind, part: &str) {
        let errs = Tiers::from_text(text).expect_err("the edited table is refused");
        assert!(
            errs.iter().any(|e| e.kind == kind
                && e.row.as_deref() == Some("jet.weekend")
                && e.detail.contains(part)),
            "{errs:#?}"
        );
    }

    #[test]
    fn single_reader_row_is_refused() {
        refused(
            &row_edit(
                "jet.weekend",
                "second_reader = \"MaroonCat\"",
                "second_reader = \"\"",
            ),
            LoadErrorKind::MissingField,
            "a tier row records two readers",
        );
    }

    #[test]
    fn same_reader_twice_is_refused() {
        refused(
            &row_edit(
                "jet.weekend",
                "second_reader = \"MaroonCat\"",
                "second_reader = \"StormyLion\"",
            ),
            LoadErrorKind::UnknownValue,
            "`StormyLion` is both readers",
        );
    }

    #[test]
    fn disagreement_not_resolved_to_the_conservative_tier_is_refused() {
        // Readers L and P, the row's tier left at L.
        let text = row_edit(
            "jet.weekend",
            "second_reader_tier = \"L\"\ndisagreement = false",
            "second_reader_tier = \"P\"\ndisagreement = true",
        );
        refused(
            &text,
            LoadErrorKind::UnknownValue,
            "`tier = \"L\"` is not the conservative choice of L and P (P)",
        );
    }

    #[test]
    fn tier_order_is_the_plan_table_order() {
        let order: Vec<&str> = Tier::ALL.iter().map(|t| t.as_str()).collect();
        assert_eq!(
            order,
            ["L", "C", "S-rel", "S-acct", "S-party", "G", "O", "P", "A"]
        );
        assert!(Tier::L < Tier::P && Tier::SParty < Tier::G);
        assert!(!Tier::P.admissible_for_d() && Tier::G.admissible_for_d());
    }
}
