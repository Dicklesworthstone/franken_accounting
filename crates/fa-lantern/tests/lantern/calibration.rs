//! fa-4psc slice 1 (plan §11.10, G3): the precision and recall of every
//! procedure an fa-gen scenario labels, measured over seeds `1..=seeds` of
//! all seven scenarios and pinned in registries/lantern_calibration.toml.
//!
//! A finding's cited entries are its flags; a corpus's labels name the
//! entries each procedure should cite. Over the fraud scenarios a flagged
//! labeled entry is a true positive, a flagged unlabeled one a false
//! positive and a missed labeled one a false negative; over the clean
//! retailer every flag counts toward the clean rate. Intervals are
//! fa-lantern's exact 95% Wilson bounds. The registry is the measurement: on
//! any drift this test fails and prints the regenerated rows.

use super::*;
use fa_gen::{GenConfig, ScenarioKind, generate};
use fa_lantern::conformal::wilson_interval_95_bps;
use fa_registry::evidence_artifacts::{
    ArtifactWitness, CalibrationWitness, EvidenceArtifacts, ProcedureConfusionWitness,
};
use fa_registry::lantern_calibration::{CalibrationRow, LanternCalibration};
use fa_registry::procedures::Procedures;

#[derive(Default)]
struct Tally {
    true_positives: u64,
    false_positives: u64,
    false_negatives: u64,
    clean_entries: u64,
    clean_flagged: u64,
}

fn count(n: usize) -> u64 {
    u64::try_from(n).expect("a corpus count fits u64")
}

fn row(id: &str, evidence: &str, t: &Tally) -> CalibrationRow {
    let precision = wilson_interval_95_bps(t.true_positives, t.true_positives + t.false_positives);
    let recall = wilson_interval_95_bps(t.true_positives, t.true_positives + t.false_negatives);
    let clean = wilson_interval_95_bps(t.clean_flagged, t.clean_entries);
    CalibrationRow {
        id: id.to_string(),
        evidence: evidence.to_string(),
        true_positives: t.true_positives,
        false_positives: t.false_positives,
        false_negatives: t.false_negatives,
        precision_bps: precision.point_estimate_bps,
        precision_lower_bps: precision.lower_bps,
        precision_upper_bps: precision.upper_bps,
        recall_bps: recall.point_estimate_bps,
        recall_lower_bps: recall.lower_bps,
        recall_upper_bps: recall.upper_bps,
        clean_entries: t.clean_entries,
        clean_flagged: t.clean_flagged,
        clean_rate_bps: clean.point_estimate_bps,
        clean_rate_upper_bps: clean.upper_bps,
    }
}

/// The rows as lantern_calibration.toml spells them.
fn render(rows: &[CalibrationRow]) -> String {
    let mut out = String::new();
    for r in rows {
        out.push_str(&format!(
            "\n[[procedure]]\nid = \"{}\"\nevidence = \"{}\"\ntrue_positives = {}\nfalse_positives = {}\nfalse_negatives = {}\nprecision_bps = {}\nprecision_lower_bps = {}\nprecision_upper_bps = {}\nrecall_bps = {}\nrecall_lower_bps = {}\nrecall_upper_bps = {}\nclean_entries = {}\nclean_flagged = {}\nclean_rate_bps = {}\nclean_rate_upper_bps = {}\n",
            r.id,
            r.evidence,
            r.true_positives,
            r.false_positives,
            r.false_negatives,
            r.precision_bps,
            r.precision_lower_bps,
            r.precision_upper_bps,
            r.recall_bps,
            r.recall_lower_bps,
            r.recall_upper_bps,
            r.clean_entries,
            r.clean_flagged,
            r.clean_rate_bps,
            r.clean_rate_upper_bps,
        ));
    }
    out
}

#[test]
fn labeled_procedures_measure_what_the_calibration_registry_pins() {
    let procedures = Procedures::embedded().expect("procedures.toml");
    let registry = LanternCalibration::embedded().expect("lantern_calibration.toml");
    let scale = usize::try_from(registry.scale).expect("scale fits usize");
    // The procedures some scenario labels: the population this measures.
    let mut labeled = BTreeSet::new();
    for scenario in ScenarioKind::ALL {
        for label in &generate(GenConfig::new(scenario, 1).with_scale(scale)).labels {
            labeled.extend(label.procedures.iter().cloned());
        }
    }
    let built: Vec<(String, Box<dyn Procedure>)> = labeled
        .iter()
        .map(|id| {
            let procedure = fa_lantern::catalog::build(
                id,
                Params::defaults(id).expect("registered defaults"),
                fa_lantern::catalog::Inputs::default(),
            )
            .unwrap_or_else(|error| panic!("{id}: {error}"));
            (id.clone(), procedure)
        })
        .collect();
    let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
    // The corpora this measures, for FA-ART-CAL-01's witness: each one's
    // scenario, seed and scale, and the vid of every entry it posted.
    let mut corpus_manifest = b"fa:lantern-calibration-corpora:v1".to_vec();
    let mut case_count = 0u64;
    for scenario in ScenarioKind::ALL {
        for seed in 1..=registry.seeds {
            let corpus = generate(GenConfig::new(scenario, seed).with_scale(scale));
            let (book, snapshot, posted_vids) = corpus_snapshot(&corpus);
            case_count += 1;
            let name = scenario.to_string();
            corpus_manifest.extend_from_slice(&count(name.len()).to_le_bytes());
            corpus_manifest.extend_from_slice(name.as_bytes());
            corpus_manifest.extend_from_slice(&seed.to_le_bytes());
            corpus_manifest.extend_from_slice(&registry.scale.to_le_bytes());
            corpus_manifest.extend_from_slice(&count(posted_vids.len()).to_le_bytes());
            for vid in &posted_vids {
                corpus_manifest.extend_from_slice(&vid.0.to_le_bytes());
            }
            for (id, procedure) in &built {
                let run = run_over(&snapshot, &book, procedure.as_ref())
                    .unwrap_or_else(|error| panic!("{scenario}/{seed}/{id}: {error}"));
                let flagged: BTreeSet<usize> = run
                    .findings
                    .iter()
                    .flat_map(|f| f.cites.iter())
                    .filter_map(|c| match c {
                        Cite::Entry(vid) => posted_vids.iter().position(|v| v == vid),
                        _ => None,
                    })
                    .collect();
                let tally = tallies.entry(id.clone()).or_default();
                if scenario == ScenarioKind::CleanRetailer {
                    tally.clean_entries += count(corpus.entries.len());
                    tally.clean_flagged += count(flagged.len());
                } else {
                    let planted = corpus.expected_entries_for_procedure(id);
                    tally.true_positives += count(planted.intersection(&flagged).count());
                    tally.false_positives += count(flagged.difference(&planted).count());
                    tally.false_negatives += count(planted.difference(&flagged).count());
                }
            }
        }
    }
    let measured: Vec<CalibrationRow> = tallies
        .iter()
        .map(|(id, tally)| {
            let evidence = &procedures.get(id).expect("a registered procedure").evidence;
            row(id, evidence, tally)
        })
        .collect();
    for r in &measured {
        println!(
            "calibration procedure={} seeds={} tp={} fp={} fn={} precision={}bps [{}, {}] recall={}bps [{}, {}] clean={}/{} (upper {}bps)",
            r.id,
            registry.seeds,
            r.true_positives,
            r.false_positives,
            r.false_negatives,
            r.precision_bps,
            r.precision_lower_bps,
            r.precision_upper_bps,
            r.recall_bps,
            r.recall_lower_bps,
            r.recall_upper_bps,
            r.clean_flagged,
            r.clean_entries,
            r.clean_rate_upper_bps,
        );
        // Not vacuous: every labeled procedure had planted entries to find
        // and a clean population to stay quiet on.
        assert!(
            r.true_positives + r.false_negatives > 0 && r.clean_entries > 0,
            "{}",
            r.id
        );
    }
    if measured != registry.rows {
        println!(
            "----- lantern_calibration.toml rows (measured) -----{}----- end -----",
            render(&measured)
        );
        panic!(
            "registries/lantern_calibration.toml does not pin this measurement; the measured rows are printed above. Review the change, then replace the file's rows with them (and set calibration = \"corpus\" for exactly these procedures)."
        );
    }

    // FA-ART-CAL-01, the work witness the registry and the scoreboard's G3-05
    // cite (fa-vtzt), recomputed from this measurement: the SHA-256 of the
    // corpus manifest above, the corpora counted, and each procedure's
    // confusion (a flag on the clean retailer is a false positive, and its
    // unflagged entries are the true negatives). It must equal the ledger
    // row, so a manifest this measurement did not produce fails here.
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let witness = CalibrationWitness {
        corpus_manifest_sha256: hex(&fa_docket::intake::sha256(&corpus_manifest)),
        case_count,
        per_procedure_confusion: measured
            .iter()
            .map(|r| ProcedureConfusionWitness {
                procedure: r.id.clone(),
                true_positives: r.true_positives,
                false_positives: r
                    .false_positives
                    .checked_add(r.clean_flagged)
                    .expect("a count"),
                false_negatives: r.false_negatives,
                true_negatives: r
                    .clean_entries
                    .checked_sub(r.clean_flagged)
                    .expect("flags are entries"),
            })
            .collect(),
    };
    println!(
        "FA-ART-CAL-01 witness:\ncorpus_manifest_sha256 = \"{}\"\ncase_count = {}",
        witness.corpus_manifest_sha256, witness.case_count
    );
    for p in &witness.per_procedure_confusion {
        println!(
            "\n[[per_procedure_confusion]]\nprocedure = \"{}\"\ntrue_positives = {}\nfalse_positives = {}\nfalse_negatives = {}\ntrue_negatives = {}",
            p.procedure, p.true_positives, p.false_positives, p.false_negatives, p.true_negatives
        );
    }
    let ledger = EvidenceArtifacts::embedded().expect("evidence_artifacts.toml");
    let artifact_id = registry
        .artifact
        .as_deref()
        .expect("lantern_calibration.toml cites its artifact");
    let artifact = ledger.get(artifact_id).expect("the cited artifact row");
    assert_eq!(
        artifact.witness,
        ArtifactWitness::Calibration(witness),
        "{artifact_id} is not what this measurement produced"
    );
}
