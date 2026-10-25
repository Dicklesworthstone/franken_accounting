//! `registries/evidence_artifacts.toml` and the `evidence/` content-addressed
//! work-witness store (bead `fa-vtzt`).
//!
//! Every activated SLO, live formal proof or model lane, external-oracle claim,
//! bounded-model invariant checker, or empirical calibration claim must cite a
//! registered `FA-ART-*` artifact row whose witness manifest on disk hashes to
//! `manifest_blake3` and carries work-witnesses that only the real computation
//! can produce.

use std::collections::BTreeSet;
use std::path::Path;

use crate::toml::{Document, Table, Value};
use crate::{RegistryError, invalid, load, req_int, req_str};

const EVIDENCE_ARTIFACTS_TOML: &str = include_str!("../../../registries/evidence_artifacts.toml");
const R: &str = "evidence_artifacts.toml";

/// The six work-witness artifact families recognized by the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArtifactKind {
    Benchmark,
    ExternalOracle,
    Lean,
    Tlc,
    LabCampaign,
    Calibration,
}

impl ArtifactKind {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "benchmark" => Some(Self::Benchmark),
            "external-oracle" => Some(Self::ExternalOracle),
            "lean" => Some(Self::Lean),
            "tlc" => Some(Self::Tlc),
            "lab-campaign" => Some(Self::LabCampaign),
            "calibration" => Some(Self::Calibration),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Benchmark => "benchmark",
            Self::ExternalOracle => "external-oracle",
            Self::Lean => "lean",
            Self::Tlc => "tlc",
            Self::LabCampaign => "lab-campaign",
            Self::Calibration => "calibration",
        }
    }
}

/// Scale witness for a benchmark artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScaleWitness {
    pub leg_count: u64,
    pub entry_count: u64,
    pub bundle_bytes: u64,
}

impl ScaleWitness {
    pub fn is_populated(&self) -> bool {
        self.leg_count > 0 || self.entry_count > 0 || self.bundle_bytes > 0
    }
}

/// Work-witness fields for `kind = "benchmark"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkWitness {
    pub scale_witness: ScaleWitness,
    pub iterations: u64,
    pub warmup: u64,
    pub quantile_samples_ns: Vec<u64>,
    pub flamegraph_svg_sha256: String,
    pub host_cpu_model: String,
    pub host_kernel: String,
    pub runner: String,
}

/// Work-witness fields for `kind = "external-oracle"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalOracleWitness {
    pub tool_binary_path: String,
    pub tool_version_stdout: String,
    pub tool_binary_sha256: String,
    pub input_fixture_sha256: String,
    pub tool_stdout_sha256: String,
    pub tool_exit_code: i64,
    pub compared_cells: u64,
}

/// Per-theorem witness row inside a Lean build artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeanTheoremWitness {
    pub name: String,
    pub module: String,
    pub sorry_count: u64,
    pub axioms_used: Vec<String>,
}

/// Work-witness fields for `kind = "lean"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeanWitness {
    pub lean_version: String,
    pub lake_manifest_sha256: String,
    pub olean_tar_sha256: String,
    pub theorem_inventory: Vec<LeanTheoremWitness>,
}

/// Work-witness fields for `kind = "tlc"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlcWitness {
    pub tlc_version: String,
    pub spec_sha256: String,
    pub cfg_sha256: String,
    pub distinct_states: u64,
    pub states_generated: u64,
    pub depth: u64,
    pub result: String,
}

/// Work-witness fields for `kind = "lab-campaign"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabCampaignWitness {
    pub seed_manifest_sha256: String,
    pub schedule_count: u64,
    pub explored_interleavings: u64,
    pub certificate_hashes_blake3: Vec<String>,
}

/// Confusion matrix witness for one calibrated procedure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureConfusionWitness {
    pub procedure: String,
    pub true_positives: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub true_negatives: u64,
}

/// Work-witness fields for `kind = "calibration"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalibrationWitness {
    pub corpus_manifest_sha256: String,
    pub case_count: u64,
    pub per_procedure_confusion: Vec<ProcedureConfusionWitness>,
}

/// Kind-specific work-witness payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactWitness {
    Benchmark(BenchmarkWitness),
    ExternalOracle(ExternalOracleWitness),
    Lean(LeanWitness),
    Tlc(TlcWitness),
    LabCampaign(LabCampaignWitness),
    Calibration(CalibrationWitness),
}

impl ArtifactWitness {
    pub fn kind(&self) -> ArtifactKind {
        match self {
            Self::Benchmark(_) => ArtifactKind::Benchmark,
            Self::ExternalOracle(_) => ArtifactKind::ExternalOracle,
            Self::Lean(_) => ArtifactKind::Lean,
            Self::Tlc(_) => ArtifactKind::Tlc,
            Self::LabCampaign(_) => ArtifactKind::LabCampaign,
            Self::Calibration(_) => ArtifactKind::Calibration,
        }
    }

    /// Number of kind-specific witness fields checked for structured logging.
    pub const fn witness_fields_checked(&self) -> usize {
        match self {
            Self::Benchmark(_) => 8,
            Self::ExternalOracle(_) => 7,
            Self::Lean(_) => 4,
            Self::Tlc(_) => 7,
            Self::LabCampaign(_) => 4,
            Self::Calibration(_) => 3,
        }
    }
}

/// One row in `registries/evidence_artifacts.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceArtifactRow {
    pub id: String,
    pub kind: ArtifactKind,
    pub manifest_path: String,
    pub manifest_blake3: String,
    pub produced_by: String,
    pub git_commit: String,
    pub summary: String,
    pub witness: ArtifactWitness,
}

/// Structured verification record emitted per evidence artifact row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactVerificationLog {
    pub artifact_id: String,
    pub kind: ArtifactKind,
    pub witness_fields_checked: usize,
    pub verdict: &'static str,
}

/// Parsed `registries/evidence_artifacts.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceArtifacts {
    pub schema_version: u32,
    pub artifacts: Vec<EvidenceArtifactRow>,
}

impl EvidenceArtifacts {
    /// Load and validate the embedded `registries/evidence_artifacts.toml`.
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_text(EVIDENCE_ARTIFACTS_TOML)
    }

    /// Parse and validate `evidence_artifacts.toml` text.
    pub fn from_text(text: &str) -> Result<Self, RegistryError> {
        let doc = load(R, text)?;
        let schema_version = u32::try_from(req_int(R, &doc.root, "schema_version")?)
            .map_err(|_| invalid(R, "schema_version must fit u32"))?;
        if schema_version != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        if let Some(key) = doc.root.keys().find(|k| k.as_str() != "schema_version") {
            return Err(invalid(R, format!("unknown top-level key `{key}`")));
        }
        if !doc.tables.is_empty() {
            return Err(invalid(R, "unexpected `[table]` section"));
        }
        if let Some(key) = doc.arrays.keys().find(|k| k.as_str() != "artifact") {
            return Err(invalid(R, format!("unknown array-of-tables `[[{key}]]`")));
        }

        let mut seen_ids = BTreeSet::new();
        let mut seen_paths = BTreeSet::new();
        let mut artifacts = Vec::new();
        let empty = Vec::new();
        for table in doc.arrays.get("artifact").unwrap_or(&empty) {
            let row = parse_artifact_row(R, table, None)?;
            if !seen_ids.insert(row.id.clone()) {
                return Err(invalid(R, format!("duplicate artifact id `{}`", row.id)));
            }
            if !seen_paths.insert(row.manifest_path.clone()) {
                return Err(invalid(
                    R,
                    format!("duplicate artifact manifest_path `{}`", row.manifest_path),
                ));
            }
            artifacts.push(row);
        }
        Ok(Self {
            schema_version,
            artifacts,
        })
    }

    /// Look up an artifact row by its `FA-ART-*` identifier.
    pub fn get(&self, id: &str) -> Option<&EvidenceArtifactRow> {
        self.artifacts.iter().find(|row| row.id == id)
    }

    /// Verify every artifact's manifest on disk under `repo_root` against its
    /// pinned BLAKE3 digest and re-validate the manifest's work-witness fields.
    pub fn verify_store(
        &self,
        repo_root: &Path,
    ) -> Result<Vec<ArtifactVerificationLog>, RegistryError> {
        let mut logs = Vec::with_capacity(self.artifacts.len());
        for row in &self.artifacts {
            let full_path = repo_root.join(&row.manifest_path);
            let bytes = std::fs::read(&full_path).map_err(|e| {
                invalid(
                    R,
                    format!(
                        "{}: cannot read manifest `{}`: {e}",
                        row.id,
                        full_path.display()
                    ),
                )
            })?;
            let actual_blake3 = blake3_hex(&bytes);
            if actual_blake3 != row.manifest_blake3 {
                return Err(invalid(
                    R,
                    format!(
                        "{}: manifest `{}` blake3 mismatch (expected {}, got {})",
                        row.id, row.manifest_path, row.manifest_blake3, actual_blake3
                    ),
                ));
            }
            let manifest_text = std::str::from_utf8(&bytes).map_err(|e| {
                invalid(
                    R,
                    format!(
                        "{}: manifest `{}` is not valid UTF-8: {e}",
                        row.id, row.manifest_path
                    ),
                )
            })?;
            verify_manifest_text(manifest_text, row)?;
            logs.push(ArtifactVerificationLog {
                artifact_id: row.id.clone(),
                kind: row.kind,
                witness_fields_checked: row.witness.witness_fields_checked(),
                verdict: "PASS",
            });
        }
        Ok(logs)
    }
}

/// Parse and validate a stand-alone witness manifest file (`evidence/<kind>/<id>.toml`)
/// and check that it agrees with its ledger row in `evidence_artifacts.toml`.
pub fn verify_manifest_text(
    manifest_text: &str,
    ledger_row: &EvidenceArtifactRow,
) -> Result<ArtifactWitness, RegistryError> {
    let doc = load(R, manifest_text)?;
    if req_int(R, &doc.root, "schema_version")? != 1 {
        return Err(invalid(R, "manifest schema_version must be 1"));
    }
    let artifact_id = req_str(R, &doc.root, "artifact_id")?;
    if artifact_id != ledger_row.id {
        return Err(invalid(
            R,
            format!(
                "manifest artifact_id `{artifact_id}` does not match ledger id `{}`",
                ledger_row.id
            ),
        ));
    }
    let kind_raw = req_str(R, &doc.root, "kind")?;
    let kind = ArtifactKind::parse(kind_raw)
        .ok_or_else(|| invalid(R, format!("unknown artifact kind `{kind_raw}` in manifest")))?;
    if kind != ledger_row.kind {
        return Err(invalid(
            R,
            format!(
                "manifest kind `{}` does not match ledger kind `{}`",
                kind.as_str(),
                ledger_row.kind.as_str()
            ),
        ));
    }
    let produced_by = req_str(R, &doc.root, "produced_by")?;
    if produced_by.trim().is_empty() {
        return Err(invalid(R, "manifest produced_by must not be empty"));
    }
    let git_commit = req_str(R, &doc.root, "git_commit")?;
    check_git_commit(R, artifact_id, git_commit)?;

    let witness = parse_witness(R, artifact_id, kind, &doc.root, Some(&doc))?;
    if witness != ledger_row.witness {
        return Err(invalid(
            R,
            format!(
                "{artifact_id}: manifest work-witness fields diverge from evidence_artifacts.toml row"
            ),
        ));
    }
    Ok(witness)
}

/// Cross-check every claim across `slo.toml`, `invariants.toml`, `proof_lanes.toml`,
/// `formats.toml`, `evidence.toml`, `procedures.toml`, and `lantern_calibration.toml`
/// against the work-witness ledger (`fa-vtzt`).
#[allow(clippy::too_many_arguments)]
pub fn verify_claim_artifact_cross_refs(
    artifacts: &EvidenceArtifacts,
    slo: &crate::g0::SloRegistry,
    invariants: &crate::invariants::Invariants,
    proof_lanes: &crate::g0::ProofLanes,
    formats: &crate::g0::Formats,
    evidence: &crate::g0::EvidenceRegistry,
    procedures: &crate::procedures::Procedures,
    lantern_calibration: &crate::lantern_calibration::LanternCalibration,
) -> Result<(), RegistryError> {
    // 1. slo.toml: every row with `activated = true` must cite a `benchmark` artifact
    // whose scale_witness matches the manifest's declared scale.
    for row in &slo.rows {
        if !row.activated {
            continue;
        }
        let Some(art_id) = row.artifact.as_deref() else {
            return Err(invalid(
                "slo.toml",
                format!(
                    "activated SLO `{}` (`{}`) must cite a benchmark `artifact = \"FA-ART-...\"`",
                    row.id, row.name
                ),
            ));
        };
        let Some(art) = artifacts.get(art_id) else {
            return Err(invalid(
                "slo.toml",
                format!(
                    "activated SLO `{}` (`{}`) cites unknown artifact `{art_id}`",
                    row.id, row.name
                ),
            ));
        };
        let ArtifactWitness::Benchmark(bench) = &art.witness else {
            return Err(invalid(
                "slo.toml",
                format!(
                    "activated SLO `{}` (`{}`) cites artifact `{art_id}` of kind `{}`, expected `benchmark`",
                    row.id,
                    row.name,
                    art.kind.as_str()
                ),
            ));
        };
        if let Some(req_legs) = row.required_leg_count
            && bench.scale_witness.leg_count < req_legs
        {
            return Err(invalid(
                "slo.toml",
                format!(
                    "activated SLO `{}` requires scale_witness.leg_count >= {req_legs}, artifact `{art_id}` has {}",
                    row.id, bench.scale_witness.leg_count
                ),
            ));
        }
        if let Some(req_entries) = row.required_entry_count
            && bench.scale_witness.entry_count < req_entries
        {
            return Err(invalid(
                "slo.toml",
                format!(
                    "activated SLO `{}` requires scale_witness.entry_count >= {req_entries}, artifact `{art_id}` has {}",
                    row.id, bench.scale_witness.entry_count
                ),
            ));
        }
        if let Some(req_bytes) = row.required_bundle_bytes
            && bench.scale_witness.bundle_bytes < req_bytes
        {
            return Err(invalid(
                "slo.toml",
                format!(
                    "activated SLO `{}` requires scale_witness.bundle_bytes >= {req_bytes}, artifact `{art_id}` has {}",
                    row.id, bench.scale_witness.bundle_bytes
                ),
            ));
        }
        if row.name == "trial_balance_100k"
            && bench.scale_witness.entry_count < 100_000
            && bench.scale_witness.leg_count < 100_000
        {
            return Err(invalid(
                "slo.toml",
                format!(
                    "activated SLO `{}` (`trial_balance_100k`) requires scale_witness >= 100,000 entries/legs, artifact `{art_id}` has entries={} legs={}",
                    row.id, bench.scale_witness.entry_count, bench.scale_witness.leg_count
                ),
            ));
        }
        if row.name == "bundle_verify_50mb" && bench.scale_witness.bundle_bytes < 50_000_000 {
            return Err(invalid(
                "slo.toml",
                format!(
                    "activated SLO `{}` (`bundle_verify_50mb`) requires scale_witness.bundle_bytes >= 50,000,000, artifact `{art_id}` has {}",
                    row.id, bench.scale_witness.bundle_bytes
                ),
            ));
        }
    }

    // 2. invariants.toml: live `proof` clauses must cite a `lean` artifact covering
    // their theorems; live `bounded_model` / `model` clauses must cite a `tlc` or
    // `lab-campaign` artifact.
    for clause in &invariants.clauses {
        let crate::invariants::Status::Live {
            checker_strength, ..
        } = &clause.status
        else {
            continue;
        };
        let full_id = clause.full_id();
        if clause.evidence_class == "proof" || checker_strength == "proof" {
            let Some(art_id) = clause.artifact.as_deref() else {
                return Err(invalid(
                    "invariants.toml",
                    format!(
                        "live proof clause `{full_id}` must cite a Lean build `artifact = \"FA-ART-...\"`"
                    ),
                ));
            };
            let Some(art) = artifacts.get(art_id) else {
                return Err(invalid(
                    "invariants.toml",
                    format!("live proof clause `{full_id}` cites unknown artifact `{art_id}`"),
                ));
            };
            let ArtifactWitness::Lean(lean) = &art.witness else {
                return Err(invalid(
                    "invariants.toml",
                    format!(
                        "live proof clause `{full_id}` cites artifact `{art_id}` of kind `{}`, expected `lean`",
                        art.kind.as_str()
                    ),
                ));
            };
            if clause.theorems.is_empty() {
                return Err(invalid(
                    "invariants.toml",
                    format!(
                        "live proof clause `{full_id}` must declare non-empty `theorems = [...]` covered by `{art_id}`"
                    ),
                ));
            }
            for thm in &clause.theorems {
                if !lean.theorem_inventory.iter().any(|t| &t.name == thm) {
                    return Err(invalid(
                        "invariants.toml",
                        format!(
                            "live proof clause `{full_id}` theorem `{thm}` is missing from Lean artifact `{art_id}` theorem_inventory"
                        ),
                    ));
                }
            }
        } else if clause.evidence_class == "bounded_model" || checker_strength == "model" {
            let Some(art_id) = clause.artifact.as_deref() else {
                return Err(invalid(
                    "invariants.toml",
                    format!(
                        "live model clause `{full_id}` must cite a `tlc` or `lab-campaign` `artifact = \"FA-ART-...\"`"
                    ),
                ));
            };
            let Some(art) = artifacts.get(art_id) else {
                return Err(invalid(
                    "invariants.toml",
                    format!("live model clause `{full_id}` cites unknown artifact `{art_id}`"),
                ));
            };
            if !matches!(
                art.witness,
                ArtifactWitness::Tlc(_) | ArtifactWitness::LabCampaign(_)
            ) {
                return Err(invalid(
                    "invariants.toml",
                    format!(
                        "live model clause `{full_id}` cites artifact `{art_id}` of kind `{}`, expected `tlc` or `lab-campaign`",
                        art.kind.as_str()
                    ),
                ));
            }
        }
    }

    // 3. proof_lanes.toml: live `lean4` lanes must cite a `lean` artifact covering
    // their theorems; live `tlaplus` lanes must cite a `tlc` artifact.
    for lane in &proof_lanes.lanes {
        if lane.status == "dormant" {
            continue;
        }
        let Some(art_id) = lane.artifact.as_deref() else {
            return Err(invalid(
                "proof_lanes.toml",
                format!(
                    "live lane `{}` (`{}`) must cite `artifact = \"FA-ART-...\"`",
                    lane.id, lane.engine
                ),
            ));
        };
        let Some(art) = artifacts.get(art_id) else {
            return Err(invalid(
                "proof_lanes.toml",
                format!("live lane `{}` cites unknown artifact `{art_id}`", lane.id),
            ));
        };
        if lane.engine == "lean4" || lane.claim_class == "proof" {
            let ArtifactWitness::Lean(lean) = &art.witness else {
                return Err(invalid(
                    "proof_lanes.toml",
                    format!(
                        "live Lean lane `{}` cites artifact `{art_id}` of kind `{}`, expected `lean`",
                        lane.id,
                        art.kind.as_str()
                    ),
                ));
            };
            if lane.theorems.is_empty() {
                return Err(invalid(
                    "proof_lanes.toml",
                    format!(
                        "live Lean lane `{}` must declare non-empty `theorems = [...]`",
                        lane.id
                    ),
                ));
            }
            for thm in &lane.theorems {
                if !lean.theorem_inventory.iter().any(|t| &t.name == thm) {
                    return Err(invalid(
                        "proof_lanes.toml",
                        format!(
                            "live Lean lane `{}` theorem `{thm}` is missing from artifact `{art_id}` theorem_inventory",
                            lane.id
                        ),
                    ));
                }
            }
        } else if (lane.engine == "tlaplus" || lane.claim_class == "bounded_model")
            && !matches!(art.witness, ArtifactWitness::Tlc(_))
        {
            return Err(invalid(
                "proof_lanes.toml",
                format!(
                    "live TLA+ lane `{}` cites artifact `{art_id}` of kind `{}`, expected `tlc`",
                    lane.id,
                    art.kind.as_str()
                ),
            ));
        }
    }

    // 4. formats.toml: any row with `oracle_tool != "none"` and `oracle_status != "unrun"`
    // must cite an `external-oracle` artifact.
    for row in &formats.rows {
        if row.oracle_tool != "none" && row.oracle_status != "unrun" {
            let Some(art_id) = row.artifact.as_deref() else {
                return Err(invalid(
                    "formats.toml",
                    format!(
                        "format `{}` claims oracle_tool = `{}` with oracle_status = `{}` without citing an external-oracle `artifact = \"FA-ART-...\"`",
                        row.name, row.oracle_tool, row.oracle_status
                    ),
                ));
            };
            let Some(art) = artifacts.get(art_id) else {
                return Err(invalid(
                    "formats.toml",
                    format!(
                        "format `{}` cites unknown external-oracle artifact `{art_id}`",
                        row.name
                    ),
                ));
            };
            if !matches!(art.witness, ArtifactWitness::ExternalOracle(_)) {
                return Err(invalid(
                    "formats.toml",
                    format!(
                        "format `{}` cites artifact `{art_id}` of kind `{}`, expected `external-oracle`",
                        row.name,
                        art.kind.as_str()
                    ),
                ));
            }
        }
    }

    // 5. evidence.toml: any live `calibration` gate must cite a `calibration` artifact.
    for gate in &evidence.gates {
        if gate.status != "dormant" && gate.kind == "calibration" {
            let Some(art_id) = gate.artifact.as_deref() else {
                return Err(invalid(
                    "evidence.toml",
                    format!(
                        "live calibration gate `{}` must cite a calibration `artifact = \"FA-ART-...\"`",
                        gate.id
                    ),
                ));
            };
            let Some(art) = artifacts.get(art_id) else {
                return Err(invalid(
                    "evidence.toml",
                    format!(
                        "live calibration gate `{}` cites unknown artifact `{art_id}`",
                        gate.id
                    ),
                ));
            };
            if !matches!(art.witness, ArtifactWitness::Calibration(_)) {
                return Err(invalid(
                    "evidence.toml",
                    format!(
                        "live calibration gate `{}` cites artifact `{art_id}` of kind `{}`, expected `calibration`",
                        gate.id,
                        art.kind.as_str()
                    ),
                ));
            }
        }
    }

    // 6. procedures.toml and lantern_calibration.toml: every procedure with
    // `calibration = "corpus" | "planted"` must cite a `calibration` artifact
    // containing its confusion counts (`TP + FN >= 1`).
    for proc in &procedures.rows {
        if matches!(
            proc.calibration,
            crate::procedures::Calibration::Corpus | crate::procedures::Calibration::Planted
        ) {
            let Some(art_id) = proc.artifact.as_deref() else {
                return Err(invalid(
                    "procedures.toml",
                    format!(
                        "procedure `{}` has calibration = `{:?}` but cites no calibration `artifact = \"FA-ART-...\"`",
                        proc.id, proc.calibration
                    ),
                ));
            };
            let Some(art) = artifacts.get(art_id) else {
                return Err(invalid(
                    "procedures.toml",
                    format!(
                        "procedure `{}` cites unknown calibration artifact `{art_id}`",
                        proc.id
                    ),
                ));
            };
            let ArtifactWitness::Calibration(cal) = &art.witness else {
                return Err(invalid(
                    "procedures.toml",
                    format!(
                        "procedure `{}` cites artifact `{art_id}` of kind `{}`, expected `calibration`",
                        proc.id,
                        art.kind.as_str()
                    ),
                ));
            };
            if !cal
                .per_procedure_confusion
                .iter()
                .any(|c| c.procedure == proc.id && c.true_positives + c.false_negatives >= 1)
            {
                return Err(invalid(
                    "procedures.toml",
                    format!(
                        "procedure `{}` is missing confusion counts (TP + FN >= 1) in calibration artifact `{art_id}`",
                        proc.id
                    ),
                ));
            }
        }
    }

    if !lantern_calibration.rows.is_empty() {
        let Some(art_id) = lantern_calibration.artifact.as_deref() else {
            return Err(invalid(
                "lantern_calibration.toml",
                "lantern_calibration.toml must cite a calibration `artifact = \"FA-ART-...\"`",
            ));
        };
        let Some(art) = artifacts.get(art_id) else {
            return Err(invalid(
                "lantern_calibration.toml",
                format!("lantern_calibration.toml cites unknown artifact `{art_id}`"),
            ));
        };
        let ArtifactWitness::Calibration(cal) = &art.witness else {
            return Err(invalid(
                "lantern_calibration.toml",
                format!(
                    "lantern_calibration.toml cites artifact `{art_id}` of kind `{}`, expected `calibration`",
                    art.kind.as_str()
                ),
            ));
        };
        for row in &lantern_calibration.rows {
            let Some(conf) = cal
                .per_procedure_confusion
                .iter()
                .find(|c| c.procedure == row.id)
            else {
                return Err(invalid(
                    "lantern_calibration.toml",
                    format!(
                        "procedure `{}` in lantern_calibration.toml is missing from artifact `{art_id}` per_procedure_confusion",
                        row.id
                    ),
                ));
            };
            if conf.true_positives != row.true_positives
                || conf.false_positives != row.false_positives
                || conf.false_negatives != row.false_negatives
            {
                return Err(invalid(
                    "lantern_calibration.toml",
                    format!(
                        "procedure `{}` confusion counts in lantern_calibration.toml do not match artifact `{art_id}`",
                        row.id
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// Prose `claims_lint` over `README.md` and `docs/**`: any paragraph asserting
/// `"proof"`, `"external oracle"`, `"measured"`, `"calibrated"`, `"constant-time"`,
/// or `"agreement across"` must cite a live `FA-ART-*` or `FA-INV-*` identifier
/// in the same paragraph (`fa-vtzt`).
pub fn verify_prose_claims_lint(
    repo_root: &Path,
    artifacts: &EvidenceArtifacts,
    invariants: &crate::invariants::Invariants,
) -> Result<(), RegistryError> {
    let readme = repo_root.join("README.md");
    if readme.exists() {
        let text = std::fs::read_to_string(&readme)
            .map_err(|e| invalid("claims_lint.toml", format!("cannot read README.md: {e}")))?;
        verify_prose_claims_lint_text("README.md", &text, artifacts, invariants)?;
    }
    let docs_dir = repo_root.join("docs");
    if docs_dir.exists() {
        let mut docs_files = Vec::new();
        collect_markdown_files(&docs_dir, &mut docs_files)?;
        docs_files.sort();
        for path in docs_files {
            if path.file_name().and_then(|s| s.to_str()) == Some("NEGATIVE_EVIDENCE.md") {
                continue;
            }
            let rel = path
                .strip_prefix(repo_root)
                .unwrap_or(&path)
                .display()
                .to_string();
            let text = std::fs::read_to_string(&path)
                .map_err(|e| invalid("claims_lint.toml", format!("cannot read `{rel}`: {e}")))?;
            verify_prose_claims_lint_text(&rel, &text, artifacts, invariants)?;
        }
    }
    Ok(())
}

/// Check a single markdown document for unbacked prose claims (`fa-vtzt`).
pub fn verify_prose_claims_lint_text(
    file_label: &str,
    text: &str,
    artifacts: &EvidenceArtifacts,
    invariants: &crate::invariants::Invariants,
) -> Result<(), RegistryError> {
    const TRIGGERS: [&str; 6] = [
        "external oracle",
        "measured",
        "calibrated",
        "constant-time",
        "agreement across",
        "proof",
    ];
    let stripped = strip_fenced_code_blocks(text);
    for (idx, paragraph) in stripped.split("\n\n").enumerate() {
        let trimmed = paragraph.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        for trigger in TRIGGERS {
            if !contains_phrase_word_bounded(&lower, trigger) {
                continue;
            }
            if is_exempt_prose_context(&lower, trigger) {
                continue;
            }
            if !has_live_claim_citation(trimmed, artifacts, invariants) {
                let preview: String = trimmed.chars().take(120).collect();
                return Err(invalid(
                    "claims_lint.toml",
                    format!(
                        "{file_label} (paragraph {}): prose asserts `{trigger}` without a live `FA-ART-*` or `FA-INV-*` citation in the same paragraph: `{preview}`",
                        idx + 1
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn collect_markdown_files(
    dir: &Path,
    out: &mut Vec<std::path::PathBuf>,
) -> Result<(), RegistryError> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        invalid(
            "claims_lint.toml",
            format!("cannot read directory `{}`: {e}", dir.display()),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| invalid("claims_lint.toml", e.to_string()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_markdown_files(&path, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("md") {
            out.push(path);
        }
    }
    Ok(())
}

fn strip_fenced_code_blocks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_fence = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn contains_phrase_word_bounded(haystack_lower: &str, phrase: &str) -> bool {
    let bytes = haystack_lower.as_bytes();
    let pbytes = phrase.as_bytes();
    if pbytes.is_empty() || bytes.len() < pbytes.len() {
        return false;
    }
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let mut pos = 0;
    while let Some(offset) = haystack_lower[pos..].find(phrase) {
        let start = pos + offset;
        let end = start + pbytes.len();
        let before_ok = start == 0 || !is_word(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        pos = start + 1;
    }
    false
}

fn is_exempt_prose_context(lower: &str, trigger: &str) -> bool {
    if trigger == "measured" && lower.contains("not measured") {
        return true;
    }
    if trigger == "proof" {
        const PROOF_EXEMPTIONS: &[&str] = &[
            "no lean 4 proof",
            "never \"franken_accounting",
            "not a legal conclusion or a formal proof",
            "not proof of",
            "what it proves",
            "proof class",
            "fa proof",
            "proof inclusion",
            "proof prefix",
            "proof balance",
            "inclusion proof",
            "prefix proof",
            "balance proof",
            "bundle proof",
            "accumulator proof",
            "merkle proof",
            "proof and its checkpoint",
            "proofs and their checkpoint",
            "proof of authenticity",
            "authorize proofs",
            "proof export",
            "proof generation",
            "`proof`",
        ];
        if PROOF_EXEMPTIONS.iter().any(|pat| lower.contains(pat)) {
            return true;
        }
    }
    false
}

fn has_live_claim_citation(
    paragraph: &str,
    artifacts: &EvidenceArtifacts,
    invariants: &crate::invariants::Invariants,
) -> bool {
    // Check for any live FA-ART-* id.
    for art in &artifacts.artifacts {
        if paragraph.contains(&art.id) {
            return true;
        }
    }
    // Check for any FA-INV-NN or FA-INV-NN.<clause> that has at least one live clause.
    for inv in &invariants.invariants {
        if paragraph.contains(&inv.id)
            && invariants
                .clauses
                .iter()
                .any(|c| c.invariant == inv.id && c.is_live())
        {
            return true;
        }
    }
    false
}

fn parse_artifact_row(
    registry: &'static str,
    table: &Table,
    doc: Option<&Document>,
) -> Result<EvidenceArtifactRow, RegistryError> {
    let id = req_str(registry, table, "id")?.to_string();
    if !id.starts_with("FA-ART-") || id.len() <= "FA-ART-".len() {
        return Err(invalid(
            registry,
            format!("artifact id `{id}` must start with `FA-ART-`"),
        ));
    }
    let kind_raw = req_str(registry, table, "kind")?;
    let kind = ArtifactKind::parse(kind_raw).ok_or_else(|| {
        invalid(
            registry,
            format!("{id}: unknown artifact kind `{kind_raw}`"),
        )
    })?;
    let manifest_path = req_str(registry, table, "manifest_path")?.to_string();
    if !manifest_path.starts_with("evidence/")
        || !manifest_path.ends_with(".toml")
        || manifest_path.contains("..")
    {
        return Err(invalid(
            registry,
            format!("{id}: manifest_path `{manifest_path}` must live under `evidence/*.toml`"),
        ));
    }
    let manifest_blake3 = req_str(registry, table, "manifest_blake3")?.to_string();
    check_hex_digest(registry, &id, "manifest_blake3", &manifest_blake3)?;
    let produced_by = req_str(registry, table, "produced_by")?.to_string();
    if produced_by.trim().is_empty() {
        return Err(invalid(
            registry,
            format!("{id}: produced_by must not be empty"),
        ));
    }
    let git_commit = req_str(registry, table, "git_commit")?.to_string();
    check_git_commit(registry, &id, &git_commit)?;
    let summary = req_str(registry, table, "summary")?.to_string();
    if summary.trim().is_empty() {
        return Err(invalid(
            registry,
            format!("{id}: summary must not be empty"),
        ));
    }

    let witness = parse_witness(registry, &id, kind, table, doc)?;
    Ok(EvidenceArtifactRow {
        id,
        kind,
        manifest_path,
        manifest_blake3,
        produced_by,
        git_commit,
        summary,
        witness,
    })
}

fn parse_witness(
    registry: &'static str,
    id: &str,
    kind: ArtifactKind,
    table: &Table,
    doc: Option<&Document>,
) -> Result<ArtifactWitness, RegistryError> {
    match kind {
        ArtifactKind::Benchmark => {
            let scale_table = doc.and_then(|d| d.tables.get("scale_witness"));
            let leg_count = opt_u64(registry, id, table, "scale_witness_leg_count")?
                .or(match scale_table {
                    Some(st) => opt_u64(registry, id, st, "leg_count")?,
                    None => None,
                })
                .unwrap_or(0);
            let entry_count = opt_u64(registry, id, table, "scale_witness_entry_count")?
                .or(match scale_table {
                    Some(st) => opt_u64(registry, id, st, "entry_count")?,
                    None => None,
                })
                .unwrap_or(0);
            let bundle_bytes = opt_u64(registry, id, table, "scale_witness_bundle_bytes")?
                .or(match scale_table {
                    Some(st) => opt_u64(registry, id, st, "bundle_bytes")?,
                    None => None,
                })
                .unwrap_or(0);
            let scale_witness = ScaleWitness {
                leg_count,
                entry_count,
                bundle_bytes,
            };
            if !scale_witness.is_populated() {
                return Err(invalid(
                    registry,
                    format!(
                        "{id}: benchmark artifact requires non-zero scale_witness (leg_count, entry_count, or bundle_bytes)"
                    ),
                ));
            }
            let iterations = req_u64(registry, id, table, "iterations")?;
            if iterations == 0 {
                return Err(invalid(
                    registry,
                    format!("{id}: benchmark iterations must be >= 1"),
                ));
            }
            let warmup = req_u64(registry, id, table, "warmup")?;
            let quantile_samples_ns = req_u64_list(registry, id, table, "quantile_samples_ns")?;
            if quantile_samples_ns.is_empty() {
                return Err(invalid(
                    registry,
                    format!("{id}: benchmark quantile_samples_ns must not be empty"),
                ));
            }
            if quantile_samples_ns.windows(2).any(|w| w[0] > w[1]) {
                return Err(invalid(
                    registry,
                    format!("{id}: benchmark quantile_samples_ns must be sorted ascending"),
                ));
            }
            let flamegraph_svg_sha256 =
                req_str_owned(registry, id, table, "flamegraph_svg_sha256")?;
            check_hex_digest(
                registry,
                id,
                "flamegraph_svg_sha256",
                &flamegraph_svg_sha256,
            )?;
            let host_cpu_model = req_str_owned(registry, id, table, "host_cpu_model")?;
            if host_cpu_model.trim().is_empty() {
                return Err(invalid(
                    registry,
                    format!("{id}: benchmark host_cpu_model must not be empty"),
                ));
            }
            let host_kernel = req_str_owned(registry, id, table, "host_kernel")?;
            if host_kernel.trim().is_empty() {
                return Err(invalid(
                    registry,
                    format!("{id}: benchmark host_kernel must not be empty"),
                ));
            }
            let runner = req_str_owned(registry, id, table, "runner")?;
            if !matches!(runner.as_str(), "rch-worker" | "local-pinned") {
                return Err(invalid(
                    registry,
                    format!(
                        "{id}: benchmark runner `{runner}` must be `rch-worker` or `local-pinned`"
                    ),
                ));
            }
            Ok(ArtifactWitness::Benchmark(BenchmarkWitness {
                scale_witness,
                iterations,
                warmup,
                quantile_samples_ns,
                flamegraph_svg_sha256,
                host_cpu_model,
                host_kernel,
                runner,
            }))
        }
        ArtifactKind::ExternalOracle => {
            let tool_binary_path = req_str_owned(registry, id, table, "tool_binary_path")?;
            if tool_binary_path.trim().is_empty() {
                return Err(invalid(
                    registry,
                    format!("{id}: external-oracle tool_binary_path must not be empty"),
                ));
            }
            let tool_version_stdout = req_str_owned(registry, id, table, "tool_version_stdout")?;
            if tool_version_stdout.trim().is_empty() {
                return Err(invalid(
                    registry,
                    format!("{id}: external-oracle tool_version_stdout must not be empty"),
                ));
            }
            let tool_binary_sha256 = req_str_owned(registry, id, table, "tool_binary_sha256")?;
            check_hex_digest(registry, id, "tool_binary_sha256", &tool_binary_sha256)?;
            let input_fixture_sha256 = req_str_owned(registry, id, table, "input_fixture_sha256")?;
            check_hex_digest(registry, id, "input_fixture_sha256", &input_fixture_sha256)?;
            let tool_stdout_sha256 = req_str_owned(registry, id, table, "tool_stdout_sha256")?;
            check_hex_digest(registry, id, "tool_stdout_sha256", &tool_stdout_sha256)?;
            let tool_exit_code =
                i64::try_from(req_int_owned(registry, id, table, "tool_exit_code")?)
                    .map_err(|_| invalid(registry, format!("{id}: tool_exit_code must fit i64")))?;
            let compared_cells = req_u64(registry, id, table, "compared_cells")?;
            if compared_cells == 0 {
                return Err(invalid(
                    registry,
                    format!(
                        "{id}: external-oracle compared_cells must be >= 1 (0 cells compared is refused)"
                    ),
                ));
            }
            Ok(ArtifactWitness::ExternalOracle(ExternalOracleWitness {
                tool_binary_path,
                tool_version_stdout,
                tool_binary_sha256,
                input_fixture_sha256,
                tool_stdout_sha256,
                tool_exit_code,
                compared_cells,
            }))
        }
        ArtifactKind::Lean => {
            let lean_version = req_str_owned(registry, id, table, "lean_version")?;
            if lean_version.trim().is_empty() {
                return Err(invalid(
                    registry,
                    format!("{id}: lean_version must not be empty"),
                ));
            }
            let lake_manifest_sha256 = req_str_owned(registry, id, table, "lake_manifest_sha256")?;
            check_hex_digest(registry, id, "lake_manifest_sha256", &lake_manifest_sha256)?;
            let olean_tar_sha256 = req_str_owned(registry, id, table, "olean_tar_sha256")?;
            check_hex_digest(registry, id, "olean_tar_sha256", &olean_tar_sha256)?;
            let theorem_inventory = parse_lean_theorems(registry, id, table, doc)?;
            if theorem_inventory.is_empty() {
                return Err(invalid(
                    registry,
                    format!("{id}: lean theorem_inventory must not be empty"),
                ));
            }
            for thm in &theorem_inventory {
                if thm.name.trim().is_empty() || thm.module.trim().is_empty() {
                    return Err(invalid(
                        registry,
                        format!("{id}: lean theorem must have non-empty name and module"),
                    ));
                }
                if thm.sorry_count > 0 {
                    return Err(invalid(
                        registry,
                        format!(
                            "{id}: lean theorem `{}` has sorry_count = {} (> 0 is forbidden)",
                            thm.name, thm.sorry_count
                        ),
                    ));
                }
                for ax in &thm.axioms_used {
                    if matches!(ax.as_str(), "sorryAx" | "Classical.choice") {
                        return Err(invalid(
                            registry,
                            format!(
                                "{id}: lean theorem `{}` uses forbidden axiom `{ax}`",
                                thm.name
                            ),
                        ));
                    }
                }
            }
            Ok(ArtifactWitness::Lean(LeanWitness {
                lean_version,
                lake_manifest_sha256,
                olean_tar_sha256,
                theorem_inventory,
            }))
        }
        ArtifactKind::Tlc => {
            let tlc_version = req_str_owned(registry, id, table, "tlc_version")?;
            if tlc_version.trim().is_empty() {
                return Err(invalid(
                    registry,
                    format!("{id}: tlc_version must not be empty"),
                ));
            }
            let spec_sha256 = req_str_owned(registry, id, table, "spec_sha256")?;
            check_hex_digest(registry, id, "spec_sha256", &spec_sha256)?;
            let cfg_sha256 = req_str_owned(registry, id, table, "cfg_sha256")?;
            check_hex_digest(registry, id, "cfg_sha256", &cfg_sha256)?;
            let distinct_states = req_u64(registry, id, table, "distinct_states")?;
            if distinct_states == 0 {
                return Err(invalid(
                    registry,
                    format!("{id}: tlc distinct_states must be >= 1"),
                ));
            }
            let states_generated = req_u64(registry, id, table, "states_generated")?;
            if states_generated < distinct_states {
                return Err(invalid(
                    registry,
                    format!(
                        "{id}: tlc states_generated ({states_generated}) < distinct_states ({distinct_states})"
                    ),
                ));
            }
            let depth = req_u64(registry, id, table, "depth")?;
            if depth == 0 {
                return Err(invalid(registry, format!("{id}: tlc depth must be >= 1")));
            }
            let result = req_str_owned(registry, id, table, "result")?;
            if result != "pass" {
                return Err(invalid(
                    registry,
                    format!("{id}: tlc result must be `pass`, got `{result}`"),
                ));
            }
            Ok(ArtifactWitness::Tlc(TlcWitness {
                tlc_version,
                spec_sha256,
                cfg_sha256,
                distinct_states,
                states_generated,
                depth,
                result,
            }))
        }
        ArtifactKind::LabCampaign => {
            let seed_manifest_sha256 = req_str_owned(registry, id, table, "seed_manifest_sha256")?;
            check_hex_digest(registry, id, "seed_manifest_sha256", &seed_manifest_sha256)?;
            let schedule_count = req_u64(registry, id, table, "schedule_count")?;
            if schedule_count == 0 {
                return Err(invalid(
                    registry,
                    format!("{id}: lab-campaign schedule_count must be >= 1"),
                ));
            }
            let explored_interleavings = req_u64(registry, id, table, "explored_interleavings")?;
            if explored_interleavings == 0 {
                return Err(invalid(
                    registry,
                    format!("{id}: lab-campaign explored_interleavings must be >= 1"),
                ));
            }
            let certificate_hashes_blake3 =
                req_str_list_owned(registry, id, table, "certificate_hashes_blake3")?;
            if certificate_hashes_blake3.is_empty() {
                return Err(invalid(
                    registry,
                    format!("{id}: lab-campaign certificate_hashes_blake3 must not be empty"),
                ));
            }
            for digest in &certificate_hashes_blake3 {
                check_hex_digest(registry, id, "certificate_hashes_blake3", digest)?;
            }
            Ok(ArtifactWitness::LabCampaign(LabCampaignWitness {
                seed_manifest_sha256,
                schedule_count,
                explored_interleavings,
                certificate_hashes_blake3,
            }))
        }
        ArtifactKind::Calibration => {
            let corpus_manifest_sha256 =
                req_str_owned(registry, id, table, "corpus_manifest_sha256")?;
            check_hex_digest(
                registry,
                id,
                "corpus_manifest_sha256",
                &corpus_manifest_sha256,
            )?;
            let case_count = req_u64(registry, id, table, "case_count")?;
            if case_count == 0 {
                return Err(invalid(
                    registry,
                    format!("{id}: calibration case_count must be >= 1"),
                ));
            }
            let per_procedure_confusion = parse_confusion_rows(registry, id, table, doc)?;
            if per_procedure_confusion.is_empty() {
                return Err(invalid(
                    registry,
                    format!("{id}: calibration per_procedure_confusion must not be empty"),
                ));
            }
            for row in &per_procedure_confusion {
                if row.procedure.trim().is_empty() {
                    return Err(invalid(
                        registry,
                        format!("{id}: calibration procedure name must not be empty"),
                    ));
                }
                if row.true_positives + row.false_negatives == 0 {
                    return Err(invalid(
                        registry,
                        format!(
                            "{id}: calibration procedure `{}` has TP + FN = 0 (at least 1 positive case required)",
                            row.procedure
                        ),
                    ));
                }
            }
            Ok(ArtifactWitness::Calibration(CalibrationWitness {
                corpus_manifest_sha256,
                case_count,
                per_procedure_confusion,
            }))
        }
    }
}

fn parse_lean_theorems(
    registry: &'static str,
    id: &str,
    table: &Table,
    doc: Option<&Document>,
) -> Result<Vec<LeanTheoremWitness>, RegistryError> {
    if let Some(d) = doc
        && let Some(rows) = d.arrays.get("theorem_inventory")
    {
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let name = req_str_owned(registry, id, r, "name")?;
            let module = req_str_owned(registry, id, r, "module")?;
            let sorry_count = req_u64(registry, id, r, "sorry_count")?;
            let axioms_used = req_str_list_owned(registry, id, r, "axioms_used")?;
            out.push(LeanTheoremWitness {
                name,
                module,
                sorry_count,
                axioms_used,
            });
        }
        return Ok(out);
    }
    let compact = req_str_list_owned(registry, id, table, "theorem_inventory")?;
    let mut out = Vec::with_capacity(compact.len());
    for entry in compact {
        // Format: "name:module:sorry_count:axiom1|axiom2" (or empty axioms after last colon).
        let parts: Vec<&str> = entry.splitn(4, ':').collect();
        if parts.len() != 4 {
            return Err(invalid(
                registry,
                format!(
                    "{id}: compact theorem_inventory entry `{entry}` must have format `name:module:sorry_count:axioms`"
                ),
            ));
        }
        let sorry_count = parts[2]
            .parse::<u64>()
            .map_err(|_| invalid(registry, format!("{id}: invalid sorry_count in `{entry}`")))?;
        let axioms_used = if parts[3].trim().is_empty() {
            Vec::new()
        } else {
            parts[3].split('|').map(str::to_string).collect()
        };
        out.push(LeanTheoremWitness {
            name: parts[0].to_string(),
            module: parts[1].to_string(),
            sorry_count,
            axioms_used,
        });
    }
    Ok(out)
}

fn parse_confusion_rows(
    registry: &'static str,
    id: &str,
    table: &Table,
    doc: Option<&Document>,
) -> Result<Vec<ProcedureConfusionWitness>, RegistryError> {
    if let Some(d) = doc
        && let Some(rows) = d.arrays.get("per_procedure_confusion")
    {
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let procedure = req_str_owned(registry, id, r, "procedure")?;
            let true_positives = req_u64(registry, id, r, "true_positives")?;
            let false_positives = req_u64(registry, id, r, "false_positives")?;
            let false_negatives = req_u64(registry, id, r, "false_negatives")?;
            let true_negatives = req_u64(registry, id, r, "true_negatives")?;
            out.push(ProcedureConfusionWitness {
                procedure,
                true_positives,
                false_positives,
                false_negatives,
                true_negatives,
            });
        }
        return Ok(out);
    }
    let compact = req_str_list_owned(registry, id, table, "per_procedure_confusion")?;
    let mut out = Vec::with_capacity(compact.len());
    for entry in compact {
        // Format: "procedure:tp:fp:fn:tn"
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() != 5 {
            return Err(invalid(
                registry,
                format!(
                    "{id}: compact per_procedure_confusion entry `{entry}` must have format `procedure:tp:fp:fn:tn`"
                ),
            ));
        }
        let parse_num = |s: &str, label: &str| -> Result<u64, RegistryError> {
            s.parse::<u64>().map_err(|_| {
                invalid(
                    registry,
                    format!("{id}: invalid {label} `{s}` in `{entry}`"),
                )
            })
        };
        out.push(ProcedureConfusionWitness {
            procedure: parts[0].to_string(),
            true_positives: parse_num(parts[1], "true_positives")?,
            false_positives: parse_num(parts[2], "false_positives")?,
            false_negatives: parse_num(parts[3], "false_negatives")?,
            true_negatives: parse_num(parts[4], "true_negatives")?,
        });
    }
    Ok(out)
}

fn check_hex_digest(
    registry: &'static str,
    id: &str,
    field: &str,
    digest: &str,
) -> Result<(), RegistryError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid(
            registry,
            format!("{id}: `{field}` must be 64 lowercase hex characters, got `{digest}`"),
        ));
    }
    Ok(())
}

fn check_git_commit(registry: &'static str, id: &str, commit: &str) -> Result<(), RegistryError> {
    if !(7..=64).contains(&commit.len())
        || !commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid(
            registry,
            format!("{id}: `git_commit` must be 7..=64 lowercase hex characters, got `{commit}`"),
        ));
    }
    Ok(())
}

fn req_str_owned(
    registry: &'static str,
    id: &str,
    table: &Table,
    key: &str,
) -> Result<String, RegistryError> {
    match table.get(key).and_then(Value::as_str) {
        Some(s) => Ok(s.to_string()),
        None => Err(invalid(
            registry,
            format!("{id}: missing or non-string required key `{key}`"),
        )),
    }
}

fn req_int_owned(
    registry: &'static str,
    id: &str,
    table: &Table,
    key: &str,
) -> Result<i128, RegistryError> {
    match table.get(key).and_then(Value::as_int) {
        Some(v) => Ok(v),
        None => Err(invalid(
            registry,
            format!("{id}: missing or non-integer required key `{key}`"),
        )),
    }
}

fn req_u64(
    registry: &'static str,
    id: &str,
    table: &Table,
    key: &str,
) -> Result<u64, RegistryError> {
    let raw = req_int_owned(registry, id, table, key)?;
    u64::try_from(raw).map_err(|_| {
        invalid(
            registry,
            format!("{id}: key `{key}` must be a non-negative u64, got {raw}"),
        )
    })
}

fn opt_u64(
    registry: &'static str,
    id: &str,
    table: &Table,
    key: &str,
) -> Result<Option<u64>, RegistryError> {
    let Some(v) = table.get(key) else {
        return Ok(None);
    };
    let raw = v
        .as_int()
        .ok_or_else(|| invalid(registry, format!("{id}: key `{key}` must be an integer")))?;
    let n = u64::try_from(raw).map_err(|_| {
        invalid(
            registry,
            format!("{id}: key `{key}` must be a non-negative u64, got {raw}"),
        )
    })?;
    Ok(Some(n))
}

fn req_u64_list(
    registry: &'static str,
    id: &str,
    table: &Table,
    key: &str,
) -> Result<Vec<u64>, RegistryError> {
    let arr = table.get(key).and_then(Value::as_array).ok_or_else(|| {
        invalid(
            registry,
            format!("{id}: missing or non-array required key `{key}`"),
        )
    })?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let raw = item
            .as_int()
            .ok_or_else(|| invalid(registry, format!("{id}: `{key}` elements must be integers")))?;
        let n = u64::try_from(raw).map_err(|_| {
            invalid(
                registry,
                format!("{id}: `{key}` elements must be non-negative u64"),
            )
        })?;
        out.push(n);
    }
    Ok(out)
}

fn req_str_list_owned(
    registry: &'static str,
    id: &str,
    table: &Table,
    key: &str,
) -> Result<Vec<String>, RegistryError> {
    let arr = table.get(key).and_then(Value::as_array).ok_or_else(|| {
        invalid(
            registry,
            format!("{id}: missing or non-array required key `{key}`"),
        )
    })?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| invalid(registry, format!("{id}: `{key}` elements must be strings")))?;
        out.push(s.to_string());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Self-contained std-only BLAKE3 256-bit hash for manifest digest verification
// ---------------------------------------------------------------------------

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for i in 0..16 {
        permuted[i] = m[MSG_PERMUTATION[i]];
    }
    *m = permuted;
}

fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut block = *block_words;
    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);

    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

fn first_8_words(compression_output: [u32; 16]) -> [u32; 8] {
    let mut out = [0u32; 8];
    out.copy_from_slice(&compression_output[..8]);
    out
}

fn words_from_little_endian_bytes(bytes: &[u8], words: &mut [u32]) {
    let (chunks, _) = bytes.as_chunks::<4>();
    for (word, chunk) in words.iter_mut().zip(chunks) {
        *word = u32::from_le_bytes(*chunk);
    }
}

#[derive(Clone, Copy)]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_output_bytes(&self) -> [u8; OUT_LEN] {
        let words = compress(
            &self.input_chaining_value,
            &self.block_words,
            0,
            self.block_len,
            self.flags | ROOT,
        );
        let mut out = [0u8; OUT_LEN];
        let (chunks, _) = out.as_chunks_mut::<4>();
        for (word, chunk) in words[..8].iter().zip(chunks) {
            *chunk = word.to_le_bytes();
        }
        out
    }
}

#[derive(Clone)]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            chaining_value: key_words,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * usize::from(self.blocks_compressed) + usize::from(self.block_len)
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if usize::from(self.block_len) == BLOCK_LEN {
                let mut block_words = [0u32; 16];
                words_from_little_endian_bytes(&self.block, &mut block_words);
                self.chaining_value = first_8_words(compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let want = BLOCK_LEN - usize::from(self.block_len);
            let take = want.min(input.len());
            self.block[usize::from(self.block_len)..usize::from(self.block_len) + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let mut block_words = [0u32; 16];
        words_from_little_endian_bytes(&self.block, &mut block_words);
        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: u32::from(self.block_len),
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(
    left_child_cv: [u32; 8],
    right_child_cv: [u32; 8],
    key_words: [u32; 8],
    flags: u32,
) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left_child_cv);
    block_words[8..].copy_from_slice(&right_child_cv);
    Output {
        input_chaining_value: key_words,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT | flags,
    }
}

/// Compute the 32-byte BLAKE3 digest of `input`.
#[must_use]
pub fn blake3_hash(mut input: &[u8]) -> [u8; OUT_LEN] {
    let mut chunk_state = ChunkState::new(IV, 0, 0);
    let mut cv_stack = [[0u32; 8]; 54];
    let mut cv_stack_len = 0usize;

    while !input.is_empty() {
        if chunk_state.len() == CHUNK_LEN {
            let chunk_cv = chunk_state.output().chaining_value();
            let total_chunks = chunk_state.chunk_counter + 1;
            let mut new_cv = chunk_cv;
            let mut total = total_chunks;
            while total & 1 == 0 {
                cv_stack_len -= 1;
                new_cv = parent_output(cv_stack[cv_stack_len], new_cv, IV, 0).chaining_value();
                total >>= 1;
            }
            cv_stack[cv_stack_len] = new_cv;
            cv_stack_len += 1;
            chunk_state = ChunkState::new(IV, total_chunks, 0);
        }
        let want = CHUNK_LEN - chunk_state.len();
        let take = want.min(input.len());
        chunk_state.update(&input[..take]);
        input = &input[take..];
    }

    let mut output = chunk_state.output();
    while cv_stack_len > 0 {
        cv_stack_len -= 1;
        output = parent_output(cv_stack[cv_stack_len], output.chaining_value(), IV, 0);
    }
    output.root_output_bytes()
}

/// Compute the 64-character lowercase hex BLAKE3 digest of `input`.
#[must_use]
pub fn blake3_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = blake3_hash(input);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_evidence_artifacts_parse_and_verify() {
        let artifacts = EvidenceArtifacts::embedded().expect("embedded evidence_artifacts.toml");
        assert!(artifacts.get("FA-ART-CAL-01").is_some());
        assert!(artifacts.get("FA-ART-LAB-01").is_some());

        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        let logs = artifacts
            .verify_store(repo_root)
            .expect("evidence store manifests verify");
        assert_eq!(logs.len(), artifacts.artifacts.len());
        for log in logs {
            assert_eq!(log.verdict, "PASS");
            assert!(log.witness_fields_checked >= 3);
        }
    }
}
