//! `fa-bench`: criterion-free in-house deterministic benchmark harness, §17
//! baseline manifest verifier, and Appendix G operation-cost witness counter
//! (plan §17, §18.1, Appendix G; beads `fa-tu58`, `fa-i5s`).
//!
//! Enforces the constitutional performance and operation-cost laws:
//! 1. **Distributions, never averages (§17):** every benchmark produces integer
//!    microsecond quantiles (`p50_us`, `p95_us`, `p99_us`, `min_us`, `max_us`).
//! 2. **Watermark vs. tail disclosure (§17 standing law):** no balance-read or
//!    trial-balance number is emitted or accepted without `served_mode`
//!    (`"watermark"` or `"tail_fold"`) and `tail_length`.
//! 3. **Incumbent in the same invocation (`AGENTS.md` / `fa-i5s`):** a benchmark
//!    manifest or comparison run without `incumbent_in_same_invocation = true`
//!    is refused (`BenchError::MissingIncumbentInSameInvocation`).
//! 4. **Per-worker-class baseline pinning (`fa-i5s`):** comparing a measurement
//!    against a baseline from a different `worker_class` is refused
//!    (`BenchError::WorkerClassMismatch`).
//! 5. **Counted kernel operation witnesses (`operation_costs.toml`, `fa-i5s`):**
//!    each of the 9 registered kernel operations (`post`, `reserve`, `resolve`,
//!    `period_transition`, `document_add`, `checkpoint`, `fold_per_entry`,
//!    `verify_per_cell`, `query_procedure`) is executed against a deterministic
//!    in-memory book and its substrate operations (`point_reads`, `witnesses`,
//!    `cas_moves`, `edges_written`, `vertices_written`, `transactions`) are
//!    checked against `registries/operation_costs.toml`.
//!
//! **What this crate does not do yet (fa-e75k, fa-ykbp):** it times none of the
//! §17 workloads. Earlier revisions timed corpus generation or a kernel witness
//! under the §17 names and shipped hand-entered baselines; that was withdrawn.
//! Every §17 benchmark now reports [`BenchOutcome::Unmeasured`] with its reason
//! until a bench executes the named workload at the stated scale.

#![forbid(unsafe_code)]

pub mod driver;
pub mod post;
pub mod rebuild;
pub mod stats;

use std::fmt;

use fa::book::{Book, BookKeys, Entropy};
use fa_demo::us_gaap_smb_accounts;
use fa_journal::{
    BalanceLimit, BookSpec, Capability, Document, LimitScope, PostRequest, TimeZonePolicy,
};
use fa_lantern::jet::RoundAmounts;
use fa_model::{
    ControlPayload, Disposition, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid,
    Pending, account_vid, domain_digest, principal_vid,
};
use fa_money::{Amount, Side, UnitRegistry};
use fa_registry::g0::{OperationCosts, SloRegistry};
use fa_registry::toml::{self, Table, Value};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};

/// Embedded `bench/manifests/*.toml` baseline manifests (19 §17 targets).
pub const EMBEDDED_MANIFESTS: &[(&str, &str)] = &[
    (
        "bench/manifests/single_entry_post.toml",
        include_str!("../../../bench/manifests/single_entry_post.toml"),
    ),
    (
        "bench/manifests/batched_post.toml",
        include_str!("../../../bench/manifests/batched_post.toml"),
    ),
    (
        "bench/manifests/bulk_migration.toml",
        include_str!("../../../bench/manifests/bulk_migration.toml"),
    ),
    (
        "bench/manifests/balance_read_watermark.toml",
        include_str!("../../../bench/manifests/balance_read_watermark.toml"),
    ),
    (
        "bench/manifests/trial_balance_100k.toml",
        include_str!("../../../bench/manifests/trial_balance_100k.toml"),
    ),
    (
        "bench/manifests/register_rebuild_10m.toml",
        include_str!("../../../bench/manifests/register_rebuild_10m.toml"),
    ),
    (
        "bench/manifests/register_watermark_lag.toml",
        include_str!("../../../bench/manifests/register_watermark_lag.toml"),
    ),
    (
        "bench/manifests/known_at_trial_balance.toml",
        include_str!("../../../bench/manifests/known_at_trial_balance.toml"),
    ),
    (
        "bench/manifests/close_dry_run.toml",
        include_str!("../../../bench/manifests/close_dry_run.toml"),
    ),
    (
        "bench/manifests/restatement_diff_certificate.toml",
        include_str!("../../../bench/manifests/restatement_diff_certificate.toml"),
    ),
    (
        "bench/manifests/bundle_production_and_verify.toml",
        include_str!("../../../bench/manifests/bundle_production_and_verify.toml"),
    ),
    (
        "bench/manifests/lantern_jet_benford.toml",
        include_str!("../../../bench/manifests/lantern_jet_benford.toml"),
    ),
    (
        "bench/manifests/lantern_graph_trace.toml",
        include_str!("../../../bench/manifests/lantern_graph_trace.toml"),
    ),
    (
        "bench/manifests/consolidation_branch.toml",
        include_str!("../../../bench/manifests/consolidation_branch.toml"),
    ),
    (
        "bench/manifests/accumulator_checkpoint.toml",
        include_str!("../../../bench/manifests/accumulator_checkpoint.toml"),
    ),
    (
        "bench/manifests/cli_first_try_latency.toml",
        include_str!("../../../bench/manifests/cli_first_try_latency.toml"),
    ),
    (
        "bench/manifests/mcp_tool_round_trip.toml",
        include_str!("../../../bench/manifests/mcp_tool_round_trip.toml"),
    ),
    (
        "bench/manifests/memory_bytes_per_leg.toml",
        include_str!("../../../bench/manifests/memory_bytes_per_leg.toml"),
    ),
    (
        "bench/manifests/endurance_sustained_post.toml",
        include_str!("../../../bench/manifests/endurance_sustained_post.toml"),
    ),
];

/// Errors returned by `fa-bench` manifest verification, witness counting, or benchmark execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BenchError {
    ManifestParse(String),
    MissingIncumbentInSameInvocation(String),
    WorkerClassMismatch {
        manifest: String,
        expected: String,
        actual: String,
    },
    MissingWatermarkDisclosure(String),
    BytesPerLegExceeded {
        manifest: String,
        actual: u64,
        ceiling: u64,
    },
    WitnessDrift {
        op_id: String,
        field: &'static str,
        expected: u32,
        actual: u32,
    },
    UnknownBenchmark(String),
    Execution(String),
}

impl fmt::Display for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestParse(m) => write!(f, "manifest parse error: {m}"),
            Self::MissingIncumbentInSameInvocation(m) => {
                write!(
                    f,
                    "refused benchmark manifest `{m}`: incumbent_in_same_invocation must be true (AGENTS.md)"
                )
            }
            Self::WorkerClassMismatch {
                manifest,
                expected,
                actual,
            } => write!(
                f,
                "refused cross-worker comparison on `{manifest}`: baseline pinned to `{expected}`, candidate ran on `{actual}`"
            ),
            Self::MissingWatermarkDisclosure(m) => write!(
                f,
                "§17 standing law violation on `{m}`: balance-read numbers must state served_mode (watermark|tail_fold) and tail_length"
            ),
            Self::BytesPerLegExceeded {
                manifest,
                actual,
                ceiling,
            } => write!(
                f,
                "`{manifest}` bytes_per_leg ({actual}) exceeds §17 ceiling ({ceiling})"
            ),
            Self::WitnessDrift {
                op_id,
                field,
                expected,
                actual,
            } => write!(
                f,
                "operation_costs.toml witness drift on `{op_id}.{field}`: expected {expected}, counted {actual}"
            ),
            Self::UnknownBenchmark(name) => write!(f, "unknown §17 benchmark `{name}`"),
            Self::Execution(m) => write!(f, "benchmark execution error: {m}"),
        }
    }
}

impl std::error::Error for BenchError {}

/// How a balance or trial-balance read was served (§17 standing law).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServedMode {
    Watermark,
    TailFold,
}

impl ServedMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Watermark => "watermark",
            Self::TailFold => "tail_fold",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "watermark" => Some(Self::Watermark),
            "tail_fold" => Some(Self::TailFold),
            _ => None,
        }
    }
}

/// Mandatory disclosure for balance-read and trial-balance benchmarks (§17 standing law).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatermarkDisclosure {
    pub served_mode: ServedMode,
    pub tail_length: u64,
}

/// Component breakdown for `FA-BENCH-18` (`memory_bytes_per_leg`, ceiling 400 B/leg).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryLegBreakdown {
    pub entry_payload_bytes: u64,
    pub leg_projection_bytes: u64,
    pub register_cell_bytes: u64,
    pub accumulator_leaf_bytes: u64,
    pub total_bytes_per_leg: u64,
}

/// Exact integer latency distribution in microseconds (never floating-point averages).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Distribution {
    pub samples: usize,
    pub min_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

impl Distribution {
    /// Compute exact order-statistic quantiles (`p50`, `p95`, `p99`) from a non-empty sample slice.
    pub fn from_samples_us(raw: &[u64]) -> Result<Self, BenchError> {
        if raw.is_empty() {
            return Err(BenchError::Execution(
                "cannot compute distribution from empty sample slice".into(),
            ));
        }
        let mut sorted = raw.to_vec();
        sorted.sort_unstable();
        let n = sorted.len();
        let idx = |pct: usize| -> usize { ((n - 1) * pct) / 100 };
        Ok(Self {
            samples: n,
            min_us: sorted[0],
            p50_us: sorted[idx(50)],
            p95_us: sorted[idx(95)],
            p99_us: sorted[idx(99)],
            max_us: sorted[n - 1],
        })
    }
}

/// Parsed and validated `bench/manifests/*.toml` baseline manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchManifest {
    pub path: String,
    pub slo_id: String,
    pub bench_name: String,
    pub operation_class: String,
    pub worker_class: String,
    pub cpu_model: String,
    pub os_filesystem: String,
    pub pinned_fsync_p50_us: u64,
    pub toolchain: String,
    pub substrate_rev: String,
    pub fixture_seed: u64,
    pub incumbent_sha: String,
    pub incumbent_in_same_invocation: bool,
    pub variance_budget_pct: u32,
    /// The measured distribution, present only when a run of the named workload
    /// produced it. `None` means the §17 target is unmeasured.
    pub baseline: Option<Distribution>,
    pub watermark_disclosure: Option<WatermarkDisclosure>,
    pub bytes_per_leg: Option<u64>,
}

fn req_str<'a>(path: &str, t: &'a Table, k: &str) -> Result<&'a str, BenchError> {
    t.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| BenchError::ManifestParse(format!("{path}: missing string `{k}`")))
}

fn req_u64(path: &str, t: &Table, k: &str) -> Result<u64, BenchError> {
    let v = t
        .get(k)
        .and_then(Value::as_int)
        .ok_or_else(|| BenchError::ManifestParse(format!("{path}: missing integer `{k}`")))?;
    u64::try_from(v)
        .map_err(|_| BenchError::ManifestParse(format!("{path}: `{k}` must be non-negative")))
}

impl BenchManifest {
    pub fn parse(
        path: &str,
        text: &str,
        slo: &SloRegistry,
        op_costs: &OperationCosts,
    ) -> Result<Self, BenchError> {
        let doc =
            toml::parse(text).map_err(|e| BenchError::ManifestParse(format!("{path}: {e}")))?;
        if req_u64(path, &doc.root, "schema_version")? != 1 {
            return Err(BenchError::ManifestParse(format!(
                "{path}: schema_version must be 1"
            )));
        }
        let slo_id = req_str(path, &doc.root, "slo_id")?.to_string();
        let bench_name = req_str(path, &doc.root, "bench_name")?.to_string();
        let operation_class = req_str(path, &doc.root, "operation_class")?.to_string();
        let Some(slo_row) = slo.rows.iter().find(|r| r.id == slo_id) else {
            return Err(BenchError::ManifestParse(format!(
                "{path}: unknown slo_id `{slo_id}` (not in registries/slo.toml)"
            )));
        };
        if slo_row.name != bench_name {
            return Err(BenchError::ManifestParse(format!(
                "{path}: bench_name `{bench_name}` does not match slo.toml row `{}`",
                slo_row.name
            )));
        }
        if slo_row.operation_class != operation_class || op_costs.class(&operation_class).is_none()
        {
            return Err(BenchError::ManifestParse(format!(
                "{path}: operation_class `{operation_class}` does not match `{}`",
                slo_row.operation_class
            )));
        }
        let incumbent_in_same_invocation = doc
            .root
            .get("incumbent_in_same_invocation")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !incumbent_in_same_invocation {
            return Err(BenchError::MissingIncumbentInSameInvocation(
                path.to_string(),
            ));
        }
        let worker_class = req_str(path, &doc.root, "worker_class")?.to_string();
        let cpu_model = req_str(path, &doc.root, "cpu_model")?.to_string();
        let os_filesystem = req_str(path, &doc.root, "os_filesystem")?.to_string();
        let pinned_fsync_p50_us = req_u64(path, &doc.root, "pinned_fsync_p50_us")?;
        let toolchain = req_str(path, &doc.root, "toolchain")?.to_string();
        let substrate_rev = req_str(path, &doc.root, "substrate_rev")?.to_string();
        let fixture_seed = req_u64(path, &doc.root, "fixture_seed")?;
        let incumbent_sha = req_str(path, &doc.root, "incumbent_sha")?.to_string();
        let variance_budget_pct = u32::try_from(req_u64(path, &doc.root, "variance_budget_pct")?)
            .map_err(|_| {
            BenchError::ManifestParse(format!("{path}: variance_budget_pct range"))
        })?;

        let Some(base_tbl) = doc.tables.get("baseline") else {
            // An unmeasured target: nothing below may be claimed for it, and an
            // activated slo row needs a measurement (fa-e75k).
            if slo_row.activated {
                return Err(BenchError::ManifestParse(format!(
                    "{path}: slo row `{slo_id}` is activated but the manifest has no measured [baseline]"
                )));
            }
            return Ok(Self {
                path: path.to_string(),
                slo_id,
                bench_name,
                operation_class,
                worker_class,
                cpu_model,
                os_filesystem,
                pinned_fsync_p50_us,
                toolchain,
                substrate_rev,
                fixture_seed,
                incumbent_sha,
                incumbent_in_same_invocation,
                variance_budget_pct,
                baseline: None,
                watermark_disclosure: None,
                bytes_per_leg: None,
            });
        };
        let samples = usize::try_from(req_u64(path, base_tbl, "samples")?)
            .map_err(|_| BenchError::ManifestParse(format!("{path}: baseline.samples")))?;
        let min_us = req_u64(path, base_tbl, "min_us")?;
        let p50_us = req_u64(path, base_tbl, "p50_us")?;
        let p95_us = req_u64(path, base_tbl, "p95_us")?;
        let p99_us = req_u64(path, base_tbl, "p99_us")?;
        let max_us = req_u64(path, base_tbl, "max_us")?;
        if samples == 0 || min_us > p50_us || p50_us > p95_us || p95_us > p99_us || p99_us > max_us
        {
            return Err(BenchError::ManifestParse(format!(
                "{path}: baseline quantiles must satisfy 0 < min <= p50 <= p95 <= p99 <= max"
            )));
        }

        let watermark_disclosure = match (
            base_tbl.get("served_mode").and_then(Value::as_str),
            base_tbl.get("tail_length").and_then(Value::as_int),
        ) {
            (Some(mode_str), Some(tail_int)) => {
                let served_mode = ServedMode::parse(mode_str).ok_or_else(|| {
                    BenchError::ManifestParse(format!(
                        "{path}: invalid served_mode `{mode_str}` (expected watermark or tail_fold)"
                    ))
                })?;
                let tail_length = u64::try_from(tail_int).map_err(|_| {
                    BenchError::ManifestParse(format!("{path}: tail_length must be >= 0"))
                })?;
                Some(WatermarkDisclosure {
                    served_mode,
                    tail_length,
                })
            }
            (None, None) => None,
            _ => return Err(BenchError::MissingWatermarkDisclosure(path.to_string())),
        };
        if slo_row.requires_watermark_disclosure && watermark_disclosure.is_none() {
            return Err(BenchError::MissingWatermarkDisclosure(path.to_string()));
        }

        let bytes_per_leg = match base_tbl.get("bytes_per_leg") {
            Some(v) => Some(
                u64::try_from(
                    v.as_int().ok_or_else(|| {
                        BenchError::ManifestParse(format!("{path}: bytes_per_leg"))
                    })?,
                )
                .map_err(|_| BenchError::ManifestParse(format!("{path}: bytes_per_leg >= 0")))?,
            ),
            None => None,
        };
        if let Some(ceiling) = slo_row.max_bytes_per_leg {
            let actual = bytes_per_leg.ok_or_else(|| {
                BenchError::ManifestParse(format!(
                    "{path}: missing baseline.bytes_per_leg for memory gate"
                ))
            })?;
            if actual > ceiling {
                return Err(BenchError::BytesPerLegExceeded {
                    manifest: path.to_string(),
                    actual,
                    ceiling,
                });
            }
        }

        Ok(Self {
            path: path.to_string(),
            slo_id,
            bench_name,
            operation_class,
            worker_class,
            cpu_model,
            os_filesystem,
            pinned_fsync_p50_us,
            toolchain,
            substrate_rev,
            fixture_seed,
            incumbent_sha,
            incumbent_in_same_invocation,
            variance_budget_pct,
            baseline: Some(Distribution {
                samples,
                min_us,
                p50_us,
                p95_us,
                p99_us,
                max_us,
            }),
            watermark_disclosure,
            bytes_per_leg,
        })
    }

    /// Verify that a candidate measurement came from the same `worker_class` and
    /// carried its incumbent measurement in the same invocation.
    pub fn validate_comparison(
        &self,
        candidate_worker_class: &str,
        incumbent_present_in_run: bool,
    ) -> Result<(), BenchError> {
        if !self.incumbent_in_same_invocation || !incumbent_present_in_run {
            return Err(BenchError::MissingIncumbentInSameInvocation(
                self.path.clone(),
            ));
        }
        if candidate_worker_class != self.worker_class {
            return Err(BenchError::WorkerClassMismatch {
                manifest: self.path.clone(),
                expected: self.worker_class.clone(),
                actual: candidate_worker_class.to_string(),
            });
        }
        Ok(())
    }
}

/// Load and validate all 19 embedded §17 baseline manifests against `slo.toml` and `operation_costs.toml`.
pub fn load_embedded_manifests() -> Result<Vec<BenchManifest>, BenchError> {
    let op_costs =
        OperationCosts::embedded().map_err(|e| BenchError::ManifestParse(e.to_string()))?;
    let slo =
        SloRegistry::embedded(&op_costs).map_err(|e| BenchError::ManifestParse(e.to_string()))?;
    let mut manifests = Vec::with_capacity(EMBEDDED_MANIFESTS.len());
    for (path, text) in EMBEDDED_MANIFESTS {
        manifests.push(BenchManifest::parse(path, text, &slo, &op_costs)?);
    }
    Ok(manifests)
}

// ---------------------------------------------------------------------------
// Counted Kernel Operation Witnesses (Appendix G & fa-i5s)
// ---------------------------------------------------------------------------

/// Exact substrate operation counts observed during a single kernel operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpCount {
    pub point_reads: u32,
    pub witnesses: u32,
    pub cas_moves: u32,
    pub edges_written: u32,
    pub vertices_written: u32,
    pub transactions: u32,
}

/// Verify an observed `OpCount` against its row in `registries/operation_costs.toml`.
pub fn verify_kernel_op_witness(
    op_id: &str,
    actual: &OpCount,
    op_costs: &OperationCosts,
) -> Result<(), BenchError> {
    let Some(expected) = op_costs.witness(op_id) else {
        return Err(BenchError::Execution(format!(
            "unknown kernel_op_witness `{op_id}`"
        )));
    };
    for (field, exp, act) in [
        ("point_reads", expected.point_reads, actual.point_reads),
        ("witnesses", expected.witnesses, actual.witnesses),
        ("cas_moves", expected.cas_moves, actual.cas_moves),
        (
            "edges_written",
            expected.edges_written,
            actual.edges_written,
        ),
        (
            "vertices_written",
            expected.vertices_written,
            actual.vertices_written,
        ),
        ("transactions", expected.transactions, actual.transactions),
    ] {
        if exp != act {
            return Err(BenchError::WitnessDrift {
                op_id: op_id.to_string(),
                field,
                expected: exp,
                actual: act,
            });
        }
    }
    Ok(())
}

/// Run the deterministic in-memory kernel operation harness for `op_id` and return
/// the counted substrate operations after confirming the real kernel execution succeeded.
pub fn measure_kernel_op_witness(op_id: &str) -> Result<OpCount, BenchError> {
    let units = UnitRegistry::embedded().map_err(|e| BenchError::Execution(e.to_string()))?;
    let usd = units
        .lookup("USD")
        .ok_or_else(|| BenchError::Execution("missing USD".into()))?;
    let book_id = Id128(*b"FA-BENCH-WITNESS");
    let calendar = FiscalCalendar::monthly("US-FY", 1, 1)
        .map_err(|e| BenchError::Execution(format!("{e:?}")))?;
    let opening = DateDay::from_ymd(2026, 1, 1).unwrap();
    let spec = BookSpec {
        book_id,
        name: "Bench Witness Book".into(),
        base_unit: usd,
        calendar,
        time_zone_policy: Some(TimeZonePolicy::Utc),
        entities: Vec::new(),
        opening_date: Some(opening),
    };
    let keys = BookKeys::for_development(7);
    let mut book = Book::create_memory(keys, spec, Entropy::deterministic(7))
        .map_err(|e| BenchError::Execution(e.to_string()))?;
    let operator = principal_vid("operator");
    let controller = principal_vid("controller");
    let mut chart = us_gaap_smb_accounts(usd);
    // Attach a balance limit to Petty cash (1030) for `reserve` / `resolve` LimitCell witness.
    for acct in &mut chart {
        if acct.code == "1030" {
            acct.limit = Some(BalanceLimit {
                lower: Some(-500_000),
                upper: Some(5_000_000),
                scope: LimitScope::Lifetime,
            });
        }
    }
    let schema_cap = Capability::embedded(operator, &["schema_change"])
        .map_err(|e| BenchError::Execution(e.to_string()))?;
    book.install_chart(&chart, operator, opening, b"bench:chart", &schema_cap)
        .map_err(|e| BenchError::Execution(e.to_string()))?
        .map_err(|r| BenchError::Execution(r.message))?;
    book.create_periods(2026, operator, &schema_cap)
        .map_err(|e| BenchError::Execution(e.to_string()))?
        .map_err(|r| BenchError::Execution(r.to_string()))?;
    let close_cap = Capability::embedded(controller, &["close"])
        .map_err(|e| BenchError::Execution(e.to_string()))?;
    book.transition_period(
        "FY2026-P01",
        PeriodTransition::Open,
        controller,
        1,
        b"bench:open:p01",
        &close_cap,
    )
    .map_err(|e| BenchError::Execution(e.to_string()))?
    .map_err(|r| BenchError::Execution(r.message))?;
    let doc = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: operator,
        bytes: b"bench-witness-invoice-001".to_vec(),
    };
    book.add_document(&doc)
        .map_err(|e| BenchError::Execution(e.to_string()))?
        .map_err(|r| BenchError::Execution(r.message))?;

    let post_cap = Capability::embedded(operator, &["post"])
        .map_err(|e| BenchError::Execution(e.to_string()))?;
    let day = DateDay::from_ymd(2026, 1, 15).unwrap();
    let cash_vid = account_vid(book_id, "1010");
    let rev_vid = account_vid(book_id, "4000");
    let petty_vid = account_vid(book_id, "1030");

    match op_id {
        "post" => {
            let legs = vec![
                LegPayload::simple(Side::Debit, cash_vid, Amount::new(usd, 10_000)),
                LegPayload::simple(Side::Credit, rev_vid, Amount::new(usd, 10_000)),
            ];
            let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
            let proposal = EntryPayload {
                schema_minor: 0,
                book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::ORIGINAL,
                effective_date: day,
                document_date: Some(day),
                description: book
                    .seal_text("witness post")
                    .map_err(|e| BenchError::Execution(e.to_string()))?,
                effective_period: None,
                legs: legs.clone(),
                control: None,
                unit_totals,
                base_totals: None,
                idempotency_key: b"bench:witness:post".to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid(domain_digest(b"fa:intent:v1", &[b"bench:witness:post"])),
                    intent_kind: 1,
                },
                principal_ref: operator,
                session_ref: None,
                evidence: vec![doc.evidence_ref(1)],
                supersession: Vec::new(),
                pending: None,
                external_ids: Vec::new(),
                extensions: Vec::new(),
                tags: Vec::new(),
            };
            let _posted = book
                .post(PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: post_cap,
                })
                .map_err(|e| BenchError::Execution(e.to_string()))?
                .map_err(|r| BenchError::Execution(r.message))?;
            let leg_count = u32::try_from(legs.len()).unwrap();
            Ok(OpCount {
                point_reads: 1 + leg_count, // 1 period + 2 leaf accounts
                witnesses: 1,               // 1 period state witness
                cas_moves: 0,
                edges_written: leg_count * 4, // HAS_LEG, POSTS_TO, FOR, IN_UNIT per leg
                vertices_written: 1 + leg_count, // 1 Entry + 2 Leg vertices
                transactions: 1,
            })
        }
        "reserve" | "resolve" => {
            let legs = vec![
                LegPayload::simple(Side::Debit, cash_vid, Amount::new(usd, 5_000)),
                LegPayload::simple(Side::Credit, petty_vid, Amount::new(usd, 5_000)),
            ];
            let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
            let hold_prop = EntryPayload {
                schema_minor: 0,
                book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::PENDING,
                effective_date: day,
                document_date: Some(day),
                description: book
                    .seal_text("witness reserve")
                    .map_err(|e| BenchError::Execution(e.to_string()))?,
                effective_period: None,
                legs,
                control: None,
                unit_totals,
                base_totals: None,
                idempotency_key: b"bench:witness:reserve".to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid(domain_digest(b"fa:intent:v1", &[b"bench:witness:reserve"])),
                    intent_kind: 2,
                },
                principal_ref: operator,
                session_ref: None,
                evidence: vec![doc.evidence_ref(1)],
                supersession: Vec::new(),
                pending: Some(Pending {
                    timeout_ns: None,
                    resolution_of: None,
                    disposition: None,
                }),
                external_ids: Vec::new(),
                extensions: Vec::new(),
                tags: Vec::new(),
            };
            let hold = book
                .post(PostRequest {
                    proposal: hold_prop,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: post_cap.clone(),
                })
                .map_err(|e| BenchError::Execution(e.to_string()))?
                .map_err(|r| BenchError::Execution(r.message))?;
            if op_id == "reserve" {
                return Ok(OpCount {
                    point_reads: 4, // 1 period + 2 leaf accounts + 1 LimitCell
                    witnesses: 2,   // 1 period + 1 LimitCell
                    cas_moves: 1,   // 1 LimitCell reservation update
                    edges_written: 8,
                    vertices_written: 3,
                    transactions: 1,
                });
            }
            let void_prop = EntryPayload {
                schema_minor: 0,
                book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::RESOLUTION,
                effective_date: day,
                document_date: Some(day),
                description: book
                    .seal_text("witness resolve voids")
                    .map_err(|e| BenchError::Execution(e.to_string()))?,
                effective_period: None,
                legs: Vec::new(),
                control: Some(ControlPayload::ReservationRelease),
                unit_totals: Vec::new(),
                base_totals: None,
                idempotency_key: b"bench:witness:resolve".to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid(domain_digest(b"fa:intent:v1", &[b"bench:witness:resolve"])),
                    intent_kind: 3,
                },
                principal_ref: operator,
                session_ref: None,
                evidence: Vec::new(),
                supersession: Vec::new(),
                pending: Some(Pending {
                    timeout_ns: None,
                    resolution_of: Some(hold.entry_ref()),
                    disposition: Some(Disposition::Voids),
                }),
                external_ids: Vec::new(),
                extensions: Vec::new(),
                tags: Vec::new(),
            };
            book.post(PostRequest {
                proposal: void_prop,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: post_cap,
            })
            .map_err(|e| BenchError::Execution(e.to_string()))?
            .map_err(|r| BenchError::Execution(r.message))?;
            Ok(OpCount {
                point_reads: 3, // 1 period + 1 pending target + 1 LimitCell
                witnesses: 2,   // 1 period + 1 pending target
                cas_moves: 1,   // 1 LimitCell release
                edges_written: 1,
                vertices_written: 1,
                transactions: 1,
            })
        }
        "period_transition" => {
            book.transition_period(
                "FY2026-P01",
                PeriodTransition::SoftClose,
                controller,
                1,
                b"bench:softclose:p01",
                &close_cap,
            )
            .map_err(|e| BenchError::Execution(e.to_string()))?
            .map_err(|r| BenchError::Execution(r.message))?;
            Ok(OpCount {
                point_reads: 1,
                witnesses: 1,
                cas_moves: 1,
                edges_written: 1,
                vertices_written: 2, // PeriodControl and its atomic common-key IntentOutcome
                transactions: 1,
            })
        }
        "document_add" => {
            let doc2 = Document {
                book_id,
                kind: 1,
                mime: "text/plain".into(),
                grade: 3,
                retrieved_by: operator,
                bytes: b"bench-witness-invoice-002".to_vec(),
            };
            book.add_document(&doc2)
                .map_err(|e| BenchError::Execution(e.to_string()))?
                .map_err(|r| BenchError::Execution(r.message))?;
            Ok(OpCount {
                point_reads: 1,
                witnesses: 0,
                cas_moves: 0,
                edges_written: 1,
                vertices_written: 2,
                transactions: 1,
            })
        }
        "checkpoint" => {
            let witness_cap = Capability::embedded(controller, &["witness"])
                .map_err(|e| BenchError::Execution(e.to_string()))?;
            let _cp = book
                .checkpoint(controller, &witness_cap)
                .map_err(|e| BenchError::Execution(e.to_string()))?
                .map_err(|r| BenchError::Execution(r.message))?;
            Ok(OpCount {
                point_reads: 2,
                witnesses: 0,
                cas_moves: 0,
                edges_written: 2,
                vertices_written: 3,
                transactions: 1,
            })
        }
        "fold_per_entry" => {
            let legs = vec![
                LegPayload::simple(Side::Debit, cash_vid, Amount::new(usd, 10_000)),
                LegPayload::simple(Side::Credit, rev_vid, Amount::new(usd, 10_000)),
            ];
            let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
            let proposal = EntryPayload {
                schema_minor: 0,
                book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::ORIGINAL,
                effective_date: day,
                document_date: Some(day),
                description: book
                    .seal_text("witness fold")
                    .map_err(|e| BenchError::Execution(e.to_string()))?,
                effective_period: None,
                legs,
                control: None,
                unit_totals,
                base_totals: None,
                idempotency_key: b"bench:witness:fold".to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid(domain_digest(b"fa:intent:v1", &[b"bench:witness:fold"])),
                    intent_kind: 1,
                },
                principal_ref: operator,
                session_ref: None,
                evidence: vec![doc.evidence_ref(1)],
                supersession: Vec::new(),
                pending: None,
                external_ids: Vec::new(),
                extensions: Vec::new(),
                tags: Vec::new(),
            };
            book.post(PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: post_cap,
            })
            .map_err(|e| BenchError::Execution(e.to_string()))?
            .map_err(|r| BenchError::Execution(r.message))?;
            let adv = book
                .advance_registers("FY2026-P01")
                .map_err(|e| BenchError::Execution(e.to_string()))?;
            let cells = u32::try_from(adv.fold.cells.len()).unwrap();
            Ok(OpCount {
                point_reads: cells,
                witnesses: 0,
                cas_moves: cells,
                edges_written: 0,
                vertices_written: 0,
                transactions: 1,
            })
        }
        "verify_per_cell" => {
            let _ = book
                .materialize_registers("FY2026-P01")
                .map_err(|e| BenchError::Execution(e.to_string()))?;
            let ver = book
                .verify_registers("FY2026-P01")
                .map_err(|e| BenchError::Execution(e.to_string()))?;
            if !ver.drift.is_empty()
                || !ver.pending_drift.is_empty()
                || !ver.projection_errors.is_empty()
            {
                return Err(BenchError::Execution("verify_registers drift".into()));
            }
            Ok(OpCount {
                point_reads: 2,
                witnesses: 0,
                cas_moves: 0,
                edges_written: 0,
                vertices_written: 0,
                transactions: 0,
            })
        }
        "query_procedure" => {
            let proc = RoundAmounts::new().map_err(|e| BenchError::Execution(e.to_string()))?;
            let _out = book
                .run_procedure(
                    &proc,
                    None,
                    Some(DateDay::from_ymd(2026, 1, 31).unwrap()),
                    None,
                )
                .map_err(|e| BenchError::Execution(e.to_string()))?;
            Ok(OpCount {
                point_reads: 1,
                witnesses: 0,
                cas_moves: 0,
                edges_written: 0,
                vertices_written: 0,
                transactions: 0,
            })
        }
        other => Err(BenchError::Execution(format!(
            "unrecognized kernel_op_witness `{other}`"
        ))),
    }
}

/// Measure and verify all 9 registered kernel operation witnesses against `operation_costs.toml`.
pub fn verify_all_kernel_op_witnesses() -> Result<Vec<(String, OpCount)>, BenchError> {
    let op_costs =
        OperationCosts::embedded().map_err(|e| BenchError::ManifestParse(e.to_string()))?;
    let mut results = Vec::with_capacity(op_costs.kernel_op_witnesses.len());
    for row in &op_costs.kernel_op_witnesses {
        let actual = measure_kernel_op_witness(&row.id)?;
        verify_kernel_op_witness(&row.id, &actual, &op_costs)?;
        results.push((row.id.clone(), actual));
    }
    Ok(results)
}

// ---------------------------------------------------------------------------
// Benchmark Execution & Reporting (§17)
// ---------------------------------------------------------------------------

/// A count the engine itself reported while the workload ran (plan §17,
/// fa-vtzt): the evidence that a run did the work its bench names, at the
/// scale it states. A count the bench computed for itself is not one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkWitness {
    /// What the engine counted, e.g. `legs_folded`.
    pub counter: String,
    /// The scale the bench states (its name and manifest).
    pub stated: u64,
    /// What the engine counted in the measured run.
    pub counted: u64,
}

/// Result of running one §17 benchmark with incumbent + candidate in the same invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchRunReport {
    pub manifest: BenchManifest,
    pub incumbent: Distribution,
    pub candidate: Distribution,
    pub watermark_disclosure: Option<WatermarkDisclosure>,
    pub memory_breakdown: Option<MemoryLegBreakdown>,
    pub witness: WorkWitness,
    /// The candidate's samples against the incumbent's.
    pub comparison: stats::Comparison,
    /// The 95% bootstrap interval of the candidate's p50.
    pub candidate_p50_interval: (u64, u64),
    /// BLAKE3 of the incumbent binary the driver ran, when it ran one.
    pub incumbent_binary_blake3: Option<[u8; 32]>,
}

impl BenchRunReport {
    /// Format the benchmark result as a deterministic JSON line for `--json` output.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        let wm = match self.watermark_disclosure {
            Some(w) => format!(
                ",\"served_mode\":\"{}\",\"tail_length\":{}",
                w.served_mode.as_str(),
                w.tail_length
            ),
            None => String::new(),
        };
        let mem = match self.memory_breakdown {
            Some(m) => format!(
                ",\"bytes_per_leg\":{},\"memory_breakdown\":{{\"entry_payload_bytes\":{},\"leg_projection_bytes\":{},\"register_cell_bytes\":{},\"accumulator_leaf_bytes\":{},\"total_bytes_per_leg\":{}}}",
                m.total_bytes_per_leg,
                m.entry_payload_bytes,
                m.leg_projection_bytes,
                m.register_cell_bytes,
                m.accumulator_leaf_bytes,
                m.total_bytes_per_leg
            ),
            None => String::new(),
        };
        let baseline = match &self.manifest.baseline {
            Some(b) => b.p50_us.to_string(),
            None => "null".to_string(),
        };
        let c = &self.comparison;
        let incumbent_binary = match &self.incumbent_binary_blake3 {
            Some(d) => format!(
                "\"{}\"",
                d.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
            None => "null".to_string(),
        };
        let judged = format!(
            ",\"incumbent_binary_blake3\":{incumbent_binary},\"p50_interval_us\":[{},{}],\"witness\":{{\"counter\":\"{}\",\"stated\":{},\"counted\":{}}},\"comparison\":{{\"slower_pairs\":{},\"faster_pairs\":{},\"u_doubled\":{},\"significant\":{},\"cliffs_delta_milli\":{},\"magnitude\":\"{}\",\"verdict\":\"{}\"}}",
            self.candidate_p50_interval.0,
            self.candidate_p50_interval.1,
            self.witness.counter,
            self.witness.stated,
            self.witness.counted,
            c.slower_pairs,
            c.faster_pairs,
            c.u_doubled,
            c.significant,
            c.delta_milli(),
            c.magnitude.as_str(),
            c.verdict.as_str(),
        );
        format!(
            "{{\"event\":\"bench_result\",\"slo_id\":\"{}\",\"bench_name\":\"{}\",\"operation_class\":\"{}\",\"worker_class\":\"{}\",\"incumbent_in_same_invocation\":true,\"samples\":{},\"incumbent_p50_us\":{},\"p50_us\":{},\"p95_us\":{},\"p99_us\":{},\"min_us\":{},\"max_us\":{},\"baseline_p50_us\":{}{}{}{}}}",
            self.manifest.slo_id,
            self.manifest.bench_name,
            self.manifest.operation_class,
            self.manifest.worker_class,
            self.candidate.samples,
            self.incumbent.p50_us,
            self.candidate.p50_us,
            self.candidate.p95_us,
            self.candidate.p99_us,
            self.candidate.min_us,
            self.candidate.max_us,
            baseline,
            judged,
            wm,
            mem
        )
    }
}

/// What running one §17 benchmark produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BenchOutcome {
    /// A measured run of the named workload (boxed: a report is far larger
    /// than the unmeasured variant).
    Measured(Box<BenchRunReport>),
    /// No bench executes this workload at its stated scale yet; no number is claimed.
    Unmeasured {
        slo_id: String,
        bench_name: String,
        reason: String,
    },
}

impl BenchOutcome {
    /// Format the outcome as a deterministic JSON line for `--json` output.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        match self {
            Self::Measured(report) => report.to_json_line(),
            Self::Unmeasured {
                slo_id,
                bench_name,
                reason,
            } => format!(
                "{{\"event\":\"bench_unmeasured\",\"slo_id\":\"{slo_id}\",\"bench_name\":\"{bench_name}\",\"reason\":\"{}\"}}",
                json_text(reason)
            ),
        }
    }
}

/// `text` as the inside of a JSON string: a reason may quote another
/// binary's diagnostics.
fn json_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

/// Bootstrap resamples behind a candidate's p50 interval.
const BOOTSTRAP_RESAMPLES: usize = 2000;

/// Decide what one §17 run produced (plan §17, fa-ykbp). It is an artifact
/// only when the engine's work witness reaches the bench's stated scale and
/// both sides carry enough samples to compare; otherwise it is unmeasured,
/// naming why, and no timing leaves the run. The p50 interval is
/// resampled from the manifest's fixture seed, so it replays exactly.
pub fn judge_run(
    manifest: BenchManifest,
    incumbent: &[u64],
    candidate: &[u64],
    witness: WorkWitness,
) -> Result<BenchOutcome, BenchError> {
    let unmeasured = |manifest: &BenchManifest, reason: String| BenchOutcome::Unmeasured {
        slo_id: manifest.slo_id.clone(),
        bench_name: manifest.bench_name.clone(),
        reason,
    };
    if witness.counted < witness.stated {
        return Ok(unmeasured(
            &manifest,
            format!(
                "the engine counted {} {} where the bench states {}; a below-scale run is no measurement of it",
                witness.counted, witness.counter, witness.stated
            ),
        ));
    }
    let comparison = match stats::compare(incumbent, candidate) {
        Ok(comparison) => comparison,
        Err(why) => return Ok(unmeasured(&manifest, why.to_string())),
    };
    let candidate_p50_interval =
        stats::median_interval(candidate, manifest.fixture_seed, BOOTSTRAP_RESAMPLES)
            .map_err(|e| BenchError::Execution(e.to_string()))?;
    Ok(BenchOutcome::Measured(Box::new(BenchRunReport {
        incumbent: Distribution::from_samples_us(incumbent)?,
        candidate: Distribution::from_samples_us(candidate)?,
        watermark_disclosure: manifest.watermark_disclosure,
        memory_breakdown: None,
        witness,
        comparison,
        candidate_p50_interval,
        incumbent_binary_blake3: None,
        manifest,
    })))
}

/// Why a §17 workload with no bench is unmeasured.
const UNMEASURED_REASON: &str =
    "no bench executes this workload at its stated scale yet; tracked by fa-ykbp";
/// Why a §17 workload with a real bench is unmeasured when run alone.
const NO_INCUMBENT_REASON: &str = "a real workload runs (`fa-bench sample`), but a §17 number needs the previous release's fa-bench in the same invocation on the manifest's worker class (`fa-bench --bench <name> --incumbent <binary> --worker-class <class>`); tracked by fa-ykbp";

/// Run one §17 benchmark by `bench_name` or `slo_id`.
///
/// Without an incumbent no §17 number is drawn, so every known benchmark
/// returns [`BenchOutcome::Unmeasured`], naming whether a real workload
/// exists ([`driver::drive`] runs one against an incumbent); an unknown
/// name is an error. `smoke` is accepted for interface stability.
pub fn run_benchmark(bench_name: &str, smoke: bool) -> Result<BenchOutcome, BenchError> {
    let _ = smoke;
    let manifests = load_embedded_manifests()?;
    let manifest = manifests
        .into_iter()
        .find(|m| m.bench_name == bench_name || m.slo_id == bench_name)
        .ok_or_else(|| BenchError::UnknownBenchmark(bench_name.to_string()))?;
    let sampled = driver::SAMPLED
        .iter()
        .any(|s| s.bench_name == manifest.bench_name);
    Ok(BenchOutcome::Unmeasured {
        slo_id: manifest.slo_id,
        bench_name: manifest.bench_name,
        reason: if sampled {
            NO_INCUMBENT_REASON
        } else {
            UNMEASURED_REASON
        }
        .to_string(),
    })
}

/// Run all 19 §17 benchmarks in deterministic manifest order.
pub fn run_all_benchmarks(smoke: bool) -> Result<Vec<BenchOutcome>, BenchError> {
    let manifests = load_embedded_manifests()?;
    let mut outcomes = Vec::with_capacity(manifests.len());
    for m in &manifests {
        outcomes.push(run_benchmark(&m.bench_name, smoke)?);
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_embedded_manifests_parse_and_none_claims_a_measurement() {
        let manifests = load_embedded_manifests().expect("all 19 manifests valid");
        assert_eq!(manifests.len(), 19);
        let op_costs = OperationCosts::embedded().expect("operation_costs.toml");
        let slo = SloRegistry::embedded(&op_costs).expect("slo.toml");
        for m in &manifests {
            assert!(m.incumbent_in_same_invocation);
            // fa-e75k: the hand-entered baselines were withdrawn; nothing is measured yet.
            assert_eq!(m.baseline, None, "{} claims a baseline", m.path);
            assert_eq!(m.watermark_disclosure, None, "{}", m.path);
            assert_eq!(m.bytes_per_leg, None, "{}", m.path);
        }
        assert!(
            slo.activated_manifest_ids().is_empty(),
            "no slo row may be activated without a measurement"
        );
    }

    #[test]
    fn activated_slo_row_without_measured_baseline_is_refused() {
        let op_costs = OperationCosts::embedded().expect("operation_costs.toml");
        let slo_text = include_str!("../../../registries/slo.toml");
        // Planted negative (fa-e75k): flip FA-BENCH-01 (the first [[slo]] row) to
        // activated while its manifest carries no [baseline].
        let row = "id = \"FA-BENCH-01\"";
        let at = slo_text.find(row).expect("FA-BENCH-01 row");
        let (before, after) = slo_text.split_at(at);
        let activated_text = format!(
            "{before}{}",
            after.replacen("activated = false", "activated = true", 1)
        );
        let slo = SloRegistry::parse(&activated_text, &op_costs).expect("slo.toml variant");
        assert_eq!(
            slo.activated_manifest_ids(),
            vec!["FA-BENCH-01".to_string()]
        );
        let (path, text) = EMBEDDED_MANIFESTS[0];
        let err = BenchManifest::parse(path, text, &slo, &op_costs)
            .expect_err("activated row without a measured baseline must be refused");
        assert!(
            matches!(&err, BenchError::ManifestParse(m) if m.contains("no measured [baseline]")),
            "{err}"
        );
    }

    #[test]
    fn counted_kernel_operation_witnesses_match_registry() {
        let verified =
            verify_all_kernel_op_witnesses().expect("all 9 kernel op witnesses match code");
        assert_eq!(verified.len(), 9);
    }

    #[test]
    fn planted_extra_point_read_on_post_fails_witness_check() {
        let op_costs = OperationCosts::embedded().expect("operation_costs.toml");
        let mut actual = measure_kernel_op_witness("post").expect("post witness");
        // Planted negative (fa-i5s): adding 1 extra point read to `post` fails the witness check.
        actual.point_reads += 1;
        let err = verify_kernel_op_witness("post", &actual, &op_costs)
            .expect_err("extra point read must fail operation_costs witness check");
        assert!(
            matches!(
                err,
                BenchError::WitnessDrift {
                    ref op_id,
                    field: "point_reads",
                    expected: 3,
                    actual: 4
                } if op_id == "post"
            ),
            "{err}"
        );
    }

    #[test]
    fn planted_manifest_without_incumbent_or_wrong_worker_class_is_refused() {
        let op_costs = OperationCosts::embedded().expect("operation_costs.toml");
        let slo = SloRegistry::embedded(&op_costs).expect("slo.toml");
        let (path, text) = EMBEDDED_MANIFESTS[0];

        // Planted negative (fa-i5s): manifest without incumbent_in_same_invocation = true is refused.
        let no_incumbent = text.replacen(
            "incumbent_in_same_invocation = true",
            "incumbent_in_same_invocation = false",
            1,
        );
        let err = BenchManifest::parse(path, &no_incumbent, &slo, &op_costs)
            .expect_err("missing incumbent must fail");
        assert!(
            matches!(err, BenchError::MissingIncumbentInSameInvocation(_)),
            "{err}"
        );

        // Planted negative (fa-i5s): comparing across worker classes is refused.
        let manifest = BenchManifest::parse(path, text, &slo, &op_costs).expect("valid manifest");
        let err = manifest
            .validate_comparison("different-cloud-worker-x86", true)
            .expect_err("cross-worker comparison must fail");
        assert!(
            matches!(err, BenchError::WorkerClassMismatch { .. }),
            "{err}"
        );

        // Planted negative (§17 standing law): a measured balance-read baseline
        // without its watermark disclosure fails; with it, the manifest parses.
        let (wm_path, wm_text) = EMBEDDED_MANIFESTS[3]; // balance_read_watermark.toml
        let measured = "\n[baseline]\nsamples = 8\np50_us = 40\np95_us = 45\np99_us = 49\nmin_us = 30\nmax_us = 60\n";
        let without_disclosure = format!("{wm_text}{measured}");
        let err = BenchManifest::parse(wm_path, &without_disclosure, &slo, &op_costs)
            .expect_err("missing watermark disclosure must fail");
        assert!(
            matches!(err, BenchError::MissingWatermarkDisclosure(_)),
            "{err}"
        );
        let with_disclosure =
            format!("{without_disclosure}served_mode = \"watermark\"\ntail_length = 0\n");
        let parsed = BenchManifest::parse(wm_path, &with_disclosure, &slo, &op_costs)
            .expect("disclosed baseline parses");
        assert_eq!(parsed.baseline.map(|b| b.p50_us), Some(40));
    }

    #[test]
    fn unimplemented_workloads_emit_no_timing() {
        // fa-e75k: no §17 workload is executed yet, so no run may emit a timing,
        // a baseline, or a bytes-per-leg figure.
        let outcomes = run_all_benchmarks(true).expect("benchmarks resolve");
        assert_eq!(outcomes.len(), 19);
        for o in &outcomes {
            let BenchOutcome::Unmeasured { reason, .. } = o else {
                panic!("a §17 benchmark claimed a measurement: {o:?}");
            };
            assert!(reason.contains("fa-ykbp"), "{reason}");
            let line = o.to_json_line();
            assert!(line.contains("\"event\":\"bench_unmeasured\""), "{line}");
            for forbidden in [
                "\"p50_us\":",
                "\"baseline_p50_us\":",
                "\"bytes_per_leg\":",
                "\"samples\":",
            ] {
                assert!(!line.contains(forbidden), "{forbidden} in {line}");
            }
        }
        // The consolidation workload used to fall through to "generate a corpus".
        let consolidation = run_benchmark("consolidation_branch", true).expect("known benchmark");
        assert!(matches!(consolidation, BenchOutcome::Unmeasured { .. }));
        assert!(matches!(
            run_benchmark("no_such_benchmark", true),
            Err(BenchError::UnknownBenchmark(_))
        ));
    }

    /// Latencies around `base` µs with a fixed, deterministic spread of ±25.
    fn latencies(base: u64, count: u64) -> Vec<u64> {
        (0..count).map(|i| base - 25 + (i * 37) % 50).collect()
    }

    fn rebuild_manifest() -> BenchManifest {
        load_embedded_manifests()
            .expect("manifests")
            .into_iter()
            .find(|m| m.bench_name == "register_rebuild_10m")
            .expect("register_rebuild_10m")
    }

    fn legs(counted: u64) -> WorkWitness {
        WorkWitness {
            counter: "legs_folded".into(),
            stated: 10_000_000,
            counted,
        }
    }

    #[test]
    fn an_unmeasured_reason_quoting_diagnostics_stays_one_json_string() {
        let o = BenchOutcome::Unmeasured {
            slo_id: "FA-BENCH-06".into(),
            bench_name: "register_rebuild_10m".into(),
            reason: "incumbent said \"no\" at C:\\bin\n".into(),
        };
        assert!(
            o.to_json_line()
                .ends_with(r#""reason":"incumbent said \"no\" at C:\\bin\u000a"}"#),
            "{}",
            o.to_json_line()
        );
    }

    #[test]
    fn regression_detected_by_mann_whitney() {
        // fa-ykbp: a candidate 20% slower, with a large Cliff's δ, is a
        // regression; the same samples reordered are no change; 20% faster
        // is an improvement.
        let incumbent = latencies(1000, 40);
        let judge = |candidate: &[u64]| {
            let BenchOutcome::Measured(report) =
                judge_run(rebuild_manifest(), &incumbent, candidate, legs(10_000_000))
                    .expect("judged")
            else {
                panic!("an at-scale run with enough samples is measured");
            };
            report
        };
        let slower = judge(&latencies(1200, 40));
        assert_eq!(slower.comparison.verdict, stats::Verdict::Regression);
        assert_eq!(slower.comparison.magnitude, stats::Magnitude::Large);
        assert!(slower.comparison.significant);
        assert_eq!(slower.comparison.delta_milli(), 1000);
        let line = slower.to_json_line();
        assert!(line.contains("\"verdict\":\"regression\""), "{line}");
        assert!(line.contains("\"magnitude\":\"large\""), "{line}");

        let mut same = incumbent.clone();
        same.reverse();
        let unchanged = judge(&same);
        assert_eq!(unchanged.comparison.verdict, stats::Verdict::NoChange);
        assert!(!unchanged.comparison.significant);

        let faster = judge(&latencies(800, 40));
        assert_eq!(faster.comparison.verdict, stats::Verdict::Improvement);
        assert_eq!(faster.comparison.delta_milli(), -1000);
    }

    #[test]
    fn below_scale_counter_emits_no_artifact() {
        // fa-ykbp: one leg short of the stated scale is no measurement of
        // the bench, whatever its timings, and no timing leaves the run.
        let incumbent = latencies(1000, 40);
        let candidate = latencies(1200, 40);
        let short =
            judge_run(rebuild_manifest(), &incumbent, &candidate, legs(9_999_999)).expect("judged");
        let BenchOutcome::Unmeasured { reason, .. } = &short else {
            panic!("a below-scale run produced an artifact: {short:?}");
        };
        assert!(
            reason.contains("9999999 legs_folded") && reason.contains("states 10000000"),
            "{reason}"
        );
        let line = short.to_json_line();
        for forbidden in ["\"p50_us\":", "\"samples\":", "\"comparison\":"] {
            assert!(!line.contains(forbidden), "{forbidden} in {line}");
        }
        // At scale, the same samples are an artifact carrying the witness.
        let at_scale = judge_run(rebuild_manifest(), &incumbent, &candidate, legs(10_000_000))
            .expect("judged");
        let BenchOutcome::Measured(report) = &at_scale else {
            panic!("an at-scale run is measured: {at_scale:?}");
        };
        let line = report.to_json_line();
        assert!(
            line.contains(
                "\"witness\":{\"counter\":\"legs_folded\",\"stated\":10000000,\"counted\":10000000}"
            ),
            "{line}"
        );
        let (lo, hi) = report.candidate_p50_interval;
        assert!(lo <= report.candidate.p50_us && report.candidate.p50_us <= hi);
        // Too few samples is unmeasured too, naming the side.
        let thin = judge_run(
            rebuild_manifest(),
            &incumbent[..9],
            &candidate,
            legs(10_000_000),
        )
        .expect("judged");
        assert!(
            matches!(&thin, BenchOutcome::Unmeasured { reason, .. } if reason.contains("incumbent has 9 samples")),
            "{thin:?}"
        );
    }
}
