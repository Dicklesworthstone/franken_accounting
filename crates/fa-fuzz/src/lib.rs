#![forbid(unsafe_code)]
//! Fuzz targets, deterministic PRNG mutator, checked-in seed corpus loader,
//! and smoke runner for FrankenAccounting (plan §16.8, bead `fa-tre`).
//!
//! Every live decoder and syntax parser in the workspace has a registered
//! target in [`LIVE_TARGETS`]. Dormant targets for subsystems not yet active
//! are registered in [`DORMANT_TARGETS`] with their activating bead IDs.
//!
//! Invariant under test across every target:
//! - Arbitrary byte sequences never trigger a panic (`unwrap()`, `expect()`,
//!   slice index out of bounds, arithmetic overflow, or `unreachable!()`).
//! - Every successful decode that supports canonical re-encoding satisfies the
//!   decode-encode-decode fixed-point property.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use fa::{
    AgingCertificate, AgingReconciliationCertificate, AllocationReview, BalanceAllocationReview,
    BalanceRequest, Book, BookKeys, BundleRequest, BundleScope, CashFlowCertificate, Entropy,
    IndirectCashFlowCertificate, PlanCertificate, PostIntent, PostPlan, ProofKind, ProofRequest,
    ReportCertificate, RollForwardCertificate, SettlementGroupReview, SettlementReview,
    StatementDiffCertificate, SummaryCertificate, TrialBalanceSelection,
};
use fa_journal::{
    AccountSpec, BookSpec, Capability, Document, PostRequest, RedactedView, RunBody,
    TransitionPlan, UnitPolicy,
};
use fa_model::{
    Entry, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, UnitDefinition,
    account_vid,
};
use fa_money::{Amount, Side, UnitRegistry};
use fa_notary::{AccumulatorState, ProductionReceipt, Statement, TransparencyCheckpoint};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::sod_policy::SodPolicy;
use fa_registry::topology::Topology;
use fa_registry::{Admissibility, EntryClasses, ExitCodes};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::VId;

/// A registered live fuzz target.
#[derive(Clone, Copy, Debug)]
pub struct FuzzTarget {
    pub name: &'static str,
    pub description: &'static str,
    pub run: fn(&[u8]),
}

/// A dormant fuzz target registered with its activating bead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DormantTarget {
    pub name: &'static str,
    pub activating_bead: &'static str,
    pub description: &'static str,
}

/// Live fuzz targets exercised by `cargo test -p fa-fuzz` and `fa-fuzz-smoke`.
pub const LIVE_TARGETS: &[FuzzTarget] = &[
    FuzzTarget {
        name: "entry_codec",
        description: "Entry::decode and EntryPayload canonical_bytes round-trip fixed-point without panic",
        run: fuzz_entry_codec,
    },
    FuzzTarget {
        name: "payload_decoders",
        description: "Every model, journal, certificate, plan, and review byte decoder without panic",
        run: fuzz_payload_decoders,
    },
    FuzzTarget {
        name: "notary_state_and_proofs",
        description: "AccumulatorState, TransparencyCheckpoint, ProductionReceipt, and envelope decoders without panic",
        run: fuzz_notary_state_and_proofs,
    },
    FuzzTarget {
        name: "fa_verify_inputs",
        description: "Dependency-free fa-verify checkpoint, proof, bundle, redaction, and disclosure verifiers without panic",
        run: fuzz_fa_verify_inputs,
    },
    FuzzTarget {
        name: "registry_toml",
        description: "TOML parser and all embedded registry schema parsers on arbitrary UTF-8/bytes without panic",
        run: fuzz_registry_toml,
    },
    FuzzTarget {
        name: "cli_args",
        description: "CLI argv tokenizer, flag parser, alias expander, and syntax validators without panic",
        run: fuzz_cli_args,
    },
    FuzzTarget {
        name: "chart_import_json",
        description: "Closed-universe JSON parser and chart spec importer without panic",
        run: fuzz_chart_import_json,
    },
    FuzzTarget {
        name: "legacy_gl_formats",
        description: "Legacy GL export readers (QuickBooks IIF/CSV, Xero CSV, NetSuite CSV, Generic GL CSV) and column-map parser without panic",
        run: fuzz_legacy_gl_formats,
    },
];

/// Dormant fuzz targets registered per `fa-tre` with their activating beads.
pub const DORMANT_TARGETS: &[DormantTarget] = &[
    DormantTarget {
        name: "bundle",
        activating_bead: "fa-795",
        description: "Dedicated .fab bundle container fuzzer (currently covered inside fa_verify_inputs)",
    },
    DormantTarget {
        name: "certificate",
        activating_bead: "fa-a6h",
        description: "Dedicated report certificate fuzzer (currently covered inside payload_decoders)",
    },
    DormantTarget {
        name: "canon_source",
        activating_bead: "fa-0t0",
        description: "Canon posting rule DSL parser and compiler fuzzer",
    },
    DormantTarget {
        name: "mcp_args",
        activating_bead: "fa-23r",
        description: "MCP tool JSON argument envelope fuzzer",
    },
];

/// Summary of a smoke run across one or all targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmokeSummary {
    pub targets_run: usize,
    pub corpus_inputs: usize,
    pub mutated_inputs: usize,
}

/// Deterministic xorshift64* PRNG for reproducible fuzz mutation campaigns.
#[derive(Clone, Debug)]
pub struct DetRng {
    state: u64,
}

impl DetRng {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn next_usize(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            0
        } else {
            (self.next_u64() as usize) % bound
        }
    }

    /// Produce a mutated copy of `seed` using a stack of 1..=4 byte-level
    /// mutation operators (bit flip, byte replace, boundary integer splice,
    /// length-prefix inflation, truncation, insertion, or slice duplication).
    pub fn mutate_bytes(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut out = seed.to_vec();
        let steps = 1 + self.next_usize(4);
        for _ in 0..steps {
            let op = self.next_usize(7);
            match op {
                0 if !out.is_empty() => {
                    let idx = self.next_usize(out.len());
                    let bit = 1u8 << (self.next_usize(8) as u8);
                    out[idx] ^= bit;
                }
                1 if !out.is_empty() => {
                    const INTERESTING_U8: &[u8] = &[0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff];
                    let idx = self.next_usize(out.len());
                    out[idx] = INTERESTING_U8[self.next_usize(INTERESTING_U8.len())];
                }
                2 if out.len() >= 4 => {
                    const INTERESTING_U32: &[u32] = &[
                        0,
                        1,
                        2,
                        16,
                        255,
                        256,
                        4096,
                        65_535,
                        65_536,
                        0x0100_0000,
                        0x7fff_ffff,
                        0x8000_0000,
                        0xffff_fffe,
                        0xffff_ffff,
                    ];
                    let pos = self.next_usize(out.len() - 3);
                    let val = INTERESTING_U32[self.next_usize(INTERESTING_U32.len())].to_le_bytes();
                    out[pos..pos + 4].copy_from_slice(&val);
                }
                3 if !out.is_empty() => {
                    let new_len = self.next_usize(out.len());
                    out.truncate(new_len);
                }
                4 if out.len() < 8192 => {
                    let pos = self.next_usize(out.len() + 1);
                    let count = 1 + self.next_usize(16);
                    let fill = (self.next_u64() & 0xff) as u8;
                    out.splice(pos..pos, std::iter::repeat_n(fill, count));
                }
                5 if out.len() >= 2 => {
                    let start = self.next_usize(out.len());
                    let max_del = (out.len() - start).min(32);
                    let del = 1 + self.next_usize(max_del);
                    out.drain(start..start + del);
                }
                _ if !out.is_empty() && out.len() < 8192 => {
                    let start = self.next_usize(out.len());
                    let len = 1 + self.next_usize((out.len() - start).min(32));
                    let chunk = out[start..start + len].to_vec();
                    let insert_at = self.next_usize(out.len() + 1);
                    out.splice(insert_at..insert_at, chunk);
                }
                _ => {
                    out.push((self.next_u64() & 0xff) as u8);
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Target 1: entry_codec
// ---------------------------------------------------------------------------

pub fn fuzz_entry_codec(bytes: &[u8]) {
    if let Ok(entry) = Entry::decode(bytes) {
        let _ = entry.proposal.validate();
        let _ = entry.proposal.proposal_digest();
        let _ = entry.proposal.canonical_bytes();
        if let Ok(reencoded) = entry.encode() {
            let redecoded =
                Entry::decode(&reencoded).expect("canonical Entry bytes must re-decode");
            assert_eq!(redecoded, entry, "Entry decode-encode-decode fixed point");
            let reencoded_twice = redecoded.encode().expect("re-decoded Entry must re-encode");
            assert_eq!(
                reencoded, reencoded_twice,
                "Entry canonical bytes idempotent"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Target 2: payload_decoders
// ---------------------------------------------------------------------------

pub fn fuzz_payload_decoders(bytes: &[u8]) {
    let _ = Entry::decode(bytes);
    if let Ok(unit) = UnitDefinition::decode(bytes)
        && let Ok(re) = unit.canonical_bytes()
    {
        assert_eq!(UnitDefinition::decode(&re), Ok(unit));
    }
    if let Ok(view) = RedactedView::decode(bytes)
        && let Ok(re) = view.canonical_bytes()
    {
        assert_eq!(RedactedView::decode(&re), Ok(view));
    }
    if let Ok(plan) = TransitionPlan::decode(bytes)
        && let Ok(re) = plan.encode()
    {
        assert_eq!(TransitionPlan::decode(&re), Ok(plan));
    }
    if let Ok(body) = RunBody::decode(bytes)
        && let Ok(re) = body.canonical_bytes()
    {
        assert_eq!(RunBody::decode(&re).expect("re-decode RunBody"), body);
    }
    if let Ok(intent) = PostIntent::decode(bytes)
        && let Ok(re) = intent.canonical_bytes()
    {
        assert_eq!(
            PostIntent::decode(&re).expect("re-decode PostIntent"),
            intent
        );
    }
    if let Ok(cert) = PlanCertificate::decode(bytes)
        && let Ok(re) = cert.canonical_bytes()
    {
        assert_eq!(
            PlanCertificate::decode(&re).expect("re-decode PlanCertificate"),
            cert
        );
    }
    if let Ok(plan) = PostPlan::decode(bytes)
        && let Ok(re) = plan.canonical_bytes()
    {
        assert_eq!(PostPlan::decode(&re).expect("re-decode PostPlan"), plan);
    }
    if let Ok(cert) = ReportCertificate::decode(bytes)
        && let Ok(re) = cert.canonical_bytes()
    {
        assert_eq!(ReportCertificate::decode(&re), Ok(cert));
    }
    if let Ok(cert) = SummaryCertificate::decode(bytes)
        && let Ok(re) = cert.canonical_bytes()
    {
        assert_eq!(SummaryCertificate::decode(&re), Ok(cert));
    }
    if let Ok(cert) = RollForwardCertificate::decode(bytes)
        && let Ok(re) = cert.canonical_bytes()
    {
        assert_eq!(RollForwardCertificate::decode(&re), Ok(cert));
    }
    if let Ok(cert) = AgingCertificate::decode(bytes)
        && let Ok(re) = cert.canonical_bytes()
    {
        assert_eq!(AgingCertificate::decode(&re), Ok(cert));
    }
    if let Ok(cert) = AgingReconciliationCertificate::decode(bytes)
        && let Ok(re) = cert.canonical_bytes()
    {
        assert_eq!(AgingReconciliationCertificate::decode(&re), Ok(cert));
    }
    if let Ok(cert) = CashFlowCertificate::decode(bytes)
        && let Ok(re) = cert.canonical_bytes()
    {
        assert_eq!(CashFlowCertificate::decode(&re), Ok(cert));
    }
    if let Ok(cert) = IndirectCashFlowCertificate::decode(bytes)
        && let Ok(re) = cert.canonical_bytes()
    {
        assert_eq!(IndirectCashFlowCertificate::decode(&re), Ok(cert));
    }
    if let Ok(cert) = StatementDiffCertificate::decode(bytes)
        && let Ok(re) = cert.canonical_bytes()
    {
        assert_eq!(StatementDiffCertificate::decode(&re), Ok(cert));
    }
    if let Ok(review) = AllocationReview::decode(bytes)
        && let Ok(re) = review.canonical_bytes()
    {
        assert_eq!(
            AllocationReview::decode(&re).expect("re-decode AllocationReview"),
            review
        );
    }
    if let Ok(review) = BalanceAllocationReview::decode(bytes)
        && let Ok(re) = review.canonical_bytes()
    {
        assert_eq!(
            BalanceAllocationReview::decode(&re).expect("re-decode BalanceAllocationReview"),
            review
        );
    }
    if let Ok(review) = SettlementReview::decode(bytes)
        && let Ok(re) = review.canonical_bytes()
    {
        assert_eq!(
            SettlementReview::decode(&re).expect("re-decode SettlementReview"),
            review
        );
    }
    if let Ok(review) = SettlementGroupReview::decode(bytes)
        && let Ok(re) = review.canonical_bytes()
    {
        assert_eq!(
            SettlementGroupReview::decode(&re).expect("re-decode SettlementGroupReview"),
            review
        );
    }
}

// ---------------------------------------------------------------------------
// Target 3: notary_state_and_proofs
// ---------------------------------------------------------------------------

pub fn fuzz_notary_state_and_proofs(bytes: &[u8]) {
    if let Ok(state) = AccumulatorState::decode(bytes)
        && let Ok(re) = state.canonical_bytes()
    {
        assert_eq!(AccumulatorState::decode(&re), Ok(state));
    }
    if let Ok(cp) = TransparencyCheckpoint::decode(bytes)
        && let Ok(re) = cp.canonical_bytes()
    {
        assert_eq!(TransparencyCheckpoint::decode(&re), Ok(cp));
    }
    if let Ok(receipt) = ProductionReceipt::decode(bytes)
        && let Ok(re) = receipt.canonical_bytes()
    {
        assert_eq!(ProductionReceipt::decode(&re), Ok(receipt));
    }
    if let Ok(cp) = fa_verify::Checkpoint::decode(bytes) {
        let re = cp.encode();
        assert_eq!(fa_verify::Checkpoint::decode(&re), Ok(cp));
    }
    let _ = fa_verify::LeafEnvelope::decode(bytes);
    let _ = fa_verify::verify_state(bytes);
}

// ---------------------------------------------------------------------------
// Target 4: fa_verify_inputs
// ---------------------------------------------------------------------------

pub fn fuzz_fa_verify_inputs(bytes: &[u8]) {
    let golden = golden_seeds();
    let trusted_keys = [golden.public_key];
    let trusted_cp = &golden.verify_checkpoint;
    let signed_cp = &golden.signed_checkpoint;

    let _ = fa_verify::verify_checkpoint(bytes, &trusted_keys);
    let _ = fa_verify::verify_state(bytes);
    let _ = fa_verify::verify_inclusion(bytes, trusted_cp);
    let _ = fa_verify::verify_consistency(bytes, trusted_cp, trusted_cp);
    let _ = fa_verify::verify_prefix(bytes, trusted_cp);
    let _ = fa_verify::verify_balance(bytes, trusted_cp);
    let _ = fa_verify::verify_scope(bytes, signed_cp, &golden.scope_claim, None);
    let _ = fa_verify::verify_bundle(bytes, &trusted_keys, None);
    if bytes.len() >= 2 {
        let split = (bytes[0] as usize) % bytes.len();
        let (left, right) = bytes.split_at(split);
        let _ = fa_verify::verify_bundle(left, &trusted_keys, Some(right));
    }
    let _ = fa_verify::redaction::verify_view_for(bytes, &golden.scope_root, &[0]);
    let _ = fa_verify::disclosure::verify(bytes, &[0], &golden.scope_root);
}

// ---------------------------------------------------------------------------
// Target 5: registry_toml
// ---------------------------------------------------------------------------

pub fn fuzz_registry_toml(bytes: &[u8]) {
    let cow = String::from_utf8_lossy(bytes);
    let text = cow.as_ref();
    let _ = fa_registry::toml::parse(text);
    if let Ok(classes) = EntryClasses::embedded() {
        let _ = Admissibility::parse(&classes, text);
        let _ = EvidencePolicy::from_text(text, &classes);
        if let Ok(adm) = Admissibility::embedded(&classes) {
            let _ = SodPolicy::parse(text, &classes, &adm);
        }
    }
    let _ = fa_registry::reason_codes::ReasonCodes::from_text(text);
    if let Ok(exits) = ExitCodes::embedded() {
        let _ = fa_registry::refusal_catalog::RefusalCatalog::from_text(text, &exits);
    }
    if let Ok(policy) = EvidencePolicy::embedded() {
        let _ = fa_registry::redaction_contracts::RedactionContracts::from_text(text, &policy);
    }
    let _ = fa_registry::procedures::Procedures::from_text(text);
    let _ = Topology::parse(text);
    if let (Ok(inv), Ok(refusals)) = (
        fa_registry::invariants::Invariants::embedded(),
        fa_registry::refusal_catalog::RefusalCatalog::embedded(),
    ) {
        let _ = fa_registry::threat_model::ThreatModel::parse(text, &inv, &refusals);
        let _ = fa_registry::mutants::MutantLedger::parse(text, &inv, &refusals);
    }
    let _ = fa_registry::invariants::Invariants::parse(text);
    let _ = fa_cli::verbs::Registry::parse(text);
}

// ---------------------------------------------------------------------------
// Target 6: cli_args
// ---------------------------------------------------------------------------

pub fn argv_from_bytes(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    if text.contains('\0') {
        text.split('\0').map(str::to_string).collect()
    } else {
        let mut out = Vec::new();
        for tok in text.split_whitespace() {
            if tok == "\"\"" {
                out.push(String::new());
            } else {
                out.push(tok.to_string());
            }
        }
        out
    }
}

pub fn fuzz_cli_args(bytes: &[u8]) {
    let argv = argv_from_bytes(bytes);
    if let Ok(reg) = fa_cli::verbs::registry() {
        let _ = fa_cli::args::parse(&argv, &reg.value_flags(), &reg.switches());
    }
    let _ = fa_cli::cli::parse_cli_invocation(&argv);
}

// ---------------------------------------------------------------------------
// Target 7: chart_import_json
// ---------------------------------------------------------------------------

pub fn fuzz_chart_import_json(bytes: &[u8]) {
    let cow = String::from_utf8_lossy(bytes);
    let text = cow.as_ref();
    if let Ok(parsed) = fa_verbs::json::parse(text) {
        let rendered = parsed.render();
        let reparsed =
            fa_verbs::json::parse(&rendered).expect("rendered Json must re-parse cleanly");
        let rendered_twice = reparsed.render();
        assert_eq!(
            rendered_twice, rendered,
            "Json canonical render-parse-render fixed point"
        );
        let reparsed_twice = fa_verbs::json::parse(&rendered_twice)
            .expect("canonical rendered Json must re-parse cleanly");
        assert_eq!(
            reparsed_twice, reparsed,
            "Canonical Json parse-render-parse fixed point"
        );
    }
    if let Ok(units) = UnitRegistry::embedded()
        && let Some(usd) = units.lookup("USD")
    {
        let _ = fa_cli::cli::parse_chart_specs("fuzz.json", text, usd, &units);
    }
}

/// Target 8 (`fa-qm4t`): Legacy GL export readers (QuickBooks IIF/CSV, Xero CSV,
/// NetSuite CSV, Generic GL CSV) and `LegacyColumnMap` parser on arbitrary bytes.
pub fn fuzz_legacy_gl_formats(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    let _ = fa_formats::legacy::LegacyColumnMap::parse_toml(&text);
    if let Ok(units) = fa_formats::UnitCatalog::embedded() {
        let mut map = fa_formats::legacy::AccountMap::new(["1000", "2000", "3000", "4000", "5000"]);
        map.insert("Checking", "1000");
        map.insert("Opening Equity", "3000");
        let _ = fa_formats::legacy::parse_quickbooks_iif(&text, &units, &map, "USD");
        let _ = fa_formats::legacy::parse_quickbooks_csv(&text, &units, &map, "USD");
        let _ = fa_formats::legacy::parse_xero_csv(&text, &units, &map, "USD");
        let _ = fa_formats::legacy::parse_netsuite_csv(&text, &units, &map, "USD");
    }
}

// ---------------------------------------------------------------------------
// Golden seed synthesis + checked-in corpus loader
// ---------------------------------------------------------------------------

struct GoldenSeeds {
    public_key: [u8; 32],
    verify_checkpoint: fa_verify::Checkpoint,
    signed_checkpoint: fa_verify::SignedCheckpoint,
    scope_claim: fa_verify::ScopeClaim,
    scope_root: [u8; 32],
    entry_bytes: Vec<u8>,
    payload_bytes: Vec<u8>,
    unit_bytes: Vec<u8>,
    plan_bytes: Vec<u8>,
    report_cert_bytes: Vec<u8>,
    state_bytes: Vec<u8>,
    checkpoint_bytes: Vec<u8>,
    receipt_bytes: Vec<u8>,
    inclusion_proof: Vec<u8>,
    prefix_proof: Vec<u8>,
    balance_proof: Vec<u8>,
    bundle_bytes: Vec<u8>,
}

fn golden_seeds() -> &'static GoldenSeeds {
    static GOLDEN: OnceLock<GoldenSeeds> = OnceLock::new();
    GOLDEN.get_or_init(build_golden_seeds)
}

fn build_golden_seeds() -> GoldenSeeds {
    let book_id = Id128([0x11; 16]);
    let cash = account_vid(book_id, "1000");
    let rev = account_vid(book_id, "4000");
    let who = VId(1);
    let units = UnitRegistry::embedded().expect("embedded units");
    let usd = units.lookup("USD").expect("USD unit");
    let usd_unit = units.get(usd).expect("USD unit definition").clone();
    let date = DateDay::from_ymd(2026, 3, 15).expect("valid date");

    let unit_def = UnitDefinition {
        id: usd,
        unit: usd_unit,
    };
    let unit_bytes = unit_def.canonical_bytes().expect("unit bytes");

    // Build an in-memory book for authentic entry, plan, certificate, checkpoint, proof, and bundle bytes.
    let calendar = FiscalCalendar::monthly("fiscal", 1, 1).expect("monthly calendar");
    let spec = BookSpec {
        book_id,
        name: "Fuzz Golden Co".to_string(),
        base_unit: usd,
        calendar,
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    };
    let keys = BookKeys::for_development(7);
    let mut book =
        Book::create_memory(keys, spec, Entropy::deterministic(7)).expect("create memory book");
    let chart = vec![
        AccountSpec {
            code: "1000".to_string(),
            name: "Cash".to_string(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "4000".to_string(),
            name: "Revenue".to_string(),
            account_type: 4,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
    ];
    book.install_chart(&chart, who, date, b"golden-chart")
        .expect("install chart")
        .expect("chart admitted");
    book.create_periods(2026).expect("create periods");
    let close_cap = Capability::embedded(who, &["close"]).expect("close cap");
    book.transition_period(
        "FY2026-P03",
        PeriodTransition::Open,
        who,
        1,
        date,
        b"open-p03",
        &close_cap,
    )
    .expect("transition")
    .expect("open admitted");

    let source_doc = Document {
        book_id,
        kind: 1,
        mime: "text/plain".to_string(),
        grade: 3,
        retrieved_by: who,
        bytes: b"INVOICE: Golden seed sale USD 150.00".to_vec(),
    };
    book.add_document(&source_doc)
        .expect("add doc")
        .expect("doc admitted");

    let legs = vec![
        LegPayload::simple(Side::Debit, cash, Amount::new(usd, 15_000)),
        LegPayload::simple(Side::Credit, rev, Amount::new(usd, 15_000)),
    ];
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: date,
        document_date: None,
        description: book.seal_text("Golden seed sale").expect("seal text"),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).expect("unit totals"),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"golden-seed-1".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        principal_ref: who,
        session_ref: None,
        evidence: vec![source_doc.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let post_cap = Capability::embedded(who, &["post"]).expect("post cap");
    let intent = PostIntent::new(proposal, Vec::new()).expect("valid PostIntent");
    let plan = book
        .plan(intent, &post_cap)
        .expect("plan")
        .expect("plan admitted");
    let plan_bytes = plan.canonical_bytes().expect("plan bytes");
    let posted = book
        .commit_plan(plan, &post_cap)
        .expect("commit_plan")
        .expect("commit admitted");
    let entry_vid = posted.entry_ref().vid;
    let (entry, _) = book
        .read_entry(entry_vid)
        .expect("read_entry")
        .expect("entry present");
    let payload_bytes = entry.proposal.canonical_bytes().expect("payload bytes");
    let entry_bytes = entry.encode().expect("entry bytes");

    // Also post a second entry via direct post_request to exercise multi-entry states
    let legs2 = vec![
        LegPayload::simple(Side::Debit, cash, Amount::new(usd, 5_000)),
        LegPayload::simple(Side::Credit, rev, Amount::new(usd, 5_000)),
    ];
    let proposal2 = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: date,
        document_date: None,
        description: book.seal_text("Golden seed sale 2").expect("seal text"),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs2).expect("unit totals"),
        legs: legs2,
        control: None,
        base_totals: None,
        idempotency_key: b"golden-seed-2".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([2; 32]),
            intent_kind: 1,
        },
        principal_ref: who,
        session_ref: None,
        evidence: vec![source_doc.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    book.post(PostRequest {
        proposal: proposal2,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: post_cap,
    })
    .expect("post 2")
    .expect("post 2 admitted");

    let cert_tb = book
        .certify_trial_balance(
            TrialBalanceSelection::Periods(vec!["FY2026-P03".to_string()]),
            None,
        )
        .expect("certify tb")
        .expect("certify admitted");
    let report_cert_bytes = cert_tb
        .certificate
        .canonical_bytes()
        .expect("encode report cert");

    let witness_cap = Capability::embedded(who, &["witness"]).expect("witness cap");
    let checkpointed = book
        .checkpoint(who, &witness_cap)
        .expect("checkpoint")
        .expect("checkpoint admitted");
    let state_bytes = checkpointed.stored.bytes.clone();
    let checkpoint_bytes = checkpointed.checkpoint.bytes.clone();
    let statement: Statement = checkpointed.stored.state.statement();
    let verify_checkpoint = fa_verify::Checkpoint {
        book_id: statement.book_id.0,
        branch_id: statement.branch_id.0,
        through_seq: statement.through_seq.0,
        leaf_count: statement.leaf_count,
        root: statement.root,
    };
    let scope_root = checkpointed.checkpoint.checkpoint.body.scope_index_root;
    let public_key = book.checkpoint_public_key();
    let signed_checkpoint =
        fa_verify::verify_checkpoint(&checkpoint_bytes, &[public_key]).expect("valid signed cp");
    let scope_claim = fa_verify::ScopeClaim {
        account: cash.0,
        from: date.0,
        to: date.0,
    };

    let produce_cap = Capability::embedded(who, &["read", "produce"]).expect("produce cap");
    let inclusion_proof = book
        .export_proof(
            who,
            &produce_cap,
            ProofRequest {
                state: Some(checkpointed.stored.oid),
                kind: ProofKind::Inclusion {
                    entry: entry_vid,
                    with_record: true,
                },
            },
        )
        .expect("prove inclusion")
        .expect("inclusion admitted")
        .bytes;
    let prefix_proof = book
        .export_proof(
            who,
            &produce_cap,
            ProofRequest {
                state: Some(checkpointed.stored.oid),
                kind: ProofKind::Prefix,
            },
        )
        .expect("prove prefix")
        .expect("prefix admitted")
        .bytes;
    let balance_proof = book
        .export_proof(
            who,
            &produce_cap,
            ProofRequest {
                state: Some(checkpointed.stored.oid),
                kind: ProofKind::Balance {
                    account: cash,
                    unit: usd,
                    effective_through: Some(date),
                },
            },
        )
        .expect("prove balance")
        .expect("balance admitted")
        .bytes;
    let produced_bundle = book
        .produce_bundle(
            who,
            &produce_cap,
            None,
            &BundleRequest {
                scope: BundleScope::Prefix,
                balances: vec![BalanceRequest {
                    account: cash,
                    unit: usd.0,
                    effective_through: Some(date.0),
                }],
                inline_documents: false,
            },
        )
        .expect("produce bundle")
        .expect("bundle admitted")
        .expect("bundle produced");
    let bundle_bytes = produced_bundle.bundle.bytes;
    let receipt_bytes = produced_bundle.receipt;

    GoldenSeeds {
        public_key,
        verify_checkpoint,
        signed_checkpoint,
        scope_claim,
        scope_root,
        entry_bytes,
        payload_bytes,
        unit_bytes,
        plan_bytes,
        report_cert_bytes,
        state_bytes,
        checkpoint_bytes,
        receipt_bytes,
        inclusion_proof,
        prefix_proof,
        balance_proof,
        bundle_bytes,
    }
}

/// Directory containing checked-in seed corpora for `target_name`.
#[must_use]
pub fn corpus_dir(target_name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(target_name)
}

/// Read all checked-in corpus files for `target_name`, sorted by filename,
/// plus synthesized canonical golden seeds for that target.
pub fn seeds_for_target(target_name: &str) -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    let dir = corpus_dir(target_name);
    if let Ok(read_dir) = std::fs::read_dir(&dir) {
        let mut paths: Vec<PathBuf> = read_dir
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        paths.sort();
        for path in paths {
            if let Ok(bytes) = std::fs::read(&path) {
                seeds.push(bytes);
            }
        }
    }
    let g = golden_seeds();
    match target_name {
        "entry_codec" => {
            seeds.push(g.entry_bytes.clone());
            seeds.push(g.payload_bytes.clone());
        }
        "payload_decoders" => {
            seeds.push(g.entry_bytes.clone());
            seeds.push(g.payload_bytes.clone());
            seeds.push(g.unit_bytes.clone());
            seeds.push(g.plan_bytes.clone());
            seeds.push(g.report_cert_bytes.clone());
        }
        "notary_state_and_proofs" => {
            seeds.push(g.state_bytes.clone());
            seeds.push(g.checkpoint_bytes.clone());
            seeds.push(g.receipt_bytes.clone());
            seeds.push(g.verify_checkpoint.encode());
        }
        "fa_verify_inputs" => {
            seeds.push(g.checkpoint_bytes.clone());
            seeds.push(g.state_bytes.clone());
            seeds.push(g.inclusion_proof.clone());
            seeds.push(g.prefix_proof.clone());
            seeds.push(g.balance_proof.clone());
            seeds.push(g.bundle_bytes.clone());
        }
        "registry_toml" => {
            seeds.push(include_bytes!("../../../registries/units.toml").to_vec());
            seeds.push(include_bytes!("../../../registries/entry_classes.toml").to_vec());
            seeds.push(include_bytes!("../../../registries/admissibility.toml").to_vec());
            seeds.push(include_bytes!("../../../registries/sod_policy.toml").to_vec());
            seeds.push(include_bytes!("../../../registries/verbs.toml").to_vec());
        }
        "cli_args" => {
            seeds.push(b"tb --period FY2026-P03 --book /tmp/b --json".to_vec());
            seeds.push(b"period reopen FY2026-P03 --to soft-closed --reason 1 --dry-run".to_vec());
            seeds.push(b"robot-docs schema balance_explained --json".to_vec());
        }
        "chart_import_json" => {
            seeds.push(
                br#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"base"}]}"#
                    .to_vec(),
            );
        }
        "legacy_gl_formats" => {
            seeds.push(
                b"!TRNS\tTRNSID\tTRNSTYPE\tDATE\tACCNT\tAMOUNT\tMEMO\n!SPL\tSPLID\tTRNSTYPE\tDATE\tACCNT\tAMOUNT\tMEMO\n!ENDTRNS\nTRNS\t1\tGENERAL JOURNAL\t2025-12-15\tChecking\t100.00\tSeed\nSPL\t2\tGENERAL JOURNAL\t2025-12-15\tOpening Equity\t-100.00\tSeed\nENDTRNS\n"
                    .to_vec(),
            );
            seeds.push(
                b"Transaction ID,Date,Account,Debit,Credit,Currency,Memo/Description\n1,2025-12-15,1000,100.00,,USD,Seed\n1,2025-12-15,3000,,100.00,USD,Seed\n"
                    .to_vec(),
            );
        }
        _ => {}
    }
    seeds
}

/// Run a single target over its seed corpus and `mutations_per_seed`
/// deterministic PRNG mutations.
pub fn run_target_smoke(target: &FuzzTarget, mutations_per_seed: usize) -> (usize, usize) {
    let seeds = seeds_for_target(target.name);
    let mut rng = DetRng::new(
        target
            .name
            .bytes()
            .fold(0x517c_c1b7_2722_0a95u64, |acc, b| {
                acc.wrapping_mul(31).wrapping_add(u64::from(b))
            }),
    );
    let mut mutated_count = 0usize;
    for seed in &seeds {
        (target.run)(seed);
        for _ in 0..mutations_per_seed {
            let mutated = rng.mutate_bytes(seed);
            (target.run)(&mutated);
            mutated_count += 1;
        }
    }
    // Always include boundary empty and single-byte inputs.
    (target.run)(&[]);
    (target.run)(&[0x00]);
    (target.run)(&[0xff]);
    (seeds.len(), mutated_count)
}

/// Run the smoke campaign across all registered [`LIVE_TARGETS`].
pub fn run_all_smoke(mutations_per_seed: usize) -> SmokeSummary {
    let mut corpus_inputs = 0usize;
    let mut mutated_inputs = 0usize;
    for target in LIVE_TARGETS {
        let (c, m) = run_target_smoke(target, mutations_per_seed);
        corpus_inputs += c;
        mutated_inputs += m;
    }
    SmokeSummary {
        targets_run: LIVE_TARGETS.len(),
        corpus_inputs,
        mutated_inputs,
    }
}

// ---------------------------------------------------------------------------
// Planted defect harnesses (falsifiability proof required by bead fa-tre)
// ---------------------------------------------------------------------------

/// A scratch copy of the entry header decoder with an injected `.unwrap()` on
/// a length-prefixed slice read (simulating an unchecked length field).
/// The `entry_codec` mutation campaign must catch this panic within the smoke
/// budget.
pub fn buggy_entry_decoder_with_planted_unwrap(bytes: &[u8]) {
    if bytes.len() >= 8 {
        let claimed_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let _slice: &[u8] = bytes.get(8..8usize.saturating_add(claimed_len)).unwrap();
    }
    fuzz_entry_codec(bytes);
}

/// A scratch CLI parser wrapper with a planted panic on an empty `--book ""`
/// flag value. The `cli_args` corpus + mutation campaign must catch this panic
/// within the smoke budget.
pub fn buggy_cli_parser_with_planted_empty_book_panic(bytes: &[u8]) {
    let argv = argv_from_bytes(bytes);
    if let Ok(reg) = fa_cli::verbs::registry()
        && let Ok(parsed) = fa_cli::args::parse(&argv, &reg.value_flags(), &reg.switches())
        && let Some(book_val) = parsed.flag("--book")
    {
        assert!(!book_val.is_empty(), "planted panic on empty --book \"\"");
    }
    fuzz_cli_args(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_live_target_has_checked_in_corpus_and_passes_smoke_campaign() {
        for target in LIVE_TARGETS {
            let dir = corpus_dir(target.name);
            assert!(
                dir.is_dir(),
                "missing checked-in corpus directory for target `{}` at {}",
                target.name,
                dir.display()
            );
            let files: Vec<_> = std::fs::read_dir(&dir)
                .expect("read corpus dir")
                .filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .collect();
            assert!(
                !files.is_empty(),
                "corpus directory for `{}` must contain at least one seed file",
                target.name
            );
            let (seeds, mutated) = run_target_smoke(target, 64);
            assert!(seeds >= files.len());
            assert!(mutated >= 64);
        }
    }

    #[test]
    fn dormant_targets_name_their_activating_beads() {
        assert_eq!(DORMANT_TARGETS.len(), 4);
        for d in DORMANT_TARGETS {
            assert!(!d.name.is_empty());
            assert!(d.activating_bead.starts_with("fa-"));
            assert!(!d.description.is_empty());
        }
    }

    #[test]
    fn planted_unwrap_on_entry_length_field_is_caught_within_smoke_budget() {
        let seeds = seeds_for_target("entry_codec");
        let mut rng = DetRng::new(0x000f_a77e_0001);
        let mut caught = false;
        'outer: for seed in &seeds {
            if std::panic::catch_unwind(|| buggy_entry_decoder_with_planted_unwrap(seed)).is_err() {
                caught = true;
                break;
            }
            for _ in 0..64 {
                let mutated = rng.mutate_bytes(seed);
                if std::panic::catch_unwind(|| buggy_entry_decoder_with_planted_unwrap(&mutated))
                    .is_err()
                {
                    caught = true;
                    break 'outer;
                }
            }
        }
        assert!(
            caught,
            "entry_codec smoke campaign must catch an injected unwrap() on a length field"
        );
    }

    #[test]
    fn planted_panic_on_empty_book_flag_in_cli_parser_is_caught_within_smoke_budget() {
        let seeds = seeds_for_target("cli_args");
        let mut rng = DetRng::new(0x000f_a77e_0002);
        let mut caught = false;
        'outer: for seed in &seeds {
            if std::panic::catch_unwind(|| buggy_cli_parser_with_planted_empty_book_panic(seed))
                .is_err()
            {
                caught = true;
                break;
            }
            for _ in 0..64 {
                let mutated = rng.mutate_bytes(seed);
                if std::panic::catch_unwind(|| {
                    buggy_cli_parser_with_planted_empty_book_panic(&mutated)
                })
                .is_err()
                {
                    caught = true;
                    break 'outer;
                }
            }
        }
        assert!(
            caught,
            "cli_args smoke campaign must catch a planted panic on --book \"\""
        );
    }
}
