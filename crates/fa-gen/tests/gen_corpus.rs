//! End-to-end integration and calibration tests for `fa-gen` (bead `fa-8mae`):
//! posts all seven labeled scenario corpora through the real `fa-journal`
//! kernel, verifies determinism (same seed -> identical committed entry digests),
//! seed sensitivity, scale knobs, label consistency against the posted book,
//! Lantern precision/recall across all seven scenarios, and the `fa-gen` CLI.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::process::Command;

use asupersync::Budget;
use asupersync::runtime::RuntimeBuilder;
use fa_gen::{GenConfig, GeneratedCorpus, ScenarioKind, generate};
use fa_journal::evidence::{Document, add_document};
use fa_journal::policy::{ApprovalRequest, Approved, record_approval};
use fa_journal::*;
use fa_lantern::cutoff::PeriodBoundary;
use fa_lantern::digits::FirstDigit;
use fa_lantern::duplicates::{SameSameDifferent, SameSameSame};
use fa_lantern::graph::{RoundTrips, Structuring};
use fa_lantern::jet::{
    PeriodEndTiming, PostClosing, RoundAmounts, SelfApproved, ThinDescriptions, Weekend,
};
use fa_lantern::numbers::SequenceGaps;
use fa_lantern::{Cite, Params, Procedure, ProcedureRun, Severity, Snapshot, run_over};
use fa_model::{
    ApprovalRef, EntryOrigin, EntryPayload, EntryRef, Erasable, EvidenceRef, ExternalId, Id128,
    LegPayload, Oid, SealKey, SymbolTable, account_vid,
};
use fa_money::{Amount, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_crypto::Hasher;
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;

const PREPARER: VId = VId(7);
const REVIEWER: VId = VId(8);

struct PostedScenario {
    db: Database<MemVfs>,
    book: BookContext,
    corpus: GeneratedCorpus,
    posted_refs: Vec<EntryRef>,
    book_journal_digest: Oid,
}

impl PostedScenario {
    fn run_procedure(&self, p: &dyn Procedure) -> ProcedureRun {
        let mut snapshot = Snapshot::read(
            &self.db,
            &self.book,
            None,
            Some(self.corpus.snapshot_cutoff),
        )
        .expect("snapshot");
        // For planted entries representing legacy self-approval (`self_approve = true`),
        // attach legacy migration self-approval provenance on the snapshot entry (native
        // self-approval is proactively refused by FA-INV-06 / FA-REF-008 at commit).
        for (idx, ge) in self.corpus.entries.iter().enumerate() {
            if ge.self_approve {
                let target_vid = self.posted_refs[idx].vid;
                if let Some(se) = snapshot.entries.iter_mut().find(|e| e.vid == target_vid) {
                    let entered = Erasable::seal(
                        &"preparer@legacy.example".to_string(),
                        None,
                        &self.book.seal_key,
                        [77; 32],
                        [77; 24],
                    );
                    let approved = Erasable::seal(
                        &"preparer@legacy.example".to_string(),
                        None,
                        &self.book.seal_key,
                        [78; 32],
                        [78; 24],
                    );
                    let mig_id =
                        Erasable::seal(&ge.key, None, &self.book.seal_key, [79; 32], [79; 24]);
                    se.entry.proposal.origin = EntryOrigin::Migration {
                        run_ref: VId(900),
                        source_system: "legacy_erp".into(),
                        source_id: mig_id,
                        source_recorded_at_ns: None,
                        source_entered_by: Some(entered),
                        source_approved_by: Some(approved),
                        batch_oid: Oid([9; 32]),
                    };
                }
            }
        }
        run_over(&snapshot, &self.book, p).expect("lantern procedure run")
    }

    fn cited_entry_indices(&self, run: &ProcedureRun) -> BTreeSet<usize> {
        let mut out = BTreeSet::new();
        for f in &run.findings {
            for c in &f.cites {
                assert!(
                    c.resolves(&self.db, &self.book, run.coordinate.known_at)
                        .expect("citation resolution"),
                    "{}: citation {c:?} must resolve in book",
                    run.procedure
                );
                if let Cite::Entry(vid) = c {
                    let idx = self
                        .posted_refs
                        .iter()
                        .position(|r| r.vid == *vid)
                        .expect("cited entry VId must belong to posted corpus");
                    out.insert(idx);
                }
            }
        }
        out
    }
}

fn post_corpus(corpus: GeneratedCorpus) -> PostedScenario {
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let keys = DatabaseKeys::new(
        [0x51; 32],
        DatabaseSecurityNamespaceId([0x52; 32]),
        [0x53; 32],
    );
    let mut db = runtime
        .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
        .expect("open_memory");
    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").expect("USD");
    let calendar = FiscalCalendar::monthly("cal", 1, 1).expect("calendar");
    let mut book_id_bytes = [0u8; 16];
    book_id_bytes[0] = corpus.scenario.tag();
    book_id_bytes[1..9].copy_from_slice(&corpus.seed.to_le_bytes());
    let book_id = Id128(book_id_bytes);
    let spec = BookSpec {
        book_id,
        name: corpus.book_name.clone(),
        base_unit: usd,
        calendar: calendar.clone(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    };
    let symbols = SymbolTable::compiled();
    runtime
        .block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await })
        .expect("create_book");
    let book = BookContext {
        book_id,
        calendar,
        units,
        seal_key: SealKey([0x33; 32]),
        symbols,
    };
    let chart: Vec<AccountSpec> = corpus
        .accounts
        .iter()
        .map(|a| AccountSpec {
            code: a.code.clone(),
            name: a.name.clone(),
            account_type: a.account_type,
            normal_balance: a.normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        })
        .collect();
    let jan1 = DateDay::from_ymd(corpus.fiscal_year, 1, 1).expect("jan1");
    runtime
        .block_on(async {
            install_chart(
                &mut db,
                &ctx,
                &book,
                &chart,
                PREPARER,
                jan1,
                b"fa-gen-chart",
                Erasable::seal(
                    &"fa-gen chart".to_string(),
                    None,
                    &book.seal_key,
                    [5; 32],
                    [6; 24],
                ),
            )
            .await
        })
        .expect("install_chart")
        .expect("chart admitted");
    let (_, periods) = runtime
        .block_on(async { create_periods(&mut db, &ctx, &book, corpus.fiscal_year).await })
        .expect("create_periods");
    for (idx, p) in periods
        .iter()
        .filter(|p| p.kind == PeriodKind::Normal)
        .enumerate()
    {
        let desc = Erasable::seal(
            &"open period".to_string(),
            None,
            &book.seal_key,
            [idx as u8; 32],
            [idx as u8; 24],
        );
        runtime
            .block_on(async {
                transition_period(
                    &mut db,
                    &ctx,
                    &book,
                    &p.code,
                    PeriodTransition::Open,
                    PREPARER,
                    1,
                    jan1,
                    format!("open-{}", p.code).as_bytes(),
                    desc,
                    &Capability::embedded(PREPARER, &["close"]).expect("close"),
                    &[],
                )
                .await
            })
            .expect("open period")
            .expect("open admitted");
    }

    // Add a reviewed source document so every entry satisfies evidence policy.
    let source = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PREPARER,
        bytes: b"INVOICE (fa-gen synthetic source voucher)".to_vec(),
    };
    runtime
        .block_on(async { add_document(&mut db, &ctx, &book, &source).await })
        .expect("add_document")
        .expect("document admitted");
    let evidence: Vec<EvidenceRef> = vec![source.evidence_ref(1)];

    let mut posted_refs: Vec<Option<EntryRef>> = vec![None; corpus.entries.len()];
    let mut salt = 1u8;

    let mut post_one = |idx: usize, db: &mut Database<MemVfs>| {
        let entry = &corpus.entries[idx];
        salt = salt.wrapping_add(1);
        let description = Erasable::seal(
            &entry.description,
            None,
            &book.seal_key,
            [salt; 32],
            [salt; 24],
        );
        let mut external_ids = Vec::new();
        for (sys, id) in &entry.external_ids {
            salt = salt.wrapping_add(1);
            let sealed_id = Erasable::seal(id, None, &book.seal_key, [salt; 32], [salt; 24]);
            external_ids.push(ExternalId {
                system: sys.clone(),
                id: sealed_id,
            });
        }
        let legs: Vec<LegPayload> = entry
            .legs
            .iter()
            .map(|l| {
                LegPayload::simple(
                    l.side,
                    account_vid(book.book_id, &l.account_code),
                    Amount::new(usd, l.cents),
                )
            })
            .collect();
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: book.book_id,
            branch_id: Id128::TRUNK,
            class: entry.class,
            effective_date: entry.effective_date,
            document_date: entry.document_date,
            description,
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).expect("unit_totals"),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: entry.key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: PREPARER,
            session_ref: None,
            evidence: evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids,
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let digest = proposal.proposal_digest().expect("proposal_digest");
        let ops: &[&str] = if entry.post_after_soft_close {
            &["post", "post_softclosed"]
        } else {
            &["post"]
        };
        if entry.self_approve {
            let req = ApprovalRequest {
                capability: Capability::embedded(PREPARER, &["approve"]).expect("approve"),
                approved_proposal_digest: digest,
                role: 0,
            };
            let approved = runtime
                .block_on(async { record_approval(db, &ctx, &book, req).await })
                .expect("record_approval")
                .expect("self-approval recorded");
            let self_approval = match approved {
                Approved::Recorded { approval, .. }
                | Approved::AlreadyRecorded { approval, .. } => approval,
            };
            let refused_req = PostRequest {
                proposal: proposal.clone(),
                approvals: vec![self_approval],
                plan_certificate: None,
                capability: Capability::embedded(PREPARER, ops).expect("post capability"),
            };
            let refusal = runtime
                .block_on(async { post(db, &ctx, &book, refused_req).await })
                .expect("post")
                .expect_err("FA-INV-06 must refuse native self-approval at commit");
            assert_eq!(refusal.code, "FA-REF-008");
        }
        let mut approvals: Vec<ApprovalRef> = Vec::new();
        if entry.review {
            let req = ApprovalRequest {
                capability: Capability::embedded(REVIEWER, &["approve"]).expect("approve"),
                approved_proposal_digest: digest,
                role: 0,
            };
            let approved = runtime
                .block_on(async { record_approval(db, &ctx, &book, req).await })
                .expect("record_approval")
                .expect("reviewer approval admitted");
            match approved {
                Approved::Recorded { approval, .. }
                | Approved::AlreadyRecorded { approval, .. } => approvals.push(approval),
            }
        }
        let req = PostRequest {
            proposal,
            approvals,
            plan_certificate: None,
            capability: Capability::embedded(PREPARER, ops).expect("post capability"),
        };
        let outcome = runtime
            .block_on(async { post(db, &ctx, &book, req).await })
            .expect("post")
            .expect("entry admitted");
        let entry_ref = match outcome {
            Posted::Committed { entry_ref, .. } => entry_ref,
            other => panic!("expected Committed, got {other:?}"),
        };
        posted_refs[idx] = Some(entry_ref);
    };

    // Phase 1: post all pre-SoftClose entries.
    for (idx, entry) in corpus.entries.iter().enumerate() {
        if !entry.post_after_soft_close {
            post_one(idx, &mut db);
        }
    }

    // Phase 2: execute scheduled period transitions (e.g. SoftClose).
    for (t_idx, t) in corpus.transitions.iter().enumerate() {
        let desc = Erasable::seal(
            &t.description,
            None,
            &book.seal_key,
            [(200 + t_idx) as u8; 32],
            [(200 + t_idx) as u8; 24],
        );
        runtime
            .block_on(async {
                transition_period(
                    &mut db,
                    &ctx,
                    &book,
                    &t.period_code,
                    t.transition,
                    PREPARER,
                    1,
                    t.effective_date,
                    format!("gen-trans-{t_idx}").as_bytes(),
                    desc,
                    &Capability::embedded(PREPARER, &["close"]).expect("close"),
                    &[],
                )
                .await
            })
            .expect("transition_period")
            .expect("transition admitted");
    }

    // Phase 3: post all post-SoftClose entries.
    for (idx, entry) in corpus.entries.iter().enumerate() {
        if entry.post_after_soft_close {
            post_one(idx, &mut db);
        }
    }

    let posted_refs: Vec<EntryRef> = posted_refs
        .into_iter()
        .map(|r| r.expect("every corpus entry must be posted"))
        .collect();
    let mut h = Hasher::new();
    h.update(b"fa:gen:book-journal:v1");
    for r in &posted_refs {
        h.update(&r.vid.0.to_le_bytes());
        h.update(&r.entry_digest);
    }
    let book_journal_digest = Oid(h.finalize().0);

    PostedScenario {
        db,
        book,
        corpus,
        posted_refs,
        book_journal_digest,
    }
}

#[test]
fn seven_scenarios_post_deterministically_and_satisfy_lantern_ground_truth() {
    for scenario in ScenarioKind::ALL {
        let run1 = post_corpus(generate(GenConfig::new(scenario, 7)));
        let run2 = post_corpus(generate(GenConfig::new(scenario, 7)));
        assert_eq!(
            run1.book_journal_digest, run2.book_journal_digest,
            "{scenario}: same seed must produce identical posted journal digest"
        );
        assert_eq!(
            run1.posted_refs, run2.posted_refs,
            "{scenario}: same seed must produce identical EntryRefs"
        );

        let run_other_seed = post_corpus(generate(GenConfig::new(scenario, 99)));
        assert_ne!(
            run1.book_journal_digest, run_other_seed.book_journal_digest,
            "{scenario}: different seeds must produce distinct posted journal digests"
        );

        println!(
            "scenario={} seed=7 entries={} labels={} journal_digest={}",
            scenario.slug(),
            run1.corpus.entries.len(),
            run1.corpus.labels.len(),
            fa_gen::oid_hex(run1.book_journal_digest)
        );

        let procedures: Vec<Box<dyn Procedure>> = vec![
            Box::new(RoundAmounts::new().unwrap()),
            Box::new(PeriodEndTiming::new().unwrap()),
            Box::new(PostClosing::new().unwrap()),
            Box::new(Weekend::new().unwrap()),
            Box::new(SelfApproved::new().unwrap()),
            Box::new(ThinDescriptions::new().unwrap()),
            Box::new(PeriodBoundary::new().unwrap()),
            Box::new(SameSameSame::new().unwrap()),
            Box::new(SameSameDifferent::new().unwrap()),
            Box::new(SequenceGaps::new().unwrap()),
            Box::new(RoundTrips::new().unwrap()),
            Box::new(Structuring::new().unwrap()),
        ];

        for proc in &procedures {
            let pid = proc.id();
            let res = run1.run_procedure(proc.as_ref());
            let cited = run1.cited_entry_indices(&res);
            let expected = run1.corpus.expected_entries_for_procedure(pid);
            println!(
                "  procedure={pid} findings={} cited={cited:?} expected={expected:?}",
                res.findings.len()
            );
            if scenario == ScenarioKind::CleanRetailer {
                assert!(
                    res.findings.is_empty(),
                    "clean-retailer must have 0 false positives on `{pid}`, got {:?}",
                    res.findings
                );
            } else {
                for &exp_idx in &expected {
                    assert!(
                        cited.contains(&exp_idx),
                        "{scenario}/`{pid}`: expected planted entry index {exp_idx} (`{}`) to be cited, got {cited:?}",
                        run1.corpus.entries[exp_idx].key
                    );
                }
            }
        }

        if scenario == ScenarioKind::CleanRetailer {
            // Verify Benford first-digit close conformity on CleanRetailer at min_population = 18.
            let params = Params::defaults(FirstDigit::ID)
                .unwrap()
                .set("min_population", 18)
                .unwrap();
            let benford = run1.run_procedure(&FirstDigit::with(params));
            assert_eq!(benford.findings.len(), 1);
            assert_eq!(
                benford.findings[0].severity,
                Severity::Info,
                "clean-retailer must achieve Benford close conformity (Severity::Info), got {:?}",
                benford.findings[0]
            );
        } else {
            assert!(
                !run1.corpus.labels.is_empty(),
                "{scenario}: fraud scenario must carry non-empty ground-truth labels"
            );
        }
    }
}

#[test]
fn fa_gen_cli_renders_scenarios_and_writes_labels_and_readme() {
    let bin = env!("CARGO_BIN_EXE_fa-gen");
    let list_out = Command::new(bin)
        .args(["scenarios", "--json"])
        .output()
        .expect("run fa-gen scenarios --json");
    assert!(list_out.status.success());
    let list_str = String::from_utf8(list_out.stdout).expect("utf8");
    for s in ScenarioKind::ALL {
        assert!(
            list_str.contains(s.slug()),
            "scenarios output must list {}",
            s.slug()
        );
    }

    let out_dir = std::env::temp_dir().join(format!("fa-gen-cli-test-{}", std::process::id()));
    let book_out = Command::new(bin)
        .args([
            "book",
            "--scenario",
            "worldcom",
            "--seed",
            "7",
            "--scale",
            "2",
            "--out",
            out_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run fa-gen book");
    assert!(book_out.status.success());
    let labels_json = std::fs::read_to_string(out_dir.join("labels.json")).expect("labels.json");
    let readme_md = std::fs::read_to_string(out_dir.join("README.md")).expect("README.md");
    assert!(labels_json.contains("\"scenario\": \"worldcom-capitalization\""));
    assert!(labels_json.contains("\"WC-FACT-01\""));
    assert!(readme_md.contains("WorldCom-Style Operating Line-Cost Capitalization"));
}
