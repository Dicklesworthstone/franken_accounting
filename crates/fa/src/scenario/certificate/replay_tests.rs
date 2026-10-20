//! Durable v1 replay survives the corrected bank-coordinate policy.

use super::*;
use crate::bank::{
    BankConfirmationRequest, BankFormat, BankImportRequest, BankMatchRequest,
    BankReconciliationRequest,
};
use crate::{BookKeys, Entropy, ReportArtifact, ReportArtifactFamily};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, ScenarioFork, UnitPolicy};
use fa_model::{EntryClass, EntryOrigin, EntryPayload, LegPayload, Oid, account_vid};
use fa_money::{Amount, Side, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

const PRINCIPAL: VId = VId(113);
const SEED: u8 = 113;
const PERIOD: &str = "FY2026-P01";
const SCENARIO: &str = "closed-bank-empty-scenario";
const CSV: &str = "sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference\n1,SCENARIO-BANK,USD,2026-01-15,0.00,100.00,2026-01-05,2026-01-05,CRDT,100.00,Customer,\n";
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn day(n: u8) -> DateDay {
    DateDay::from_ymd(2026, 1, n).unwrap()
}

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

/// Real facade cash, retained source, confirmation and close. No checkpoint
/// or register maintenance precedes the close, so later compression cannot
/// invalidate any of its original native coordinates.
fn closed_book(dir: &Path) -> (Book, CommitSeq) {
    let unit = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let book_id = Id128([SEED; 16]);
    let mut book = Book::create_dir(
        dir,
        BookKeys::for_development(SEED),
        BookSpec {
            book_id,
            name: "Scenario certificate compatibility".into(),
            base_unit: unit,
            calendar: FiscalCalendar::monthly("scenario-compatibility", 1, 0).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(u64::from(SEED)),
    )
    .unwrap();
    let accounts: Vec<_> = [("1000", 1), ("3000", 3)]
        .into_iter()
        .map(|(code, account_type)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type,
            normal_balance: u8::from(account_type == 3),
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        })
        .collect();
    book.install_chart(
        &accounts,
        PRINCIPAL,
        day(1),
        b"chart",
        &cap(&["schema_change"]),
    )
    .unwrap()
    .unwrap();
    book.create_periods(2026, PRINCIPAL, &cap(&["schema_change"]))
        .unwrap()
        .unwrap();
    book.transition_period(
        PERIOD,
        PeriodTransition::Open,
        PRINCIPAL,
        1,
        b"open",
        &cap(&["close"]),
    )
    .unwrap()
    .unwrap();
    let evidence = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"Independent source cash receipt".to_vec(),
    };
    book.add_document(&evidence).unwrap().unwrap();
    let legs = vec![
        LegPayload::simple(
            Side::Debit,
            account_vid(book_id, "1000"),
            Amount::new(unit, 10_000),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(book_id, "3000"),
            Amount::new(unit, 10_000),
        ),
    ];
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day(5),
        document_date: None,
        description: book.seal_text("Source cash receipt").unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"cash".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([SEED; 32]),
            intent_kind: 1,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: vec![evidence.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        tags: Vec::new(),
        extensions: Vec::new(),
    };
    book.post(PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: cap(&["post"]),
    })
    .unwrap()
    .unwrap();
    let capability = cap(&["read", "post", "reconcile", "privileged"]);
    let imported = book
        .import_bank_statement(
            &capability,
            BankImportRequest {
                account: account_vid(book_id, "1000"),
                format: BankFormat::Csv,
                bytes: CSV.as_bytes().to_vec(),
                previous_manifest: None,
            },
        )
        .unwrap()
        .unwrap();
    let matched = book
        .match_bank_statement(
            &capability,
            BankMatchRequest {
                manifest_oid: imported.manifest_oid,
                known_at: None,
                date_window_days: 3,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(matched.proposals.len(), 1);
    book.confirm_bank_statement_match(
        &capability,
        BankConfirmationRequest {
            manifest_oid: imported.manifest_oid,
            line_ordinal: matched.lines[0].line_ordinal,
            proposal_digest: matched.proposals[0].oid().unwrap().0,
            source_known_at: matched.known_at,
            date_window_days: matched.date_window_days,
            proposer: matched.proposals[0].principal,
        },
    )
    .unwrap()
    .unwrap();
    let evaluated_known_at = book.head().unwrap();
    let closed = book
        .reconcile_bank_statement(
            &capability,
            BankReconciliationRequest {
                manifest_oid: imported.manifest_oid,
                evaluated_known_at,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(closed.claim.cash_balance, 10_000);
    (book, closed.recorded_at)
}

/// Frozen pre-v2 field order and domain, independent of the production
/// certificate encoder/version dispatch. The caller supplies the exact
/// report that the old compressed or rollout-era protected replay produced.
fn version_one_bytes(source: &ScenarioDiffCertificate, report: &ScenarioDiff) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(b"fa:scenario-diff-certificate:v1")
        .bytes(&source.trunk.canonical_bytes().unwrap())
        .u128(source.scenario.0)
        .str(&source.name)
        .fixed(&source.body_digest)
        .list(&source.intents, |w, record| {
            w.u128(record.0);
        })
        .fixed(&report.seq_map_digest)
        .u64(report.scenario_known_at.0)
        .u128(source.producer.0)
        .fixed(&source.capability_commitment)
        .bytes(&output_bytes(report).unwrap());
    let mut bytes = w.finish().unwrap();
    let digest = domain_digest(b"fa:scenario-diff-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    bytes
}

#[test]
fn bank_scenario_v1_and_v2_certificates_preserve_exact_retained_cold_replay() {
    let dir = std::env::temp_dir().join(format!(
        "fa-scenario-certificate-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
    ));
    let (mut book, closed_at) = closed_book(&dir);
    let (_, fork_at) = book.materialize_registers(PERIOD).unwrap();
    assert_eq!(fork_at.0, closed_at.0 + 1);
    book.open_scenario(
        cap(&["post"]),
        SCENARIO,
        ScenarioFork {
            at: Some(fork_at),
            ..ScenarioFork::default()
        },
        day(20),
        "Empty scenario after a legitimate bank close and maintenance",
    )
    .unwrap()
    .unwrap();
    let materialized = book.materialize_scenario(SCENARIO).unwrap().unwrap();
    assert_eq!(materialized.book.head().unwrap(), fork_at);
    assert_eq!(materialized.map.pairs.len() as u64, closed_at.0);
    for (index, pair) in materialized.map.pairs.iter().enumerate() {
        assert_eq!(pair.source_seq.0, index as u64 + 1);
        assert_eq!(pair.scratch_seq, pair.source_seq);
    }
    let map_digest = materialized.map.digest().unwrap();
    drop(materialized);

    let periods = vec![PERIOD.to_string()];
    let producer = cap(&["read", "produce"]);
    let current = book
        .certify_scenario_diff(PRINCIPAL, &producer, SCENARIO, &periods, false)
        .unwrap()
        .unwrap();
    assert_eq!(current.certificate.format(), CERTIFICATE_FORMAT);
    assert_eq!(current.report.scenario_known_at, fork_at);
    assert_eq!(current.report.seq_map_digest, map_digest);
    assert_eq!(current.report.intents, 0);
    assert!(current.report.rows.is_empty());

    // The sole omitted commit is after the close. Its immutable claim stays
    // lawful in the old scratch book; only the materialization's head differs.
    // No fallback selected by map digest alone could distinguish these v1s.
    let mut legacy_report = current.report.clone();
    legacy_report.scenario_known_at = closed_at;
    let legacy_bytes = version_one_bytes(&current.certificate, &legacy_report);
    let legacy = ScenarioDiffCertificate::decode(&legacy_bytes).unwrap();
    let rollout_bytes = version_one_bytes(&current.certificate, &current.report);
    let rollout = ScenarioDiffCertificate::decode(&rollout_bytes).unwrap();
    assert_eq!(legacy.format(), LEGACY_CERTIFICATE_FORMAT);
    assert_ne!(legacy.digest(), rollout.digest());
    let fixtures = [
        (legacy.clone(), legacy_report.clone(), legacy_bytes),
        (rollout, current.report.clone(), rollout_bytes),
        (
            current.certificate.clone(),
            current.report.clone(),
            current.certificate.canonical_bytes().unwrap(),
        ),
    ];
    for (certificate, expected, bytes) in &fixtures {
        assert_eq!(certificate.canonical_bytes().unwrap(), *bytes);
        assert_eq!(
            ReportArtifact::decode(bytes).unwrap().family(),
            ReportArtifactFamily::ScenarioDiff
        );
        assert_eq!(
            book.replay_scenario_diff(PRINCIPAL, &producer, certificate)
                .unwrap()
                .unwrap(),
            *expected
        );
        book.retain_scenario_diff(PRINCIPAL, &producer, certificate)
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        book.scenario_diff(SCENARIO, &periods, false)
            .unwrap()
            .unwrap(),
        current.report,
        "new materializations never select legacy coordinates"
    );

    // A valid container still needs the complete matching output. Metadata
    // alone, or the old coordinates inside a v2 container, proves nothing.
    let mut changed = legacy_report.clone();
    changed.seq_map_digest[0] ^= 1;
    let wrong_map =
        ScenarioDiffCertificate::decode(&version_one_bytes(&current.certificate, &changed))
            .unwrap();
    changed = current.report.clone();
    changed.name.push_str("-different-output");
    let wrong_output =
        ScenarioDiffCertificate::decode(&version_one_bytes(&current.certificate, &changed))
            .unwrap();
    let mut v2_with_legacy_coordinates = current.certificate.clone();
    v2_with_legacy_coordinates.scenario_known_at = legacy_report.scenario_known_at;
    v2_with_legacy_coordinates.output = output_bytes(&legacy_report).unwrap();
    v2_with_legacy_coordinates.digest = domain_digest(
        DIGEST_DOMAIN,
        &[&v2_with_legacy_coordinates.body().unwrap()],
    );
    for certificate in [&wrong_map, &wrong_output, &v2_with_legacy_coordinates] {
        let refusal = book
            .replay_scenario_diff(PRINCIPAL, &producer, certificate)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, "FA-REF-150", "{refusal:?}");
    }
    let refusal = book
        .replay_scenario_diff(PRINCIPAL, &cap(&["produce"]), &legacy)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-011");

    book.checkpoint(PRINCIPAL, &cap(&["witness"]))
        .unwrap()
        .unwrap();
    let before_replay = book.head().unwrap();
    drop(book);
    for (certificate, expected, bytes) in fixtures {
        let mut reopened = Book::open_dir(
            &dir,
            BookKeys::for_development(SEED),
            Entropy::deterministic(u64::from(SEED) + 1),
        )
        .unwrap();
        let reader = cap(&["read"]);
        let retained = reopened
            .read_report_artifact(PRINCIPAL, &reader, certificate.digest())
            .unwrap()
            .unwrap();
        let retained_bytes = retained.canonical_bytes().unwrap();
        assert_eq!(retained_bytes, bytes);
        let decoded = ScenarioDiffCertificate::decode(&retained_bytes).unwrap();
        // This is the same admitted historical hydration the CLI performs
        // before dispatching a scenario artifact to its synchronous replay.
        reopened
            .prepare_report_history(PRINCIPAL, &reader, Some(decoded.trunk.known_at))
            .unwrap()
            .unwrap();
        let replayed = reopened
            .replay_scenario_diff(PRINCIPAL, &reader, &decoded)
            .unwrap()
            .unwrap();
        assert_eq!(replayed, expected);
        assert_eq!(output_bytes(&replayed).unwrap(), decoded.output);
        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
        assert_eq!(reopened.head().unwrap(), before_replay);
    }
    std::fs::remove_dir_all(dir).unwrap();
}
