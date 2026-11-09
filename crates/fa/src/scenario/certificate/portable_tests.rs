//! Real native rehearsal, signed complete-prefix transport, and independent
//! conditional mathematics. The verifier never opens the producer's book.

use super::*;
use crate::{BookKeys, Entropy, ProducedBundle, scenario_math_request};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, ScenarioFork, UnitPolicy};
use fa_model::{EntryClass, EntryOrigin, EntryPayload, LegPayload, Oid, account_vid};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_notary::scenario::{ScenarioDocument, assemble};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fa_verify::scenario_report::{
    ScenarioExpectation, VerifiedScenarioMath, verify_scenario_math_expected,
};

const BOOK: Id128 = Id128([0x6a; 16]);
const PRINCIPAL: VId = VId(106);
const NAME: &str = "but-for-additive-revenue";
const JAN: &str = "FY2026-P01";

fn day(month: u8, date: u8) -> DateDay {
    DateDay::from_ymd(2026, month, date).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

struct Fixture {
    book: Book,
    usd: UnitId,
    eur: UnitId,
    evidence: Document,
    assumption: Document,
}
impl Fixture {
    fn new() -> Self {
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let mut book = Book::create_memory(
            BookKeys::for_development(0x6a),
            BookSpec {
                book_id: BOOK,
                name: "Conditional scenario mathematics".into(),
                base_unit: usd,
                calendar: FiscalCalendar::monthly("scenario-math", 1, 0).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(106),
        )
        .unwrap();
        let accounts: Vec<_> = [("1000", 1), ("4000", 4), ("6000", 5)]
            .into_iter()
            .map(|(code, kind)| AccountSpec {
                code: code.into(),
                name: format!("Account {code}"),
                account_type: kind,
                normal_balance: u8::from(kind == 4),
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            })
            .collect();
        book.install_chart(
            &accounts,
            PRINCIPAL,
            day(1, 1),
            b"chart",
            &cap(&["schema_change"]),
        )
        .unwrap()
        .unwrap();
        book.create_periods(2026, PRINCIPAL, &cap(&["schema_change"]))
            .unwrap()
            .unwrap();
        for (period, key) in [(JAN, b"jan".as_slice()), ("FY2026-P02", b"feb".as_slice())] {
            book.transition_period(
                period,
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                key,
                &cap(&["close"]),
            )
            .unwrap()
            .unwrap();
        }
        let evidence = Document {
            book_id: BOOK,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Retained source invoice for conditional assumed entries".to_vec(),
        };
        let assumption = Document {
            book_id: BOOK,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Explicit but-for premise: additional sales and associated expense".to_vec(),
        };
        book.add_document(&evidence).unwrap().unwrap();
        book.add_document(&assumption).unwrap().unwrap();
        let mut f = Self {
            book,
            usd,
            eur,
            evidence,
            assumption,
        };
        f.post("source-sale", day(1, 5), "1000", "4000", 1000);
        f.post("source-cost", day(1, 6), "6000", "1000", 200);
        f
    }

    fn proposal(
        &self,
        key: &str,
        effective: DateDay,
        debit: &str,
        credit: &str,
        unit: UnitId,
        value: i128,
    ) -> EntryPayload {
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(BOOK, debit),
                Amount::new(unit, value),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(BOOK, credit),
                Amount::new(unit, value),
            ),
        ];
        EntryPayload {
            schema_minor: 0,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: effective,
            document_date: None,
            description: self.book.seal_text("Native scenario math fixture").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([0x6a; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![self.evidence.evidence_ref(1)],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            tags: Vec::new(),
            extensions: Vec::new(),
        }
    }

    fn post(&mut self, key: &str, date: DateDay, debit: &str, credit: &str, amount: i128) {
        let proposal = self.proposal(key, date, debit, credit, self.usd, amount);
        self.book
            .post(PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            })
            .unwrap()
            .unwrap();
    }

    fn open(&mut self) {
        self.book
            .open_scenario(
                cap(&["post"]),
                NAME,
                ScenarioFork {
                    at: None,
                    from: Some(day(1, 10)),
                    assumptions: vec![self.assumption.oid()],
                },
                day(1, 10),
                "Explicit additive assumptions",
            )
            .unwrap()
            .unwrap();
    }

    fn plan(
        &mut self,
        key: &str,
        date: DateDay,
        debit: &str,
        credit: &str,
        unit: UnitId,
        value: i128,
    ) {
        let intent = fa_intents::PostIntent::new(
            self.proposal(key, date, debit, credit, unit, value),
            Vec::new(),
        )
        .unwrap();
        self.book
            .run_in_scenario(cap(&["post"]), NAME, intent)
            .unwrap()
            .unwrap();
    }

    fn certify(&mut self, activity: bool) -> CertifiedScenarioDiff {
        self.book
            .certify_scenario_diff(
                PRINCIPAL,
                &cap(&["read", "produce"]),
                NAME,
                &[JAN.to_string()],
                activity,
            )
            .unwrap()
            .unwrap()
    }

    fn produce(&mut self, certificate: &ScenarioDiffCertificate) -> ProducedBundle {
        self.book
            .checkpoint(PRINCIPAL, &cap(&["read", "produce", "witness"]))
            .unwrap()
            .unwrap();
        self.book
            .produce_scenario_math_bundle(PRINCIPAL, &cap(&["read", "produce"]), None, certificate)
            .unwrap()
            .unwrap()
            .unwrap()
    }
}

fn question(report: &ScenarioDiff) -> ScenarioExpectation {
    let bytes = scenario_math_request(BOOK, report).unwrap();
    let expected = ScenarioExpectation::decode(&bytes).unwrap();
    assert_eq!(expected.encode().unwrap(), bytes);
    expected
}

fn verify(
    produced: &ProducedBundle,
    key: [u8; 32],
    expected: &ScenarioExpectation,
    pin: &[u8; 32],
) -> VerifiedScenarioMath {
    verify_scenario_math_expected(
        &produced.bundle.bytes,
        &[key],
        None,
        Some(&produced.receipt),
        expected,
        Some(pin),
    )
    .unwrap()
}

#[test]
fn signed_additive_scenario_replays_all_gross_columns_units_and_pinned_plans_without_book() {
    let mut f = Fixture::new();
    f.open();
    f.plan("assumed-sale", day(1, 15), "1000", "4000", f.usd, 500);
    f.plan("assumed-cost", day(1, 16), "6000", "1000", f.usd, 120);
    f.plan("outside-january", day(2, 5), "6000", "1000", f.usd, 40);
    f.plan("assumed-eur", day(1, 17), "1000", "4000", f.eur, 60);
    let certified = f.certify(false);
    let expected = question(&certified.report);
    let source_bytes = certified.certificate.canonical_bytes().unwrap();
    // Later trunk postings and later scenario plans do not enter this question.
    f.post("later-trunk", day(1, 18), "1000", "4000", 999);
    f.plan("later-plan", day(1, 19), "1000", "4000", f.usd, 9);
    let produced = f.produce(&certified.certificate);
    let key = f.book.checkpoint_public_key();
    let usd = f.usd.0;
    let eur = f.eur.0;
    drop(f);
    let replay = verify(&produced, key, &expected, certified.certificate.digest());
    assert_eq!(replay.output, certified.certificate.output());
    assert_eq!(
        certified.certificate.canonical_bytes().unwrap(),
        source_bytes
    );
    assert_eq!(replay.checked_intents, 4);
    assert_eq!(replay.checked_documents, 2);
    assert_eq!(replay.rows.len(), 5);
    let cash = replay
        .rows
        .iter()
        .find(|row| row.code == "1000" && row.unit == usd)
        .unwrap();
    assert_eq!(
        (
            cash.trunk_debits,
            cash.trunk_credits,
            cash.scenario_debits,
            cash.scenario_credits,
            cash.delta
        ),
        (1000, 200, 1500, 320, 380)
    );
    let costs = replay.rows.iter().find(|row| row.code == "6000").unwrap();
    assert_eq!(
        (costs.trunk_debits, costs.scenario_debits, costs.delta),
        (200, 320, 120)
    );
    assert_eq!(
        replay
            .rows
            .iter()
            .filter(|row| row.unit == eur)
            .map(|row| row.delta)
            .sum::<i128>(),
        0
    );
    assert!(replay.rows.iter().all(|row| row.trunk_debits_pending == 0
        && row.trunk_credits_pending == 0
        && row.scenario_debits_pending == 0
        && row.scenario_credits_pending == 0
        && row.pending_delta == 0));
    assert_eq!(replay.scope, "conditional_additive_scenario_math");
    assert_eq!(replay.historical_admission, "not_judged");
    assert_eq!(replay.native_marker_membership, "not_judged");
    assert!(replay.receipt.is_some());
    assert!(
        verify_scenario_math_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            None,
            &expected,
            Some(certified.certificate.digest())
        )
        .is_ok()
    );
    assert!(
        verify_scenario_math_expected(
            &produced.bundle.bytes,
            &[],
            None,
            Some(&produced.receipt),
            &expected,
            Some(certified.certificate.digest())
        )
        .is_err()
    );
    assert_eq!(
        verify_scenario_math_expected(&produced.bundle.bytes, &[key], None, None, &expected, None)
            .unwrap_err()
            .predicate,
        "scenario_input_authority"
    );
}

struct Parts {
    certificate: Vec<u8>,
    trunk: Vec<u8>,
    map: Vec<u8>,
    documents: Vec<ScenarioDocument>,
}
fn parts(bundle: &[u8]) -> Parts {
    let mut r = Reader::new(bundle);
    assert_eq!(
        r.bytes(64, "format").unwrap(),
        fa_notary::scenario::SCENARIO_MATH_BUNDLE_FORMAT
    );
    assert_eq!(
        r.str(64, "method").unwrap(),
        fa_notary::scenario::NATIVE_ORIGINAL_ADDITIVE_METHOD
    );
    let certificate = r.bytes(64 * 1024 * 1024, "certificate").unwrap().to_vec();
    let trunk = r.bytes(64 * 1024 * 1024, "trunk").unwrap().to_vec();
    let map = r.bytes(64 * 1024 * 1024, "map").unwrap().to_vec();
    let documents = r
        .list(65_536, "documents", |r| {
            Ok(ScenarioDocument {
                oid: Oid(r.fixed("oid")?),
                kind: r.u8("kind")?,
                bytes: r.bytes(64 * 1024 * 1024, "bytes")?.to_vec(),
            })
        })
        .unwrap();
    r.finish().unwrap();
    Parts {
        certificate,
        trunk,
        map,
        documents,
    }
}
impl Parts {
    fn bundle(&self) -> Vec<u8> {
        assemble(&self.certificate, &self.trunk, &self.map, &self.documents)
            .unwrap()
            .bytes
    }
    fn reseal(&mut self, mutate: impl FnOnce(&mut ScenarioDiffCertificate)) -> [u8; 32] {
        let mut certificate = ScenarioDiffCertificate::decode(&self.certificate).unwrap();
        mutate(&mut certificate);
        certificate.digest = domain_digest(DIGEST_DOMAIN, &[&certificate.body().unwrap()]);
        self.certificate = certificate.canonical_bytes().unwrap();
        certificate.digest
    }
}

#[test]
fn resealed_scenario_cannot_change_order_omit_a_plan_or_forge_output_and_documents() {
    let mut f = Fixture::new();
    f.open();
    f.plan("first", day(1, 12), "1000", "4000", f.usd, 30);
    f.plan("second", day(1, 13), "6000", "1000", f.usd, 7);
    f.plan("third", day(1, 14), "1000", "4000", f.usd, 11);
    let certified = f.certify(true);
    let expected = question(&certified.report);
    let produced = f.produce(&certified.certificate);
    let key = f.book.checkpoint_public_key();
    let intent = f.book.scenario(NAME).unwrap().unwrap().intents[0]
        .intent
        .canonical_bytes()
        .unwrap();
    drop(f);
    assert_eq!(
        verify(&produced, key, &expected, certified.certificate.digest()).checked_intents,
        3
    );
    let reject = |body: &Parts, pin: &[u8; 32]| {
        // Deliberately choose the forged certificate and question here, so
        // these negatives exercise journal/semantic replay beyond pin checks.
        let certificate = ScenarioDiffCertificate::decode(&body.certificate).unwrap();
        let mut selected = expected.clone();
        selected.intents = certificate.intents.len() as u64;
        let records: Vec<[u8; 16]> = certificate
            .intents
            .iter()
            .map(|record| record.0.to_le_bytes())
            .collect();
        let parts: Vec<&[u8]> = records.iter().map(<[u8; 16]>::as_slice).collect();
        selected.intents_digest = domain_digest(b"fa:scenario-intents:v1", &parts);
        verify_scenario_math_expected(&body.bundle(), &[key], None, None, &selected, Some(pin))
            .unwrap_err()
    };
    let mut forged = parts(&produced.bundle.bytes);
    let pin = forged.reseal(|certificate| certificate.intents.swap(0, 1));
    assert_eq!(reject(&forged, &pin).predicate, "scenario_intents");
    let mut forged = parts(&produced.bundle.bytes);
    let pin = forged.reseal(|certificate| {
        certificate.intents.remove(1);
    });
    assert_eq!(reject(&forged, &pin).predicate, "scenario_intents");
    let mut forged = parts(&produced.bundle.bytes);
    let pin = forged.reseal(|certificate| {
        let last = certificate.output.len() - 1;
        certificate.output[last] ^= 1;
    });
    assert_eq!(reject(&forged, &pin).predicate, "scenario_recomputation");
    let mut forged = parts(&produced.bundle.bytes);
    let pin = forged.reseal(|certificate| certificate.seq_map_digest = [0; 32]);
    assert_eq!(reject(&forged, &pin).predicate, "scenario_seq_map");
    let mut forged = parts(&produced.bundle.bytes);
    forged.documents[0].bytes[0] ^= 1;
    assert_eq!(
        reject(&forged, certified.certificate.digest()).predicate,
        "scenario_documents"
    );
    let mut forged = parts(&produced.bundle.bytes);
    forged.documents[0].kind ^= 1;
    assert_eq!(
        reject(&forged, certified.certificate.digest()).predicate,
        "scenario_documents"
    );
    let mut forged = parts(&produced.bundle.bytes);
    forged.documents.pop();
    assert_eq!(
        reject(&forged, certified.certificate.digest()).predicate,
        "scenario_documents"
    );
    let mut forged = parts(&produced.bundle.bytes);
    let at = forged
        .trunk
        .windows(intent.len())
        .position(|bytes| bytes == intent)
        .unwrap();
    forged.trunk[at + intent.len() - 1] ^= 1;
    assert_eq!(
        reject(&forged, certified.certificate.digest()).predicate,
        "record_derivation"
    );
    let mut wrong = expected.clone();
    wrong.activity = false;
    assert_eq!(
        verify_scenario_math_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            &wrong,
            Some(certified.certificate.digest())
        )
        .unwrap_err()
        .predicate,
        "scenario_request"
    );
    let mut wrong = expected.clone();
    wrong.from = Some(day(1, 11).0);
    assert_eq!(
        verify_scenario_math_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            &wrong,
            Some(certified.certificate.digest())
        )
        .unwrap_err()
        .predicate,
        "scenario_request"
    );
    let mut wrong = expected;
    wrong.method = "unrestricted-native-replay:v1".into();
    assert_eq!(
        verify_scenario_math_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            &wrong,
            Some(certified.certificate.digest())
        )
        .unwrap_err()
        .predicate,
        "scenario_request"
    );
}

#[test]
fn empty_and_outside_period_diffs_still_require_open_assumptions_and_complete_fork() {
    let mut f = Fixture::new();
    f.open();
    let empty = f.certify(false);
    assert!(empty.report.rows.is_empty());
    let expected = question(&empty.report);
    let produced = f.produce(&empty.certificate);
    let key = f.book.checkpoint_public_key();
    let verified = verify(&produced, key, &expected, empty.certificate.digest());
    assert!(verified.rows.is_empty());
    assert_eq!(
        (verified.checked_intents, verified.checked_documents),
        (0, 1)
    );
    assert!(verified.checked_records > 0);
    let mut omitted = parts(&produced.bundle.bytes);
    omitted.documents.clear();
    assert_eq!(
        verify_scenario_math_expected(
            &omitted.bundle(),
            &[key],
            None,
            None,
            &expected,
            Some(empty.certificate.digest())
        )
        .unwrap_err()
        .predicate,
        "scenario_documents"
    );
    f.plan("later-period-only", day(2, 5), "1000", "4000", f.usd, 44);
    let later_stock = f.certify(false);
    let later_stock_question = question(&later_stock.report);
    let outside = f.certify(true);
    let later_question = question(&outside.report);
    let earlier_question = question(&empty.report);
    assert!(
        verify_scenario_math_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            &earlier_question,
            None,
        )
        .is_ok()
    );
    assert_eq!(
        verify_scenario_math_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            &later_stock_question,
            None,
        )
        .unwrap_err()
        .predicate,
        "scenario_request"
    );
    let mut wrong_digest = earlier_question;
    wrong_digest.intents_digest[0] ^= 1;
    assert_eq!(
        verify_scenario_math_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            &wrong_digest,
            None,
        )
        .unwrap_err()
        .predicate,
        "scenario_request"
    );
    let produced = f.produce(&outside.certificate);
    let verified = verify(
        &produced,
        key,
        &later_question,
        outside.certificate.digest(),
    );
    assert_eq!(verified.checked_intents, 1);
    assert!(verified.rows.is_empty());
    assert_eq!(verified.checked_documents, 2);
    assert_eq!(
        f.book
            .replay_scenario_diff(PRINCIPAL, &cap(&["read"]), &empty.certificate)
            .unwrap()
            .unwrap(),
        empty.report
    );
}

#[test]
fn offsetting_assumptions_keep_changed_gross_columns_even_when_net_delta_is_zero() {
    let mut f = Fixture::new();
    f.open();
    f.plan("sale", day(1, 12), "1000", "4000", f.usd, 80);
    f.plan("refund", day(1, 13), "4000", "1000", f.usd, 80);
    let certified = f.certify(false);
    let produced = f.produce(&certified.certificate);
    let replay = verify(
        &produced,
        f.book.checkpoint_public_key(),
        &question(&certified.report),
        certified.certificate.digest(),
    );
    assert_eq!(replay.rows.len(), 2);
    assert!(replay.rows.iter().all(|row| row.delta == 0));
    let cash = replay.rows.iter().find(|row| row.code == "1000").unwrap();
    assert_eq!(
        (
            cash.trunk_debits,
            cash.trunk_credits,
            cash.scenario_debits,
            cash.scenario_credits
        ),
        (1000, 200, 1080, 280)
    );
    let revenue = replay.rows.iter().find(|row| row.code == "4000").unwrap();
    assert_eq!(
        (
            revenue.trunk_debits,
            revenue.trunk_credits,
            revenue.scenario_debits,
            revenue.scenario_credits
        ),
        (0, 1000, 80, 1080)
    );
}

#[test]
fn unsupported_assumption_version_and_missing_checkpoint_plan_coverage_refuse() {
    let mut f = Fixture::new();
    f.open();
    f.book
        .checkpoint(PRINCIPAL, &cap(&["read", "produce", "witness"]))
        .unwrap()
        .unwrap();
    f.plan("after-checkpoint", day(1, 12), "1000", "4000", f.usd, 13);
    let certified = f.certify(false);
    let refusal = f
        .book
        .produce_scenario_math_bundle(
            PRINCIPAL,
            &cap(&["read", "produce"]),
            None,
            &certified.certificate,
        )
        .unwrap()
        .unwrap_err();
    assert!(refusal.message.contains("checkpoint omits"), "{refusal:?}");
    let mut newer = f.proposal("newer-schema", day(1, 13), "1000", "4000", f.usd, 9);
    newer.schema_minor = 2;
    f.book
        .run_in_scenario(
            cap(&["post"]),
            NAME,
            fa_intents::PostIntent::new(newer, Vec::new()).unwrap(),
        )
        .unwrap()
        .unwrap();
    let unsupported = f.certify(false);
    let refusal = f
        .book
        .produce_scenario_math_bundle(
            PRINCIPAL,
            &cap(&["read", "produce"]),
            None,
            &unsupported.certificate,
        )
        .unwrap()
        .unwrap_err();
    assert!(
        refusal.message.contains("outside native-original-additive"),
        "{refusal:?}"
    );
    f.book
        .checkpoint(PRINCIPAL, &cap(&["read", "produce", "witness"]))
        .unwrap()
        .unwrap();
    let trunk = f
        .book
        .produce_report_bundle(
            PRINCIPAL,
            &cap(&["read", "produce"]),
            None,
            unsupported.certificate.trunk(),
        )
        .unwrap()
        .unwrap()
        .unwrap();
    let materialized = f.book.materialize_scenario(NAME).unwrap().unwrap();
    let mut documents = vec![&f.evidence, &f.assumption]
        .into_iter()
        .map(|document| ScenarioDocument {
            oid: document.oid(),
            kind: document.kind,
            bytes: document.bytes.clone(),
        })
        .collect::<Vec<_>>();
    documents.sort_by_key(|document| document.oid);
    let bundle = assemble(
        &unsupported.certificate.canonical_bytes().unwrap(),
        &trunk.bundle.bytes,
        &materialized.map.canonical_bytes().unwrap(),
        &documents,
    )
    .unwrap();
    assert_eq!(
        verify_scenario_math_expected(
            &bundle.bytes,
            &[f.book.checkpoint_public_key()],
            None,
            None,
            &question(&unsupported.report),
            Some(unsupported.certificate.digest())
        )
        .unwrap_err()
        .predicate,
        "scenario_profile"
    );
}
