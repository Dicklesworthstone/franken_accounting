//! Golden vectors for the accumulator's byte formats (fa-l3c).
//!
//! A synthetic journal — fixed entries at fixed commit sequences, built with
//! the model codec and no substrate, so the vectors move only when a format
//! moves — is accumulated, and its state objects and proofs must equal the
//! pinned bytes in `crates/fa-verify/tests/fixtures/accumulator_v1.txt`
//! exactly. The same file is verified by `fa-verify`'s own golden test with
//! nothing but the verifier, so the producer and the verifier are pinned to
//! one set of bytes from both sides. The vectors are never regenerated to
//! make a change pass: a format change is a new `v2` file.

use fa_model::{
    ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128,
    LegPayload, Oid, PeriodRef, SealKey,
};
use fa_money::{Amount, Side, UnitId};
use fa_notary::{AccumulatorState, Journal, state_oid};
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

const FIXTURE: &str = include_str!("../../fa-verify/tests/fixtures/accumulator_v1.txt");
const BOOK: Id128 = Id128([0x5a; 16]);
const KEY: SealKey = SealKey([0x33; 32]);

fn payload(class: EntryClass, legs: Vec<LegPayload>, key: &[u8]) -> EntryPayload {
    EntryPayload {
        schema_minor: 1,
        book_id: BOOK,
        branch_id: Id128::TRUNK,
        class,
        effective_date: DateDay(20_527),
        document_date: None,
        description: Erasable::seal(&"golden".to_string(), None, &KEY, [1; 32], [2; 24]),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([4; 32]),
            intent_kind: 1,
        },
        principal_ref: VId(7),
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

/// A control record for the codec vectors only. These records are never
/// staged: they pin the model codec's bytes, not an admissible journal — the
/// PeriodControl leaf's `control_kind` 1 would be refused by `entry_mirrors`
/// if it were staged (ruling 3412: the pinned bytes stay).
fn control(class: EntryClass, control: ControlPayload, key: &[u8]) -> Entry {
    let mut p = payload(class, Vec::new(), key);
    p.control = Some(control);
    p.origin = EntryOrigin::Control {
        control_kind: fa_model::ControlKind::CHART_INSTALL,
        spec_body_digest: [9; 32],
    };
    p.seal(Vec::new(), None).unwrap()
}

/// Four entries: a schema control (undated) at seq 2, a period opening at
/// seq 4, and two postings committed together at seq 5 — the second with
/// two units and three accounts, so the ordinal and the sorted, deduplicated
/// selection lists are all exercised.
fn records() -> Vec<(VId, Entry, CommitSeq)> {
    let usd = UnitId(1);
    let eur = UnitId(2);
    let (cash, rent, fx) = (VId(0x30), VId(0x10), VId(0x20));
    let schema = control(
        EntryClass::SCHEMA_CONTROL,
        ControlPayload::SchemaChange {
            kind: 1,
            canonical_bytes: vec![1, 2, 3],
        },
        b"chart",
    );
    let open = control(
        EntryClass::PERIOD_CONTROL,
        ControlPayload::PeriodTransition {
            period_ref: PeriodRef {
                calendar: "cal".into(),
                code: "FY2026-P03".into(),
            },
            from: 0,
            to: 1,
            reason_code: 1,
            case_ref: None,
        },
        b"open",
    );
    let rent_post = payload(
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, rent, Amount::new(usd, 120_000)),
            LegPayload::simple(Side::Credit, cash, Amount::new(usd, 120_000)),
        ],
        b"rent",
    )
    .seal(Vec::new(), None)
    .unwrap();
    let two_units = payload(
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, rent, Amount::new(eur, 500)),
            LegPayload::simple(Side::Credit, fx, Amount::new(eur, 500)),
            LegPayload::simple(Side::Debit, fx, Amount::new(usd, 550)),
            LegPayload::simple(Side::Credit, cash, Amount::new(usd, 550)),
        ],
        b"fx",
    )
    .seal(Vec::new(), None)
    .unwrap();
    // Deliberately out of order: the journal derives the order.
    vec![
        (VId(0x104), two_units, CommitSeq(5)),
        (VId(0x101), schema, CommitSeq(2)),
        (VId(0x103), rent_post, CommitSeq(5)),
        (VId(0x102), open, CommitSeq(4)),
    ]
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fixture(name: &str) -> String {
    FIXTURE
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' ').map(str::to_string))
        .unwrap_or_default()
}

#[test]
fn accumulator_formats_equal_the_pinned_vectors() {
    let full = Journal::from_records(BOOK, CommitSeq(6), records()).unwrap();
    let first_two: Vec<_> = records().into_iter().filter(|(_, _, s)| s.0 <= 4).collect();
    let early = Journal::from_records(BOOK, CommitSeq(4), first_two).unwrap();

    let ordinals: Vec<_> = full
        .leaves
        .iter()
        .map(|l| {
            (
                l.vid.0,
                l.envelope.commit_seq.0,
                l.envelope.within_commit_ordinal,
            )
        })
        .collect();
    assert_eq!(
        ordinals,
        vec![(0x101, 2, 0), (0x102, 4, 0), (0x103, 5, 0), (0x104, 5, 1)]
    );
    assert_eq!(full.leaves[0].envelope.effective_day, None);
    assert_eq!(full.leaves[3].envelope.unit_ids, vec![1, 2]);
    assert_eq!(
        full.leaves[3].envelope.account_vids,
        vec![VId(0x10), VId(0x20), VId(0x30)]
    );

    let old_state = AccumulatorState::of_journal(&early, None);
    let old_bytes = old_state.canonical_bytes().unwrap();
    let state = AccumulatorState::of_journal(&full, Some(state_oid(&old_bytes)));
    let state_bytes = state.canonical_bytes().unwrap();
    assert_eq!(AccumulatorState::decode(&state_bytes).unwrap(), state);

    let actual = [
        ("old_state", hex(&old_bytes)),
        ("state", hex(&state_bytes)),
        (
            "inclusion",
            hex(&full.inclusion_proof(VId(0x104), true).unwrap().unwrap()),
        ),
        (
            "consistency",
            hex(&full.consistency_proof(&early.statement()).unwrap().unwrap()),
        ),
        ("prefix", hex(&full.prefix_proof().unwrap())),
        (
            "balance",
            hex(&full.balance_proof(VId(0x30), 1, None).unwrap().unwrap()),
        ),
    ];
    let mut drift = Vec::new();
    for (name, bytes) in &actual {
        if fixture(name) != *bytes {
            drift.push(format!("{name} {bytes}"));
        }
    }
    assert!(
        drift.is_empty(),
        "accumulator bytes differ from the pinned v1 vectors:\n{}",
        drift.join("\n")
    );
}

/// Five postings, one per commit at sequences 1..=5: prefixes of 3 and 5
/// leaves, so the pinned consistency proof takes `consistent()`'s
/// non-power-of-two branch (the 2→4 vector above takes the other).
fn five_commits() -> Vec<(VId, Entry, CommitSeq)> {
    let usd = UnitId(1);
    (1..=5u8)
        .map(|i| {
            let entry = payload(
                EntryClass::ORIGINAL,
                vec![
                    LegPayload::simple(
                        Side::Debit,
                        VId(0x10),
                        Amount::new(usd, i128::from(i) * 100),
                    ),
                    LegPayload::simple(
                        Side::Credit,
                        VId(0x30),
                        Amount::new(usd, i128::from(i) * 100),
                    ),
                ],
                &[b'k', i],
            )
            .seal(Vec::new(), None)
            .unwrap();
            (VId(0x200 + u128::from(i)), entry, CommitSeq(u64::from(i)))
        })
        .collect()
}

#[test]
fn odd_sized_consistency_equals_the_pinned_vectors() {
    let three: Vec<_> = five_commits()
        .into_iter()
        .filter(|(_, _, s)| s.0 <= 3)
        .collect();
    let early = Journal::from_records(BOOK, CommitSeq(3), three).unwrap();
    let full = Journal::from_records(BOOK, CommitSeq(5), five_commits()).unwrap();
    assert_eq!((early.len(), full.len()), (3, 5));

    let s3 = AccumulatorState::of_journal(&early, None)
        .canonical_bytes()
        .unwrap();
    let s5 = AccumulatorState::of_journal(&full, Some(state_oid(&s3)))
        .canonical_bytes()
        .unwrap();
    let actual = [
        ("state_3", hex(&s3)),
        ("state_5", hex(&s5)),
        (
            "consistency_3_5",
            hex(&full.consistency_proof(&early.statement()).unwrap().unwrap()),
        ),
    ];
    let drift: Vec<String> = actual
        .iter()
        .filter(|(name, bytes)| fixture(name) != *bytes)
        .map(|(name, bytes)| format!("{name} {bytes}"))
        .collect();
    assert!(
        drift.is_empty(),
        "accumulator bytes differ from the pinned v1 vectors:\n{}",
        drift.join("\n")
    );
}

const CHECKPOINT_FIXTURE: &str = include_str!("../../fa-verify/tests/fixtures/checkpoint_v1.txt");

fn checkpoint_fixture(name: &str) -> String {
    CHECKPOINT_FIXTURE
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' ').map(str::to_string))
        .unwrap_or_default()
}

/// The signed checkpoint and scope-proof formats (fa-l3c slice 3): a
/// checkpoint over the pinned 4-leaf state, signed with a fixed key, and
/// three scope proofs over its index, must equal
/// `crates/fa-verify/tests/fixtures/checkpoint_v1.txt` byte for byte.
#[test]
fn checkpoint_formats_equal_the_pinned_vectors() {
    use fa_notary::checkpoint::CheckpointBody;
    use fa_notary::{ScopeIndex, SigningKey, TransparencyCheckpoint};

    let full = Journal::from_records(BOOK, CommitSeq(6), records()).unwrap();
    let first_two: Vec<_> = records().into_iter().filter(|(_, _, s)| s.0 <= 4).collect();
    let early = Journal::from_records(BOOK, CommitSeq(4), first_two).unwrap();
    let old_bytes = AccumulatorState::of_journal(&early, None)
        .canonical_bytes()
        .unwrap();
    let state = AccumulatorState::of_journal(&full, Some(state_oid(&old_bytes)));
    let index = ScopeIndex::of(&full);
    assert_eq!(index.tuples().len(), 5, "rent ×2, fx ×1, cash ×2");
    let key = SigningKey::from_seed(&[0x11; 32]);
    let body = CheckpointBody {
        statement: full.statement(),
        state_oid: state.oid().unwrap(),
        scope_index_root: index.root(),
        substrate_chain_commitment: [0xc0; 32],
        witness_policy_oid: None,
        time_evidence_oid: None,
    };
    let checkpoint = TransparencyCheckpoint::sign(body, &[&key]).unwrap();
    let bytes = checkpoint.canonical_bytes().unwrap();
    assert_eq!(TransparencyCheckpoint::decode(&bytes).unwrap(), checkpoint);

    let actual = [
        ("public_key", hex(&key.public_key())),
        ("checkpoint", hex(&bytes)),
        (
            "scope",
            hex(&index.proof(&full, 0x10, 20_527, 20_527).unwrap()),
        ),
        (
            "scope_empty",
            hex(&index.proof(&full, 0x20, 20_528, 20_600).unwrap()),
        ),
        (
            "scope_last",
            hex(&index.proof(&full, 0x30, i32::MIN, i32::MAX).unwrap()),
        ),
    ];
    let mut drift = Vec::new();
    for (name, bytes) in &actual {
        if !checkpoint_fixture(name).eq(bytes) {
            drift.push(format!("{name} {bytes}"));
        }
    }
    assert!(
        drift.is_empty(),
        "checkpoint bytes differ from the pinned v1 vectors:\n{}",
        drift.join("\n")
    );
}

const BUNDLE_FIXTURE: &str = include_str!("../../fa-verify/tests/fixtures/bundle_v1.txt");

fn bundle_fixture(name: &str) -> String {
    BUNDLE_FIXTURE
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' ').map(str::to_string))
        .unwrap_or_default()
}

/// The two documents the fifth posting cites: (kind, bytes).
const GOLDEN_DOCUMENTS: [(u8, &[u8]); 2] = [(1, b"INVOICE golden"), (1, b"LEASE golden")];

fn golden_document_oid(kind: u8, bytes: &[u8]) -> Oid {
    fa_journal::evidence::document_oid(BOOK, &fa_journal::evidence::doc_commit(kind, bytes))
}

/// `records()` and a fifth posting at seq 7, `Dr rent / Cr cash` 99.00 USD,
/// citing both documents.
fn bundle_records() -> Vec<(VId, Entry, CommitSeq)> {
    let usd = UnitId(1);
    let mut evidence: Vec<EvidenceRef> = GOLDEN_DOCUMENTS
        .iter()
        .map(|(kind, bytes)| EvidenceRef {
            document_oid: golden_document_oid(*kind, bytes),
            doc_commit: fa_journal::evidence::doc_commit(*kind, bytes),
            role: 1,
        })
        .collect();
    evidence.sort();
    let mut cited = payload(
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, VId(0x10), Amount::new(usd, 9_900)),
            LegPayload::simple(Side::Credit, VId(0x30), Amount::new(usd, 9_900)),
        ],
        b"cited",
    );
    cited.evidence = evidence;
    let mut all = records();
    all.push((
        VId(0x105),
        cited.seal(Vec::new(), None).unwrap(),
        CommitSeq(7),
    ));
    all
}

/// Every golden document, read whole: a stub reads only its kind and bytes.
fn golden_documents() -> std::collections::BTreeMap<Oid, fa_journal::DocumentRead> {
    GOLDEN_DOCUMENTS
        .iter()
        .map(|(kind, bytes)| {
            (
                golden_document_oid(*kind, bytes),
                fa_journal::DocumentRead::Full(fa_journal::Document {
                    book_id: BOOK,
                    kind: *kind,
                    mime: "text/plain".into(),
                    grade: 3,
                    retrieved_by: VId(0),
                    bytes: bytes.to_vec(),
                }),
            )
        })
        .collect()
}

/// The evidence bundle and production receipt formats (fa-l3c slice 5):
/// three bundles over a synthetic five-leaf journal against a checkpoint
/// signed with a fixed key, and a receipt over the first, must equal
/// `crates/fa-verify/tests/fixtures/bundle_v1.txt` byte for byte; and the
/// independent verifier accepts every one.
#[test]
fn bundle_formats_equal_the_pinned_vectors() {
    use fa_notary::bundle::{
        BalanceRequest, BundleRequest, BundleScope, ProductionReceipt, ReceiptBody, assemble,
        cited_documents,
    };
    use fa_notary::checkpoint::{CheckpointBody, checkpoint_oid, checkpoint_vid};
    use fa_notary::{
        ScopeIndex, ScopeRequest, SigningKey, StoredCheckpoint, TransparencyCheckpoint,
    };

    let journal = Journal::from_records(BOOK, CommitSeq(7), bundle_records()).unwrap();
    assert_eq!(journal.len(), 5);
    let state_oid = AccumulatorState::of_journal(&journal, None).oid().unwrap();
    let key = SigningKey::from_seed(&[0x11; 32]);
    let checkpoint = TransparencyCheckpoint::sign(
        CheckpointBody {
            statement: journal.statement(),
            state_oid,
            scope_index_root: ScopeIndex::of(&journal).root(),
            substrate_chain_commitment: [0xc0; 32],
            witness_policy_oid: None,
            time_evidence_oid: None,
        },
        &[&key],
    )
    .unwrap();
    let bytes = checkpoint.canonical_bytes().unwrap();
    let stored = StoredCheckpoint {
        oid: checkpoint_oid(&bytes),
        vid: checkpoint_vid(&state_oid),
        checkpoint,
        bytes,
    };
    let produce = |scope: BundleScope, balances: Vec<BalanceRequest>, inline_documents: bool| {
        let request = BundleRequest {
            scope,
            balances,
            inline_documents,
        };
        let documents = golden_documents();
        let cited = cited_documents(&journal, &request).unwrap().unwrap();
        assert!(cited.iter().all(|oid| documents.contains_key(oid)));
        assemble(&journal, &stored, &request, &documents)
            .unwrap()
            .unwrap()
    };
    let everything = BundleRequest {
        scope: BundleScope::Prefix,
        balances: Vec::new(),
        inline_documents: true,
    };
    let mut cited = cited_documents(&journal, &everything).unwrap().unwrap();
    cited.sort();
    let mut golden: Vec<Oid> = golden_documents().into_keys().collect();
    golden.sort();
    assert_eq!(
        cited, golden,
        "the prefix cites both golden documents, once each"
    );
    let prefix = produce(
        BundleScope::Prefix,
        vec![BalanceRequest {
            account: VId(0x30),
            unit: 1,
            effective_through: None,
        }],
        true,
    );
    let account = produce(
        BundleScope::Index(ScopeRequest::Account {
            account: VId(0x10),
            from: i32::MIN,
            to: i32::MAX,
        }),
        Vec::new(),
        false,
    );
    let entries = produce(
        BundleScope::Entries(vec![VId(0x105), VId(0x104)]),
        Vec::new(),
        true,
    );
    let receipt = ProductionReceipt::sign(
        ReceiptBody {
            bundle_digest: prefix.digest,
            producer_principal: VId(7),
            produced_at_seq: CommitSeq(9),
            capability_commitment: [0xcc; 32],
            time_evidence_oid: None,
        },
        &key,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    for b in [&prefix, &account, &entries] {
        let report = fa_verify::verify_bundle(&b.bytes, &[key.public_key()], None).unwrap();
        assert!(report.verified(), "{:#?}", report.checks);
    }

    let actual = [
        ("public_key", hex(&key.public_key())),
        ("bundle_prefix", hex(&prefix.bytes)),
        ("digest_prefix", hex(&prefix.digest)),
        ("bundle_account", hex(&account.bytes)),
        ("bundle_entries", hex(&entries.bytes)),
        ("receipt", hex(&receipt)),
    ];
    let drift: Vec<String> = actual
        .iter()
        .filter(|(name, bytes)| bundle_fixture(name) != *bytes)
        .map(|(name, bytes)| format!("{name} {bytes}"))
        .collect();
    assert!(
        drift.is_empty(),
        "bundle bytes differ from the pinned v1 vectors:\n{}",
        drift.join("\n")
    );
}
