//! Persisted migration runs through the public facade and the actual fa CLI.
//! Setup posts through the kernel and obtains real approvals. Export must
//! prove the same balance as the literal register fold without writing.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa::book::{Book, BookKeys, Entropy};
use fa::{ProofKind, ProofRequest};
use fa_cli::json::{self, Json};
use fa_journal::migration::kind;
use fa_journal::{
    AccountSpec, BookSpec, Document, PostRequest, RunBody, RunControlRequest, RunMode,
    TrialBalanceLine, UnitPolicy, open_proposal,
};
use fa_model::{
    ApprovalRef, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid,
    PeriodRef, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_notary::StoredState;
use fa_policy::Capability;
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fa_verify::{Balance, Checkpoint};
use fgdb_types::VId;

const BOOK_ID: Id128 = Id128([0x62; 16]);
const PREPARER: VId = VId(7);
const OPENING: &str = "FY2026-OPEN";

fn day() -> DateDay {
    DateDay::from_ymd(2026, 1, 1).unwrap()
}

fn capability(ops: &[&str]) -> Capability {
    Capability::embedded(PREPARER, ops).unwrap()
}

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fa-migration-proof-cli-{}-{index}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

struct Fixture {
    path: PathBuf,
    usd: UnitId,
    evidence: EvidenceRef,
}

impl Fixture {
    fn new() -> Self {
        let path = directory().join("book");
        let keys = BookKeys::for_development(91);
        let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let mut book = Book::create_dir(
            &path,
            keys.clone(),
            BookSpec {
                book_id: BOOK_ID,
                name: "Migration proof integration".into(),
                base_unit: usd,
                calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(91),
        )
        .unwrap();
        keys.save(&path.join("book.keys")).unwrap();
        let accounts: Vec<_> = [("1000", 1, 0), ("2000", 2, 1), ("3000", 3, 1)]
            .into_iter()
            .map(|(code, account_type, normal_balance)| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type,
                normal_balance,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            })
            .collect();
        book.install_chart(&accounts, PREPARER, day(), b"chart")
            .unwrap()
            .unwrap();
        book.create_periods(2026).unwrap();
        for (index, transition) in [
            PeriodTransition::Open,
            PeriodTransition::SoftClose,
            PeriodTransition::Close,
        ]
        .into_iter()
        .enumerate()
        {
            book.transition_period(
                OPENING,
                transition,
                PREPARER,
                1,
                day(),
                format!("opening-{index}").as_bytes(),
                &capability(&["close"]),
            )
            .unwrap()
            .unwrap();
        }
        let lock = book
            .plan_transition(
                OPENING,
                PeriodTransition::Lock,
                PREPARER,
                1,
                day(),
                b"lock-opening",
            )
            .unwrap()
            .unwrap();
        let digest = book.plan_digest(&lock).unwrap();
        let approval = book
            .approve(Capability::embedded(VId(8), &["approve"]).unwrap(), digest)
            .unwrap()
            .unwrap()
            .approval();
        book.transition_planned(
            &lock,
            PeriodTransition::Lock,
            &capability(&["close"]),
            &[approval],
        )
        .unwrap()
        .unwrap();
        let source = Document {
            book_id: BOOK_ID,
            kind: 18,
            mime: "text/csv".into(),
            grade: 3,
            retrieved_by: PREPARER,
            bytes: b"account,unit,net\n1000,USD,5000\n3000,USD,-5000\n".to_vec(),
        };
        book.add_document(&source).unwrap().unwrap();
        Self {
            path,
            usd,
            evidence: source.evidence_ref(1),
        }
    }

    fn open(&self) -> Book {
        Book::open_dir(
            &self.path,
            BookKeys::load(&self.path.join("book.keys")).unwrap(),
            Entropy::deterministic(93),
        )
        .unwrap()
    }

    fn checkpoint(book: &mut Book) -> StoredState {
        book.checkpoint(PREPARER, &capability(&["witness"]))
            .unwrap()
            .unwrap()
            .stored
    }

    fn stage(&self, book: &mut Book) -> VId {
        let body = RunBody {
            book_id: BOOK_ID,
            run_key: "legacy-opening".into(),
            source_system: "legacy".into(),
            mode: RunMode::OpeningOnly,
            trial_balance: self.evidence.document_oid,
            opening_date: day(),
            lines: [("1000", 5_000), ("3000", -5_000)]
                .into_iter()
                .map(|(account, mantissa)| TrialBalanceLine {
                    account_code: account.into(),
                    unit: self.usd,
                    mantissa,
                })
                .collect(),
            periods: Vec::new(),
            detail_base: Vec::new(),
            sole_opening_source: false,
        };
        let proposal = open_proposal(
            book.context(),
            PREPARER,
            &body,
            vec![self.evidence],
            b"open-run",
            book.seal_text("Open migration").unwrap(),
        )
        .unwrap();
        book.open_migration_run(
            &body,
            RunControlRequest {
                proposal,
                capability: capability(&["post", "migrate"]),
                approvals: Vec::new(),
            },
        )
        .unwrap()
        .unwrap();
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(BOOK_ID, "1000"),
                Amount::new(self.usd, 5_000),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(BOOK_ID, "3000"),
                Amount::new(self.usd, 5_000),
            ),
        ];
        let proposal = EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: BOOK_ID,
            branch_id: Id128::TRUNK,
            class: EntryClass::MIGRATION,
            effective_date: day(),
            document_date: None,
            description: book.seal_text("Opening chunk").unwrap(),
            effective_period: Some(PeriodRef {
                calendar: "cal".into(),
                code: OPENING.into(),
            }),
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: b"opening-chunk".to_vec(),
            origin: EntryOrigin::Migration {
                run_ref: body.vid(),
                source_system: body.source_system.clone(),
                source_id: book.seal_text("legacy-JE-1").unwrap(),
                source_recorded_at_ns: Some(42),
                source_entered_by: None,
                source_approved_by: None,
                batch_oid: Oid([5; 32]),
            },
            principal_ref: PREPARER,
            session_ref: None,
            evidence: vec![self.evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let approvals = approve(book, &proposal);
        book.post(PostRequest {
            proposal,
            approvals,
            plan_certificate: None,
            capability: capability(&["post", "migrate"]),
        })
        .unwrap()
        .unwrap();
        body.vid()
    }

    fn terminal(book: &mut Book, run: VId, transition: u8) {
        let proposal = book
            .plan_migration_transition(
                run,
                transition,
                PREPARER,
                b"finish-run",
                book.seal_text("Finish migration").unwrap(),
            )
            .unwrap()
            .unwrap();
        let approvals = if transition == kind::FINALIZE {
            approve(book, &proposal)
        } else {
            Vec::new()
        };
        book.transition_migration_run(RunControlRequest {
            proposal,
            capability: capability(&["post", "migrate"]),
            approvals,
        })
        .unwrap()
        .unwrap();
    }

    fn export(&self, state: &StoredState, account: &str, cutoff: Option<&str>) -> Vec<u8> {
        let state_oid = fa_verify::blake3::hex(&state.oid.0);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fa"));
        cmd.arg("--book").arg(&self.path).args([
            "proof",
            "balance",
            "--state",
            &state_oid,
            "--account",
            account,
            "--unit",
            "USD",
            "--json",
        ]);
        if let Some(day) = cutoff {
            cmd.args(["--as-of", day]);
        }
        let output = cmd.env_remove("FA_BOOK").output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
        let lines: Vec<_> = stdout.lines().collect();
        assert_eq!(lines.len(), 1, "{stdout}\n{stderr}");
        fa_cli::verbs::registry()
            .unwrap()
            .check_line(lines[0])
            .unwrap();
        let value = json::parse(lines[0]).unwrap();
        assert_eq!(text(&value, "event"), "proof_exported");
        assert_eq!(text(&value, "signatures"), "unsigned");
        assert_eq!(text(&value, "trust"), "external_checkpoint_required");
        let bytes = unhex(text(&value, "bytes"));
        let book = self.open();
        let request = ProofRequest {
            state: Some(state.oid),
            kind: ProofKind::Balance {
                account: account_vid(BOOK_ID, account),
                unit: self.usd,
                effective_through: cutoff.map(|day| DateDay::parse(day).unwrap()),
            },
        };
        let artifact = book
            .export_proof(PREPARER, &capability(&["read", "produce"]), request)
            .unwrap()
            .unwrap();
        assert_eq!(
            artifact.bytes, bytes,
            "facade and CLI export identical bytes"
        );
        bytes
    }
}

fn approve(book: &mut Book, proposal: &EntryPayload) -> Vec<ApprovalRef> {
    let digest = proposal.proposal_digest().unwrap();
    [VId(8), VId(9)]
        .into_iter()
        .map(|principal| {
            book.approve(
                Capability::embedded(principal, &["approve"]).unwrap(),
                digest,
            )
            .unwrap()
            .unwrap()
            .approval()
        })
        .collect()
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get("data")
        .and_then(|data| data.get(key))
        .or_else(|| value.get(key))
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("missing {key}: {value:?}"))
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
        .collect()
}

fn anchor(state: &StoredState) -> Checkpoint {
    // The fixture retains the checkpoint at publication, separately from
    // the untrusted export. The export never establishes its own trust.
    Checkpoint {
        book_id: state.state.book_id.0,
        branch_id: state.state.branch_id.0,
        through_seq: state.state.through_seq.0,
        leaf_count: state.state.leaf_count,
        root: state.state.root,
    }
}

/// Facade balance exports are payload-complete v3 for every scope (69270c52,
/// fa-n6fh), with or without migration candidates: every prefix payload is
/// disclosed, so the independent verifier derives the scope and recomputes.
fn verified(bytes: &[u8], state: &StoredState, expected: i128) -> Balance {
    let format: &[u8] = b"fa:acc-balance-proof:v3";
    assert_eq!(
        &bytes[..4],
        &u32::try_from(format.len()).unwrap().to_le_bytes()
    );
    assert_eq!(&bytes[4..4 + format.len()], format);
    let report = fa_verify::verify_balance(bytes, &anchor(state)).unwrap();
    assert_eq!(report.scope, "recomputation");
    assert_eq!((report.claim.debits, report.claim.credits), (expected, 0));
    report
}

fn literal_cash(book: &Book) -> i128 {
    let fold = book.fold_period(OPENING).unwrap();
    fold.cells
        .iter()
        .find(|cell| cell.key.account == account_vid(BOOK_ID, "1000"))
        .map_or(0, |cell| cell.debits)
}

#[test]
fn persisted_migrations_export_before_and_after_finalize_or_abandon_without_writes() {
    for terminal in [kind::FINALIZE, kind::ABANDON] {
        let fixture = Fixture::new();
        let mut book = fixture.open();
        let before = Fixture::checkpoint(&mut book);
        let run = fixture.stage(&mut book);
        assert_eq!(literal_cash(&book), 0);
        let staged = Fixture::checkpoint(&mut book);
        Fixture::terminal(&mut book, run, terminal);
        let expected = if terminal == kind::FINALIZE { 5_000 } else { 0 };
        assert_eq!(literal_cash(&book), expected);
        let after = Fixture::checkpoint(&mut book);
        let head = book.head().unwrap();
        drop(book);

        verified(&fixture.export(&before, "1000", None), &before, 0);
        let original_staged = fixture.export(&staged, "1000", None);
        let staged_report = verified(&original_staged, &staged, 0);
        assert!(staged_report.contributing.is_empty());
        let final_bytes = fixture.export(&after, "1000", Some("2026-01-01"));
        let final_report = verified(&final_bytes, &after, expected);
        assert_eq!(
            final_report.contributing.len(),
            usize::from(terminal == kind::FINALIZE)
        );
        assert_eq!(fixture.export(&staged, "1000", None), original_staged);
        assert!(fa_verify::verify_balance(&final_bytes, &anchor(&staged)).is_err());
        verified(&fixture.export(&after, "2000", None), &after, 0);
        verified(
            &fixture.export(&after, "1000", Some("2025-12-31")),
            &after,
            0,
        );
        assert_eq!(
            fixture.open().head().unwrap(),
            head,
            "proof export is read-only"
        );
    }
}

#[test]
fn migration_proof_export_keeps_read_and_produce_authority_mandatory() {
    let fixture = Fixture::new();
    let mut book = fixture.open();
    fixture.stage(&mut book);
    let state = Fixture::checkpoint(&mut book);
    let request = ProofRequest {
        state: Some(state.oid),
        kind: ProofKind::Balance {
            account: account_vid(BOOK_ID, "1000"),
            unit: fixture.usd,
            effective_through: None,
        },
    };
    let head = book.head().unwrap();
    for ops in [&["read"][..], &["produce"][..]] {
        let refusal = book
            .export_proof(PREPARER, &capability(ops), request)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, 7);
        assert_eq!(book.head().unwrap(), head);
    }
    let allowed = book
        .export_proof(PREPARER, &capability(&["read", "produce"]), request)
        .unwrap()
        .unwrap();
    verified(&allowed.bytes, &state, 0);
    assert_eq!(book.head().unwrap(), head);
}
