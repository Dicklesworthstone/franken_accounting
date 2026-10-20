//! Existing-draft reviews retain exact historical source and reviewer authority.

#![forbid(unsafe_code)]

use fa::{
    Book, BookKeys, DRAFT_DIFF_CERTIFICATE_FORMAT, DraftDiffCertificate, Entropy,
    MAX_DRAFT_DIFF_CERTIFICATE_BYTES, ReportArtifact, ReportArtifactFamily,
};
use fa_intents::PostIntent;
use fa_journal::{AccountSpec, BookSpec, Document, DraftRehearsalSource, DraftState, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid,
    Reader, Writer, account_vid, domain_digest,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::{Capability, Op, Profile};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::{CommitSeq, VId};

const ADMIN: VId = VId(181);
const PLANNER: VId = VId(182);
const REVIEWER: VId = VId(183);
const DRAFT: &str = "review-january";
const PERIOD: &str = "FY2026-P01";

fn day() -> DateDay {
    DateDay::from_ymd(2026, 1, 15).unwrap()
}

fn cap(principal: VId, ops: &[&str]) -> Capability {
    Capability::embedded(principal, ops).unwrap()
}

fn planner() -> Capability {
    Capability::new(PLANNER, Profile::Agent, &[Op::Read, Op::Post], ADMIN).unwrap()
}

fn producer() -> Capability {
    cap(REVIEWER, &["read", "produce"])
}

fn account(code: &str, name: &str, kind: AccountType, unit: UnitId) -> AccountSpec {
    AccountSpec {
        code: code.into(),
        name: name.into(),
        account_type: kind.0,
        normal_balance: u8::from(kind == AccountType::EQUITY),
        is_leaf: true,
        unit_policy: UnitPolicy::Single(unit),
        parent_code: None,
        limit: None,
    }
}

struct Fixture {
    book: Book,
    usd: UnitId,
    evidence: EvidenceRef,
}

impl Fixture {
    fn new() -> Self {
        let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let book_id = Id128([181; 16]);
        let mut book = Book::create_memory(
            BookKeys::for_development(181),
            BookSpec {
                book_id,
                name: "Draft review facade".into(),
                base_unit: usd,
                calendar: FiscalCalendar::monthly("draft-review-facade", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(181),
        )
        .unwrap();
        let schema = cap(ADMIN, &["schema_change"]);
        book.install_chart(
            &[
                account("1000", "Cash", AccountType::ASSET, usd),
                account("6000", "Rent", AccountType::EXPENSE, usd),
            ],
            ADMIN,
            day(),
            b"chart",
            &schema,
        )
        .unwrap()
        .unwrap();
        book.create_periods(2026, ADMIN, &schema).unwrap().unwrap();
        book.transition_period(
            PERIOD,
            PeriodTransition::Open,
            ADMIN,
            1,
            b"open-period",
            &cap(ADMIN, &["close"]),
        )
        .unwrap()
        .unwrap();
        let document = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: ADMIN,
            bytes: b"Retained invoices for the exact January draft review".to_vec(),
        };
        book.add_document(&document).unwrap().unwrap();
        book.open_draft(planner(), DRAFT, day(), "January review")
            .unwrap()
            .unwrap();
        let mut fixture = Self {
            book,
            usd,
            evidence: document.evidence_ref(1),
        };
        fixture.plan(1_250, b"rent");
        fixture.plan(250, b"fees");
        // A real maintenance publication must keep its source position in
        // the rehearsal even though its register rows are not copied.
        let before = fixture.book.head().unwrap();
        let maintained_at = fixture.book.advance_registers(PERIOD).unwrap().published_at;
        assert!(maintained_at > before);
        fixture
    }

    fn plan(&mut self, amount: i128, key: &[u8]) {
        let book_id = self.book.context().book_id;
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, "6000"),
                Amount::new(self.usd, amount),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, "1000"),
                Amount::new(self.usd, amount),
            ),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(),
            document_date: None,
            description: self.book.seal_text("Reviewed expense").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([181; 32]),
                intent_kind: 1,
            },
            principal_ref: PLANNER,
            session_ref: None,
            evidence: vec![self.evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        self.book
            .plan_into_draft(
                planner(),
                DRAFT,
                PostIntent::new(proposal, Vec::new()).unwrap(),
            )
            .unwrap()
            .unwrap();
    }
}

#[test]
fn retained_review_replays_under_a_historical_ceiling_but_requires_current_authority() {
    let mut f = Fixture::new();
    let original_head = f.book.head().unwrap();
    let source_draft = f.book.draft(DRAFT).unwrap().unwrap();
    let source_tb = f.book.trial_balance(&[PERIOD.into()]).unwrap();
    let certified = f
        .book
        .certify_draft_diff(REVIEWER, &producer(), DRAFT, PERIOD)
        .unwrap()
        .unwrap();
    assert_eq!(f.book.head().unwrap(), original_head);
    assert_eq!(f.book.draft(DRAFT).unwrap().unwrap(), source_draft);
    assert_eq!(f.book.trial_balance(&[PERIOD.into()]).unwrap(), source_tb);
    let report = certified.report;
    assert_eq!(report.source_known_at, original_head);
    assert_eq!(report.rehearsal_known_at, CommitSeq(original_head.0 + 1));
    assert_eq!(report.plans, 2);
    assert_eq!(report.entries.len(), 2);
    assert_eq!(
        report
            .rows
            .iter()
            .map(|row| (row.code.as_str(), row.delta, row.pending_delta))
            .collect::<Vec<_>>(),
        [("1000", -1_500, 0), ("6000", 1_500, 0)],
    );
    let bytes = certified.certificate.canonical_bytes().unwrap();
    let certificate = DraftDiffCertificate::decode(&bytes).unwrap();
    assert_eq!(certificate, certified.certificate);
    assert_eq!(certificate.output(), report.canonical_bytes().unwrap());
    let retained = f
        .book
        .retain_draft_diff(REVIEWER, &producer(), &certificate)
        .unwrap()
        .unwrap();
    assert_eq!(retained.digest, *certificate.digest());
    assert_eq!(retained.recorded_at, CommitSeq(original_head.0 + 1));
    let artifact = f
        .book
        .read_report_artifact(REVIEWER, &cap(REVIEWER, &["read"]), &retained.digest)
        .unwrap()
        .unwrap();
    assert_eq!(artifact.family(), ReportArtifactFamily::DraftDiff);
    assert_eq!(artifact.canonical_bytes().unwrap(), bytes);
    assert_eq!(ReportArtifact::decode(&bytes).unwrap(), artifact);
    assert_eq!(
        f.book
            .retain_draft_diff(REVIEWER, &producer(), &certificate)
            .unwrap()
            .unwrap(),
        retained,
    );
    assert_eq!(f.book.head().unwrap(), retained.recorded_at);

    f.book
        .open_account(
            &account("1100", "Later cash account", AccountType::ASSET, f.usd),
            day(),
            None,
            ADMIN,
            day(),
            b"later-account",
            &cap(ADMIN, &["schema_change"]),
        )
        .unwrap()
        .unwrap();
    f.plan(999, b"later-plan");
    assert_eq!(f.book.draft(DRAFT).unwrap().unwrap().intents.len(), 3);
    f.book
        .discard_draft(planner(), DRAFT, day(), "Later draft decision")
        .unwrap()
        .unwrap();
    assert_eq!(
        f.book.draft(DRAFT).unwrap().unwrap().state,
        DraftState::Discarded
    );
    let head = f.book.head().unwrap();
    assert!(head > certificate.known_at());
    let reader = cap(REVIEWER, &["read"])
        .known_at_most(certificate.known_at())
        .on_branch(Id128::TRUNK)
        .unwrap();
    assert_eq!(
        f.book
            .replay_draft_diff(REVIEWER, &reader, &certificate)
            .unwrap()
            .unwrap(),
        report,
    );
    assert_eq!(f.book.head().unwrap(), head);
    // The supplied typed certificate selects its historical source. These
    // separate HEAD operations deliberately retain their narrower contract.
    for refusal in [
        f.book
            .draft_diff(REVIEWER, &reader, DRAFT, PERIOD)
            .unwrap()
            .unwrap_err(),
        f.book
            .read_report_artifact(REVIEWER, &reader, &retained.digest)
            .unwrap()
            .unwrap_err(),
    ] {
        assert_eq!(refusal.code, "FA-REF-011", "{refusal}");
        assert!(refusal.message.contains("known_at"), "{refusal}");
    }
    let expired = reader.clone().expiring_at(head);
    let refusal = f
        .book
        .replay_draft_diff(REVIEWER, &expired, &certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-014", "{refusal}");
    assert_eq!(f.book.head().unwrap(), head);
    f.book
        .revoke_capability(
            cap(ADMIN, &["issue_capability"]),
            reader.commitment().unwrap(),
            day(),
            b"revoke-historical-reviewer",
            "Revoke the exact historical reviewer capability",
        )
        .unwrap()
        .unwrap();
    let revoked_at = f.book.head().unwrap();
    let refusal = f
        .book
        .replay_draft_diff(REVIEWER, &reader, &certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-023", "{refusal}");
    assert_eq!(f.book.head().unwrap(), revoked_at);
}

/// Rebuild an otherwise valid outer container, including its public digest.
/// This intentionally passes decoding so only full historical replay can
/// distinguish the invented source/map/result from a genuine rehearsal.
fn forged(certificate: &DraftDiffCertificate, change: &str) -> DraftDiffCertificate {
    let bytes = certificate.canonical_bytes().unwrap();
    let mut r = Reader::new(&bytes);
    assert_eq!(
        r.bytes(64, "format").unwrap(),
        DRAFT_DIFF_CERTIFICATE_FORMAT
    );
    let trunk = r.bytes(MAX_DRAFT_DIFF_CERTIFICATE_BYTES, "trunk").unwrap();
    let mut source =
        DraftRehearsalSource::decode(r.bytes(MAX_DRAFT_DIFF_CERTIFICATE_BYTES, "source").unwrap())
            .unwrap();
    let mut map: [u8; 32] = r.fixed("map").unwrap();
    let head = r.u64("head").unwrap();
    let principal = r.u128("principal").unwrap();
    let authority: [u8; 32] = r.fixed("authority").unwrap();
    let mut output = r
        .bytes(MAX_DRAFT_DIFF_CERTIFICATE_BYTES, "output")
        .unwrap()
        .to_vec();
    let _: [u8; 32] = r.fixed("digest").unwrap();
    r.finish().unwrap();
    match change {
        "source" => source.plans[0].entry_ref.entry_digest[0] ^= 1,
        "map" => map[0] ^= 1,
        "output" => *output.last_mut().unwrap() ^= 1,
        _ => unreachable!(),
    }
    let mut w = Writer::new();
    w.bytes(DRAFT_DIFF_CERTIFICATE_FORMAT)
        .bytes(trunk)
        .bytes(&source.canonical_bytes().unwrap())
        .fixed(&map)
        .u64(head)
        .u128(principal)
        .fixed(&authority)
        .bytes(&output);
    let mut bytes = w.finish().unwrap();
    let digest = domain_digest(b"fa:draft-diff-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    DraftDiffCertificate::decode(&bytes).unwrap()
}

#[test]
fn replay_and_retention_refuse_rehashed_source_map_or_output_substitution() {
    let mut f = Fixture::new();
    let certified = f
        .book
        .certify_draft_diff(REVIEWER, &producer(), DRAFT, PERIOD)
        .unwrap()
        .unwrap();
    let head = f.book.head().unwrap();
    let before = f.book.draft(DRAFT).unwrap().unwrap();
    for change in ["source", "map", "output"] {
        let certificate = forged(&certified.certificate, change);
        assert_ne!(certificate.digest(), certified.certificate.digest());
        for refusal in [
            f.book
                .replay_draft_diff(REVIEWER, &cap(REVIEWER, &["read"]), &certificate)
                .unwrap()
                .unwrap_err(),
            f.book
                .retain_draft_diff(REVIEWER, &producer(), &certificate)
                .unwrap()
                .unwrap_err(),
        ] {
            assert_eq!(
                refusal.code,
                fa::certificate::code::CERTIFICATE_INVALID,
                "{change}: {refusal}"
            );
            assert_eq!(
                refusal.exit,
                fa_journal::exit::VERIFICATION,
                "{change}: {refusal}"
            );
        }
        assert_eq!(f.book.head().unwrap(), head, "{change}");
        assert_eq!(f.book.draft(DRAFT).unwrap().unwrap(), before, "{change}");
    }
    assert_eq!(
        f.book
            .replay_draft_diff(REVIEWER, &cap(REVIEWER, &["read"]), &certified.certificate)
            .unwrap()
            .unwrap(),
        certified.report,
    );
    assert_eq!(f.book.head().unwrap(), head);
}
