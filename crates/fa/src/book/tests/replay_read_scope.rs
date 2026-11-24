//! A scenario's financial history stays at its fork while read authority is
//! checked on its current source. No issuance is copied into the replay.

use super::*;
use crate::{RollForwardRequest, SummaryRequest, SummaryScope, TrialBalanceSelection};
use fa_policy::{Op, Profile, possession_digest};

const HOLDER: VId = VId(70);
const ISSUER: VId = VId(71);

struct Fixture {
    source: Book,
    replay: Book,
    reader: Capability,
    issuer: Capability,
    unit: fa_money::UnitId,
    day: DateDay,
    original: VId,
    later: VId,
}

impl Fixture {
    fn new() -> Self {
        let (mut source, unit, day, original) = certified_fixture();
        let fork = source.head().unwrap();
        source
            .open_scenario(
                Capability::embedded(VId(1), &["post"]).unwrap(),
                "late-reader",
                fa_journal::ScenarioFork {
                    at: Some(fork),
                    ..fa_journal::ScenarioFork::default()
                },
                day,
                "Read a historical fork using authority issued afterward",
            )
            .unwrap()
            .unwrap();
        let issuer = Capability::embedded(ISSUER, &["issue_capability", "read"]).unwrap();
        let reader = bound_reader(source.context().book_id, HOLDER, 70);
        source
            .issue_capability(
                issuer.clone(),
                reader.clone(),
                day,
                b"late-scenario-reader",
                "Current authority for the original logical book",
            )
            .unwrap()
            .unwrap();
        let later = post_rent(
            &mut source,
            unit,
            VId(1),
            day,
            b"after-scenario-fork",
            150_000,
        )
        .unwrap()
        .unwrap()
        .entry_ref()
        .vid;
        let scenario = source.materialize_scenario("late-reader").unwrap().unwrap();
        assert_eq!(scenario.view.body.fork_at, fork);
        assert!(source.head().unwrap() > fork);
        Self {
            source,
            replay: scenario.book,
            reader,
            issuer,
            unit,
            day,
            original,
            later,
        }
    }

    fn issue(&mut self, capability: &Capability, key: &[u8]) {
        self.source
            .issue_capability(
                self.issuer.clone(),
                capability.clone(),
                self.day,
                key,
                "Scenario read regression",
            )
            .unwrap()
            .unwrap();
    }
}

fn bound_reader(book: Id128, holder: VId, secret: u8) -> Capability {
    Capability::new(holder, Profile::Human, &[Op::Read], ISSUER)
        .unwrap()
        .for_books(&[book])
        .unwrap()
        .holder_bound(possession_digest(&[secret; 32]))
}

#[test]
fn postfork_holder_bound_reader_reads_only_replay_data_without_importing_authority() {
    let f = Fixture::new();
    let periods = vec!["FY2026-P03".into()];
    let before_source = f.source.head().unwrap();
    let before_replay = f.replay.head().unwrap();
    let reader_bytes = f.reader.canonical_bytes().unwrap();
    let reader_commitment = f.reader.commitment().unwrap();
    assert!(
        f.source
            .issued_capability(&reader_commitment)
            .unwrap()
            .is_some()
    );
    assert!(
        f.replay
            .issued_capability(&reader_commitment)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.replay
            .read_scope(HOLDER, &f.reader)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-156"
    );

    let scope = f
        .source
        .read_scope_for_replay(&f.replay, HOLDER, &f.reader)
        .unwrap()
        .unwrap();
    assert_eq!(scope.capability().canonical_bytes().unwrap(), reader_bytes);
    assert_eq!(scope.capability().commitment().unwrap(), reader_commitment);
    assert_eq!(scope.capability().possession(), f.reader.possession());
    assert_eq!(scope.capability().holder(), HOLDER);
    assert_eq!(
        scope.read_entry(f.original, None).unwrap().unwrap(),
        f.replay.read_entry(f.original).unwrap()
    );
    assert!(scope.read_entry(f.later, None).unwrap().unwrap().is_none());
    assert!(f.source.read_entry(f.later).unwrap().is_some());
    let balance = scope.trial_balance_at(&periods, None).unwrap().unwrap();
    assert_eq!(balance, f.replay.trial_balance(&periods).unwrap());
    assert_ne!(balance.rows, f.source.trial_balance(&periods).unwrap().rows);

    let embedded = Capability::embedded(HOLDER, &["read"]).unwrap();
    let summary_request = SummaryRequest {
        selection: TrialBalanceSelection::Periods(periods.clone()),
        scope: SummaryScope::AllRoots,
        known_at: None,
    };
    assert_eq!(
        scope
            .summary_trial_balance(&summary_request)
            .unwrap()
            .unwrap(),
        f.replay
            .summary_trial_balance(HOLDER, &embedded, &summary_request)
            .unwrap()
            .unwrap(),
    );
    let roll_request = RollForwardRequest {
        accounts: vec![
            account_vid(f.replay.context().book_id, "1000"),
            account_vid(f.replay.context().book_id, "6000"),
        ],
        units: vec![f.unit.0],
        label: "Historical scenario movements".into(),
        effective_from: DateDay::from_ymd(2026, 3, 1).unwrap(),
        effective_through: DateDay::from_ymd(2026, 3, 31).unwrap(),
        known_at: None,
    };
    assert_eq!(
        scope.roll_forward(&roll_request).unwrap().unwrap(),
        f.replay
            .roll_forward(HOLDER, &embedded, &roll_request)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        scope.general_ledger(&roll_request).unwrap().unwrap(),
        f.replay
            .general_ledger(HOLDER, &embedded, &roll_request)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(f.source.head().unwrap(), before_source);
    assert_eq!(f.replay.head().unwrap(), before_replay);
    assert!(
        f.replay
            .issued_capability(&reader_commitment)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.replay.admit_current(&f.reader).unwrap().unwrap_err().code,
        "FA-REF-156",
        "a read scope must not install authority in the replay"
    );
}

#[test]
fn replay_scope_rejects_unissued_wrong_holder_foreign_book_and_incomplete_reach() {
    let mut f = Fixture::new();
    let (foreign_spec, _) = spec(Id128([0xf4; 16]));
    let foreign = Book::create_memory(
        BookKeys::for_development(0xf4),
        foreign_spec,
        Entropy::deterministic(244),
    )
    .unwrap();
    let unissued = bound_reader(f.source.context().book_id, VId(72), 72);
    assert_eq!(
        f.source
            .read_scope_for_replay(&foreign, unissued.holder(), &unissued)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-156",
        "current source authority must be checked before the target identity"
    );
    assert_eq!(
        f.source
            .read_scope_for_replay(&f.replay, VId(999), &f.reader)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-011"
    );
    let denied = f
        .source
        .read_scope_for_replay(&foreign, HOLDER, &f.reader)
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, "FA-REF-011");
    assert!(denied.message.contains("books"));

    // This narrow capability is genuinely issued: scope refusal cannot be
    // mistaken for the unissued-body failure of an edited bound token.
    let narrow = bound_reader(f.source.context().book_id, VId(73), 73)
        .for_periods(&["FY2026-P03"])
        .unwrap();
    f.issue(&narrow, b"issued-scoped-scenario-reader");
    assert_eq!(
        f.source
            .read_scope_for_replay(&f.replay, narrow.holder(), &narrow)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-011"
    );

    let owner = Capability::embedded(HOLDER, &["read"]).unwrap();
    let cases = [
        (
            "post only",
            Capability::embedded(HOLDER, &["post"]).unwrap(),
        ),
        ("accounts", owner.clone().for_accounts(&["1000"]).unwrap()),
        (
            "periods",
            owner.clone().for_periods(&["FY2026-P03"]).unwrap(),
        ),
        ("effective", owner.clone().effective_through(f.day)),
        (
            "classes",
            owner.clone().for_classes(&[EntryClass::ORIGINAL]).unwrap(),
        ),
        (
            "branch",
            owner.clone().on_branch(Id128([0x77; 16])).unwrap(),
        ),
        (
            "known-at",
            owner.clone().known_at_most(f.source.head().unwrap()),
        ),
        (
            "book",
            owner.for_books(&[foreign.context().book_id]).unwrap(),
        ),
    ];
    let before = (
        f.source.head().unwrap(),
        f.replay.head().unwrap(),
        foreign.head().unwrap(),
    );
    for (case, capability) in cases {
        assert_eq!(
            f.source
                .read_scope_for_replay(&f.replay, HOLDER, &capability)
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-011",
            "{case}"
        );
    }
    assert_eq!(
        (
            f.source.head().unwrap(),
            f.replay.head().unwrap(),
            foreign.head().unwrap()
        ),
        before
    );
}

#[test]
fn a_new_replay_scope_observes_leaf_and_issuer_revocation_on_current_source() {
    let mut f = Fixture::new();
    let sibling = bound_reader(f.source.context().book_id, VId(74), 74);
    f.issue(&sibling, b"sibling-scenario-reader");
    {
        let scope = f
            .source
            .read_scope_for_replay(&f.replay, HOLDER, &f.reader)
            .unwrap()
            .unwrap();
        assert!(
            scope
                .read_entry(f.original, None)
                .unwrap()
                .unwrap()
                .is_some()
        );
        // The immutable source borrow ends here. Advancing its single-writer
        // handle requires a fresh admission before another replay read.
    }
    f.source
        .revoke_capability(
            f.issuer.clone(),
            f.reader.commitment().unwrap(),
            f.day,
            b"revoke-scenario-reader",
            "Withdraw scenario read authority",
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        f.source
            .read_scope_for_replay(&f.replay, HOLDER, &f.reader)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-023"
    );
    f.source
        .read_scope_for_replay(&f.replay, sibling.holder(), &sibling)
        .unwrap()
        .unwrap();

    f.source
        .revoke_capability(
            Capability::embedded(VId(75), &["issue_capability"]).unwrap(),
            f.issuer.commitment().unwrap(),
            f.day,
            b"revoke-scenario-issuer",
            "Withdraw the original issuance ancestor",
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        f.source
            .read_scope_for_replay(&f.replay, sibling.holder(), &sibling)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-023"
    );
    assert!(
        f.replay
            .issued_capability(&sibling.commitment().unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn replay_authority_expires_at_the_current_source_head_not_the_historical_target() {
    let mut f = Fixture::new();
    let expiry = CommitSeq(f.source.head().unwrap().0 + 2);
    let expiring = bound_reader(f.source.context().book_id, VId(76), 76).expiring_at(expiry);
    f.issue(&expiring, b"expiring-scenario-reader");
    assert!(f.source.head().unwrap() < expiry);
    assert!(f.replay.head().unwrap() < expiry);
    {
        let scope = f
            .source
            .read_scope_for_replay(&f.replay, expiring.holder(), &expiring)
            .unwrap()
            .unwrap();
        assert!(
            scope
                .read_entry(f.original, None)
                .unwrap()
                .unwrap()
                .is_some()
        );
    }
    let before_replay = f.replay.head().unwrap();
    certificate_tick(&mut f.source, 1_000, true);
    assert!(f.source.head().unwrap() >= expiry);
    assert_eq!(
        f.source
            .read_scope_for_replay(&f.replay, expiring.holder(), &expiring)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-014"
    );
    assert_eq!(f.replay.head().unwrap(), before_replay);
    assert!(before_replay < expiry);
}
