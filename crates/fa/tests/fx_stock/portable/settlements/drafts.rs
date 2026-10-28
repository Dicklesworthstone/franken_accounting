//! Foreign drafts are reviewable at an exact historical prefix before their
//! independently authorized promotion, with the original carrying law intact.

use super::*;
use std::collections::BTreeMap;

use fa::{DraftDiffCertificate, TrialBalanceSelection};
use fa_intents::PostIntent;
use fa_policy::{Op, Profile};

const PLANNER: VId = VId(181);
const REVIEWER: VId = VId(182);
const DRAFT: &str = "foreign-collections";
const PERIOD: &str = "FY2026-P01";

fn planner() -> Capability {
    Capability::new(PLANNER, Profile::Agent, &[Op::Read, Op::Post], PRINCIPAL).unwrap()
}

fn reviewer(ops: &[&str]) -> Capability {
    Capability::embedded(REVIEWER, ops).unwrap()
}

fn planned_fixture(numerator: u128, second_amount: i128) -> (Fixture, [EntryRef; 2], Oid) {
    let mut fixture = settlement_fixture();
    let targets = [
        fixture.post(b"draft-first-invoice", day(1, 5), 3, numerator),
        fixture.post(b"draft-second-invoice", day(1, 5), 3, numerator),
    ];
    let rate = settlement_rate(&mut fixture);
    fixture
        .book
        .open_draft(planner(), DRAFT, day(1, 15), "Foreign collections")
        .unwrap()
        .unwrap();
    for (target, amount, key) in [
        (targets[0], 1, b"draft-first-payment".as_slice()),
        (
            targets[1],
            second_amount,
            b"draft-second-payment".as_slice(),
        ),
    ] {
        let request = application(&fixture, target, amount, rate);
        let mut proposal = template(&fixture, key, day(1, 15));
        proposal.principal_ref = PLANNER;
        let prepared = fixture
            .book
            .prepare_fx_settlement(&planner(), &request, proposal)
            .unwrap()
            .unwrap();
        fixture
            .book
            .plan_into_draft(
                planner(),
                DRAFT,
                PostIntent::new(prepared.into_proposal(), Vec::new()).unwrap(),
            )
            .unwrap()
            .unwrap();
    }
    (fixture, targets, rate)
}

fn functional_balances(book: &mut Book) -> BTreeMap<String, i128> {
    let report = book
        .functional_trial_balance(
            &reviewer(&["read"]),
            TrialBalanceSelection::AsOf(day(1, 31)),
            None,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        report.total_debits().unwrap(),
        report.total_credits().unwrap()
    );
    assert!(report.pending.is_empty());
    report
        .cells
        .iter()
        .map(|cell| {
            assert_eq!(cell.unit_id, report.base_unit.0);
            assert!(cell.entity.is_none());
            (
                report.accounts[&cell.account].code.clone(),
                cell.net().unwrap(),
            )
        })
        .collect()
}

#[test]
fn foreign_draft_review_preserves_carrying_reports_and_original_trunk() {
    for (numerator, base, second_amount, remaining, cash, realized, relief) in
        [(33, 10, 3, [2, 0], 8, 5, 13), (3, 1, 1, [2, 2], 4, -4, 0)]
    {
        let (mut fixture, targets, _) = planned_fixture(numerator, second_amount);
        // A maintenance publication is omitted as data but must retain its
        // sequence, including the Rate document and planner coordinates.
        fixture
            .book
            .advance_registers(PRINCIPAL, &cap(&["read", "verify", "maintain"]), PERIOD)
            .unwrap()
            .unwrap();
        let before = fixture.book.head().unwrap();
        let original_draft = fixture.book.draft(DRAFT).unwrap().unwrap();
        let original_tb = fixture.book.trial_balance(&[PERIOD.into()]).unwrap();
        let original_items = fixture.book.open_items(None, None).unwrap();
        let certified = fixture
            .book
            .certify_draft_diff(REVIEWER, &reviewer(&["read", "produce"]), DRAFT, PERIOD)
            .unwrap()
            .unwrap();
        let certificate =
            DraftDiffCertificate::decode(&certified.certificate.canonical_bytes().unwrap())
                .unwrap();
        let (mut scratch, rehearsal) = fixture
            .book
            .rehearse_draft_at(REVIEWER, &reviewer(&["read"]), DRAFT, before)
            .unwrap()
            .unwrap();
        assert_eq!(rehearsal.source.known_at, before);
        assert_eq!(rehearsal.batch.recorded_at, CommitSeq(before.0 + 1));
        assert_eq!(rehearsal.batch.entries, certified.report.entries);
        assert_eq!(rehearsal.view, original_draft);
        assert!(
            rehearsal
                .seq_map
                .pairs
                .iter()
                .all(|pair| pair.source_seq == pair.scratch_seq)
        );
        assert!(scratch.verify_fx_conversions(None).unwrap().is_green());
        let items = scratch.open_items(None, None).unwrap();
        for (target, expected) in targets.into_iter().zip(remaining) {
            let item = items
                .iter()
                .find(|item| item.entry == target.vid && item.ordinal == 0)
                .unwrap();
            assert_eq!(item.open, expected);
        }
        let expected = BTreeMap::from([
            ("1000".to_string(), cash),
            ("1200".to_string(), base * 2 - relief),
            ("1299".to_string(), 0),
            ("4000".to_string(), -base * 2),
            ("4900".to_string(), realized),
        ]);
        assert_eq!(functional_balances(&mut scratch), expected);
        let mut expected_deltas = BTreeMap::from([
            (("1000", fixture.usd.0), cash),
            (("1200", fixture.eur.0), -(1 + second_amount)),
            (("1299", fixture.eur.0), 1 + second_amount),
            (("4900", fixture.usd.0), realized),
        ]);
        if relief != 0 {
            expected_deltas.insert(("1299", fixture.usd.0), -relief);
        }
        assert_eq!(
            certified
                .report
                .rows
                .iter()
                .map(|row| ((row.code.as_str(), row.unit_id), row.delta))
                .collect::<BTreeMap<_, _>>(),
            expected_deltas
        );
        assert_eq!(fixture.book.head().unwrap(), before);
        assert_eq!(fixture.book.draft(DRAFT).unwrap().unwrap(), original_draft);
        assert_eq!(
            fixture.book.trial_balance(&[PERIOD.into()]).unwrap(),
            original_tb
        );
        assert_eq!(fixture.book.open_items(None, None).unwrap(), original_items);
        for entry in &rehearsal.batch.entries {
            assert!(fixture.book.read_entry(entry.vid).unwrap().is_none());
        }

        let promoted = fixture
            .book
            .promote_draft(
                reviewer(&["read", "approve"]),
                DRAFT,
                day(1, 15),
                "Reviewed FX receipts",
            )
            .unwrap()
            .unwrap();
        assert_eq!(promoted.entries, rehearsal.batch.entries);
        assert_eq!(functional_balances(&mut fixture.book), expected);
        assert_eq!(
            fixture
                .book
                .replay_draft_diff(REVIEWER, &reviewer(&["read"]), &certificate)
                .unwrap()
                .unwrap(),
            certified.report
        );
        assert_eq!(fixture.book.head().unwrap(), promoted.recorded_at);

        // The promoted effects also remain readable by the independent,
        // dependency-free verifier from their retained functional report.
        let functional = certify(&mut fixture, TrialBalanceSelection::AsOf(day(1, 31)));
        let state = checkpoint(&mut fixture.book);
        let produced = produce(&mut fixture, state, &functional);
        let verified = verify(&fixture, &produced, &functional);
        assert_eq!(verified.output, functional.output);
        let book_id = fixture.book.context().book_id;
        let cells = verified.functional_trial_balance.unwrap().cells;
        for (code, amount) in &expected {
            let cell = cells
                .iter()
                .find(|cell| cell.account == account_vid(book_id, code).0)
                .unwrap();
            assert_eq!(cell.debits.checked_sub(cell.credits).unwrap(), *amount);
        }
    }
}

#[test]
fn foreign_draft_review_refuses_current_drift_but_replays_the_certified_prefix() {
    for change in ["carrying", "revocation"] {
        let (mut fixture, targets, rate) = planned_fixture(33, 1);
        let certified = fixture
            .book
            .certify_draft_diff(REVIEWER, &reviewer(&["read", "produce"]), DRAFT, PERIOD)
            .unwrap()
            .unwrap();
        if change == "carrying" {
            let request = application(&fixture, targets[1], 1, rate);
            pay(&mut fixture, &request, b"competing-receipt", day(1, 15), 3);
        } else {
            fixture
                .book
                .revoke_capability(
                    cap(&["issue_capability"]),
                    planner().commitment().unwrap(),
                    day(1, 15),
                    b"revoked-fx-planner",
                    "Planner authority revoked after review",
                )
                .unwrap()
                .unwrap();
        }
        let before = fixture.book.head().unwrap();
        let original = fixture.book.draft(DRAFT).unwrap().unwrap();
        let refusal = fixture
            .book
            .draft_diff(REVIEWER, &reviewer(&["read"]), DRAFT, PERIOD)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refusal.code,
            if change == "carrying" {
                "FA-REF-071"
            } else {
                "FA-REF-023"
            }
        );
        assert_eq!(fixture.book.head().unwrap(), before);
        assert_eq!(fixture.book.draft(DRAFT).unwrap().unwrap(), original);
        for entry in &certified.report.entries {
            assert!(fixture.book.read_entry(entry.vid).unwrap().is_none());
        }
        assert_eq!(
            fixture
                .book
                .replay_draft_diff(REVIEWER, &reviewer(&["read"]), &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report
        );
        assert_eq!(fixture.book.head().unwrap(), before);
    }
}
