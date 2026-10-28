//! A PPA is a current-period correction through retained earnings, bound
//! to the earlier period in the scenario that its case will approve.

use super::*;
use fa_journal::case::{CaseKind, derive_member};
use fa_journal::scenario::{Coordinates, MaterializeRefusal, materialize_into};
use fa_model::PeriodRef;

fn setup() -> (Harness, VId, VId) {
    let mut h = harness();
    let ctx = h.ctx();
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    let retained = account_vid(h.book.book_id, "3000");
    let capital = account_vid(h.book.book_id, "3100");
    let accounts =
        [("3000", "Retained earnings"), ("3100", "Share capital")].map(|(code, name)| {
            AccountSpec {
                code: code.into(),
                name: name.into(),
                account_type: fa_model::AccountType::EQUITY.0,
                normal_balance: 1,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(h.usd),
                parent_code: None,
                limit: None,
            }
        });
    let day = h.day();
    let description = Erasable::seal(
        &"PPA setup".to_string(),
        None,
        &h.book.seal_key,
        [91; 32],
        [92; 24],
    );
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &ctx,
            &h.book,
            &accounts,
            PRINCIPAL,
            day,
            b"ppa-equity-accounts",
            description.clone(),
            &schema,
        ))
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(create_periods(
            &mut h.db,
            &ctx,
            &h.book,
            2025,
            PRINCIPAL,
            description.clone(),
            &schema,
        ))
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(record_account_role(
            &mut h.db,
            &ctx,
            &h.book,
            &AccountRoleSpec {
                account: retained,
                role: "retained_earnings".into(),
                assigned: true,
            },
            PRINCIPAL,
            b"ppa-retained-earnings-role",
            description,
            &schema,
        ))
        .unwrap()
        .unwrap();
    (h, retained, capital)
}

fn source() -> PeriodRef {
    PeriodRef {
        calendar: "cal".into(),
        code: "FY2025-P12".into(),
    }
}

fn template(h: &Harness, debit: VId, credit: VId) -> EntryPayload {
    let mut proposal = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, debit, Amount::new(h.usd, 125)),
            LegPayload::simple(Side::Credit, credit, Amount::new(h.usd, 125)),
        ],
        b"ppa-correction",
        EntryClass::ORIGINAL,
    );
    proposal.with_prior_period_adjustment(&source()).unwrap();
    proposal
}

fn rehearse(h: &mut Harness, proposal: EntryPayload) -> Result<fa_model::Entry, Refusal> {
    let ctx = h.ctx();
    let keys = DatabaseKeys::new(
        [0xa1; 32],
        DatabaseSecurityNamespaceId([0xa2; 32]),
        [0xa3; 32],
    );
    let target = h
        .runtime
        .block_on(Database::open_memory(&ctx.commit(), keys))
        .unwrap();
    let request = h.request(proposal, &["post", "read", "restate"]);
    let frontier = h.db.frontier().unwrap();
    let result = h
        .runtime
        .block_on(materialize_into(
            &mut h.db,
            target,
            &ctx,
            &h.book,
            frontier,
            Coordinates::Protected,
            vec![request],
        ))
        .expect("rehearsal kernel");
    assert_eq!(
        h.db.frontier().unwrap(),
        frontier,
        "rehearsal leaves trunk intact"
    );
    match result {
        Ok((target, _, entries)) => {
            assert_eq!(entries.len(), 1);
            Ok(read_entry(&target, entries[0]).unwrap().unwrap().0)
        }
        Err(MaterializeRefusal::Intent(0, refusal)) => Err(refusal),
        Err(other) => panic!("unexpected materialization refusal: {other:?}"),
    }
}

#[test]
fn prior_period_adjustment_must_book_through_retained_earnings() {
    let (mut h, retained, capital) = setup();
    let cash = h.cash;
    // Both signs of a prior correction can be rehearsed, and the approved
    // source survives conversion from the template to the case's class.
    for (debit, credit) in [(retained, cash), (cash, retained)] {
        let planned = template(&h, debit, credit);
        let rehearsed = rehearse(&mut h, planned.clone()).unwrap();
        assert_eq!(
            rehearsed
                .proposal
                .prior_period_adjustment()
                .unwrap()
                .unwrap()
                .relates_to,
            source()
        );
        let member = derive_member(
            h.book.book_id,
            CaseKind::PriorPeriodAdjustment,
            1,
            VId(99),
            &planned,
            PRINCIPAL,
        )
        .unwrap()
        .unwrap();
        assert_eq!(member.class, EntryClass::PRIOR_PERIOD_ADJUSTMENT);
        assert_eq!(
            member.prior_period_adjustment().unwrap(),
            planned.prior_period_adjustment().unwrap()
        );
        assert_ne!(
            member.proposal_digest().unwrap(),
            planned.proposal_digest().unwrap()
        );
    }
    let cases = [
        (h.rent, retained, "current-income"),
        (retained, h.revenue, "current-income"),
        (cash, capital, "does not hold retained_earnings"),
        (retained, capital, "does not hold retained_earnings"),
        (cash, h.receivable, "no positive leg"),
    ];
    for (debit, credit, reason) in cases {
        let proposal = template(&h, debit, credit);
        let refusal = rehearse(&mut h, proposal).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-202", exit::REFUSAL));
        assert!(refusal.message.contains(reason), "{refusal}");
        assert!(refusal.fix.contains("retained_earnings"));
    }
    // A role is a journaled fact, not a name heuristic or a sticky cache:
    // removing it makes the same reviewed correction inadmissible.
    let ctx = h.ctx();
    h.runtime
        .block_on(record_account_role(
            &mut h.db,
            &ctx,
            &h.book,
            &AccountRoleSpec {
                account: retained,
                role: "retained_earnings".into(),
                assigned: false,
            },
            PRINCIPAL,
            b"ppa-remove-retained-earnings",
            Erasable::seal(
                &"retained earnings role removed".to_string(),
                None,
                &h.book.seal_key,
                [93; 32],
                [94; 24],
            ),
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let former = template(&h, retained, cash);
    let refusal = rehearse(&mut h, former).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-202", "{refusal}");
    assert!(refusal.message.contains("none assigned"), "{refusal}");
}

#[test]
fn prior_period_adjustment_requires_a_real_earlier_period_and_case_posting() {
    let (mut h, retained, _) = setup();
    let valid = template(&h, retained, h.cash);
    let head = h.db.frontier().unwrap();
    let request = h.request(valid.clone(), &["post", "read", "restate"]);
    let refusal = h.post(request).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-202", "{refusal}");
    assert!(refusal.message.contains("only inside its approved case"));
    assert_eq!(h.db.frontier().unwrap(), head);

    for (calendar, code, reason) in [
        ("foreign", "FY2025-P12", "calendar"),
        ("cal", "FY2024-P12", "has not been created"),
        ("cal", "not-a-period", "not a period"),
        ("cal", "FY2026-P03", "not earlier"),
        ("cal", "FY2026-P04", "not earlier"),
    ] {
        let mut invalid = valid.clone();
        invalid
            .with_prior_period_adjustment(&PeriodRef {
                calendar: calendar.into(),
                code: code.into(),
            })
            .unwrap();
        let refusal = rehearse(&mut h, invalid).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-202", "{refusal}");
        assert!(refusal.message.contains(reason), "{refusal}");
    }
    let mut missing = valid.clone();
    missing.extensions.clear();
    assert_eq!(
        derive_member(
            h.book.book_id,
            CaseKind::PriorPeriodAdjustment,
            1,
            VId(99),
            &missing,
            PRINCIPAL
        )
        .unwrap()
        .unwrap_err()
        .code,
        "FA-REF-202"
    );
    assert_eq!(
        derive_member(
            h.book.book_id,
            CaseKind::Revision,
            1,
            VId(99),
            &valid,
            PRINCIPAL
        )
        .unwrap()
        .unwrap_err()
        .code,
        "FA-REF-202"
    );
    missing.class = EntryClass::PRIOR_PERIOD_ADJUSTMENT;
    assert_eq!(rehearse(&mut h, missing).unwrap_err().code, "FA-REF-202");
}
