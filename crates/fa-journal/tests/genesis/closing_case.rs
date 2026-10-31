//! Locked-period Closing is an exact singleton case computation. Rehearsal
//! exercises period and source laws without conveying trunk authority.

use super::*;
use fa_journal::closing::{YearEndCloseRequest, prepare_year_end_close_for_case};
use fa_journal::scenario::{Coordinates, MaterializeRefusal, materialize_into};

fn request() -> YearEndCloseRequest {
    YearEndCloseRequest {
        fiscal_year: 2026,
        closing_period: "FY2026-CLOSE".into(),
    }
}

fn authority() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "post", "restate"]).unwrap()
}

fn prepare(h: &Harness) -> fa_journal::closing::PreparedYearEndClose {
    prepare_year_end_close_for_case(&h.db, &h.ctx(), &h.book, &authority(), &request())
        .unwrap()
        .unwrap()
}

fn locked() -> (Harness, VId) {
    let (mut h, equity) = year_end_close_fixture();
    h.post(h.request(h.invoice(20_000, b"case-close-original"), &["post"]))
        .unwrap();
    let first = year_end_close_proposal(&h, &year_end_close_prepare(&h), b"case-first-close");
    h.post(h.request(first, &["read", "post", "close"]))
        .unwrap();
    h.post(h.request(h.invoice(3_000, b"case-close-later"), &["post"]))
        .unwrap();
    h.transition(
        "FY2026-CLOSE",
        PeriodTransition::Close,
        b"case-close-period",
    )
    .unwrap();
    h.transition("FY2026-CLOSE", PeriodTransition::Lock, b"case-lock-period")
        .unwrap();
    (h, equity)
}

fn rehearse(
    h: &mut Harness,
    proposals: Vec<EntryPayload>,
) -> Result<fa_journal::scenario::Materialized, MaterializeRefusal> {
    let ctx = h.ctx();
    let target = h
        .runtime
        .block_on(Database::open_memory(
            &ctx.commit(),
            DatabaseKeys::new(
                [0xb1; 32],
                DatabaseSecurityNamespaceId([0xb2; 32]),
                [0xb3; 32],
            ),
        ))
        .unwrap();
    let requests = proposals
        .into_iter()
        .map(|proposal| h.request(proposal, &["read", "post", "restate"]))
        .collect();
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
            requests,
        ))
        .unwrap();
    assert_eq!(
        h.db.frontier().unwrap(),
        frontier,
        "scratch cannot write trunk"
    );
    result
}

#[test]
fn locked_reclose_rehearses_exact_delta_but_cannot_publish_outside_its_case() {
    let (mut h, equity) = locked();
    let at = h.db.frontier().unwrap();
    assert!(year_end_close_verify(&h, None).needs_reclose);
    let prepared = prepare(&h);
    assert_eq!(h.db.frontier().unwrap(), at);
    assert_eq!(prepared.legs().len(), 2);
    assert!(
        prepared
            .residuals()
            .iter()
            .any(|row| row.account == h.revenue && row.net == -3_000)
    );
    let proposal = year_end_close_proposal(&h, &prepared, b"case-reclose");
    let (scratch, _, entries) = rehearse(&mut h, vec![proposal.clone()]).unwrap();
    assert_eq!(entries.len(), 1);
    let checked = fa_journal::closing::verify_year_end_close(
        &scratch,
        &h.ctx(),
        &h.book,
        &authority(),
        2026,
        None,
    )
    .unwrap()
    .unwrap();
    assert!(checked.is_green() && !checked.needs_reclose);
    assert_eq!(year_end_close_net(&h, h.revenue, at), -3_000);
    assert_eq!(year_end_close_net(&h, equity, at), -20_000);

    assert!(
        h.post_plan(h.request(proposal.clone(), &["read", "post", "close", "restate"]))
            .is_err()
    );
    assert!(
        h.post(h.request(proposal.clone(), &["read", "post", "close", "restate"]))
            .is_err()
    );
    let derived = derive_member(
        h.book.book_id,
        CaseKind::Restatement,
        1,
        VId(71),
        &proposal,
        PRINCIPAL,
    )
    .unwrap()
    .unwrap();
    assert_eq!(derived.class, EntryClass::CLOSING);
    assert_eq!(derived.legs, proposal.legs);
    assert_eq!(derived.extensions.len(), 2);
    assert_eq!(
        h.post(h.request(derived, &["read", "post", "close", "restate"]))
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CASE_MEMBERSHIP,
    );
    assert!(
        derive_member(
            h.book.book_id,
            CaseKind::PriorPeriodAdjustment,
            1,
            VId(71),
            &proposal,
            PRINCIPAL
        )
        .unwrap()
        .is_err()
    );
    assert_eq!(h.db.frontier().unwrap(), at);
}

#[test]
fn case_reclose_requires_current_whole_book_restate_and_a_locked_period() {
    let (h, _) = year_end_close_fixture();
    assert!(
        prepare_year_end_close_for_case(&h.db, &h.ctx(), &h.book, &authority(), &request())
            .unwrap()
            .is_err()
    );
    let (h, _) = locked();
    let at = h.db.frontier().unwrap();
    for denied in [
        Capability::embedded(PRINCIPAL, &["read", "post", "close"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["post", "restate"]).unwrap(),
        authority().for_accounts(&["4000", "3000"]).unwrap(),
        authority().known_at_most(at),
    ] {
        assert_eq!(
            prepare_year_end_close_for_case(&h.db, &h.ctx(), &h.book, &denied, &request())
                .unwrap()
                .unwrap_err()
                .exit,
            7
        );
    }
    assert_eq!(h.db.frontier().unwrap(), at);
}

#[test]
fn reclose_rehearsal_refuses_mixed_members_in_both_orders_and_changed_sources() {
    let (mut h, _) = locked();
    let proposal = year_end_close_proposal(&h, &prepare(&h), b"case-stale-reclose");
    let other = h.invoice(2_000, b"case-forbidden-sibling");
    for proposals in [
        vec![proposal.clone(), other.clone()],
        vec![other, proposal.clone()],
    ] {
        let Err(MaterializeRefusal::Intent(_, refusal)) = rehearse(&mut h, proposals) else {
            panic!("a mixed closing scenario must be refused");
        };
        assert_eq!(
            refusal.code,
            fa_journal::refusal::code::CLASS_NOT_IMPLEMENTED
        );
    }
    h.post(h.request(h.invoice(1_000, b"case-intervening-source"), &["post"]))
        .unwrap();
    let Err(MaterializeRefusal::Intent(0, refusal)) = rehearse(&mut h, vec![proposal]) else {
        panic!("an intervening source must invalidate the exact reviewed close");
    };
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert!(year_end_close_verify(&h, None).needs_reclose);
}
