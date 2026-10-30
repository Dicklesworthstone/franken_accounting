//! Carrying-close regressions use native postings and an independent two-measure
//! journal fold. The close never receives a new rate or caller-supplied value.

use super::*;
use fa_journal::closing::{YearEndCloseRequest, prepare_year_end_close, verify_year_end_close};
use fa_journal::fx::{FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms, value_proposal};
use fa_money::RoundingLaw;
use fa_money::rate::{ArithmeticBudget, BudgetLimits};

struct Fixture {
    h: Harness,
    foreign: UnitId,
    nominal: VId,
    counterparty: VId,
    equity: VId,
}

fn fixture() -> Fixture {
    fixture_with_foreign_only_routes(false)
}

#[test]
fn carrying_close_draft_preserves_both_measures_under_independent_closing_authority() {
    let mut f = fixture();
    f.source(Side::Credit, 1_000, 1_250, b"draft-carrying-sale");
    f.source(Side::Debit, 400, 520, b"draft-carrying-return");
    let agent = f.h.agent_capability();
    let prepared = fa_journal::closing::prepare_year_end_close_for_draft(
        &f.h.db,
        &f.h.ctx(),
        &f.h.book,
        &agent,
        &YearEndCloseRequest {
            fiscal_year: 2026,
            closing_period: "FY2026-CLOSE".into(),
        },
    )
    .unwrap()
    .unwrap();
    let mut proposal = year_end_close_proposal(&f.h, &prepared, b"draft-carrying-close");
    proposal.principal_ref = AGENT;
    assert!(proposal.base_totals.is_some());
    let reviewed_legs = proposal.legs.clone();
    let reviewed_totals = proposal.base_totals.clone();
    assert_eq!(measure(&f.h, f.nominal, f.foreign), (-600, -730));
    f.h.open_draft(agent.clone(), "carrying-close").unwrap();
    f.h.plan_draft(agent, "carrying-close", proposal).unwrap();
    let promoter = Capability::embedded(APPROVER, &["read", "approve", "close"]).unwrap();
    let promoted = f.h.promote(promoter, "carrying-close").unwrap();
    let (entry, _) = read_entry(&f.h.db, promoted.entries[0].vid)
        .unwrap()
        .unwrap();
    assert_eq!(entry.proposal.principal_ref, AGENT);
    assert_eq!(entry.proposal.legs, reviewed_legs);
    assert_eq!(entry.proposal.base_totals, reviewed_totals);
    assert_eq!(measure(&f.h, f.nominal, f.foreign), (0, 0));
    assert_eq!(measure(&f.h, f.equity, f.foreign), (-600, -730));
    f.green();
}

fn fixture_with_foreign_only_routes(foreign_only: bool) -> Fixture {
    let (mut h, native_equity) = year_end_close_fixture();
    let foreign = h.book.units.lookup("EUR").unwrap();
    let accounts = [
        (
            "1225",
            "Foreign receivables",
            fa_model::AccountType::ASSET,
            0,
        ),
        ("4025", "Foreign revenue", fa_model::AccountType::REVENUE, 1),
        (
            "3025",
            "Foreign retained earnings",
            fa_model::AccountType::EQUITY,
            1,
        ),
    ]
    .into_iter()
    .map(|(code, name, kind, normal)| AccountSpec {
        code: code.into(),
        name: name.into(),
        account_type: kind.0,
        normal_balance: normal,
        is_leaf: true,
        unit_policy: if foreign_only {
            UnitPolicy::Single(foreign)
        } else {
            UnitPolicy::AnyCurrency
        },
        parent_code: None,
        limit: None,
    })
    .collect::<Vec<_>>();
    let cx = h.ctx();
    let day = DateDay::from_ymd(2026, 1, 1).unwrap();
    let description = h
        .proposal(vec![], b"close-fx-chart", EntryClass::ORIGINAL)
        .description;
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &cx,
            &h.book,
            &accounts,
            PRINCIPAL,
            day,
            b"close-fx-chart",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let nominal = account_vid(h.book.book_id, "4025");
    let equity = account_vid(h.book.book_id, "3025");
    let counterparty = account_vid(h.book.book_id, "1225");
    let routes = [
        (h.rent, native_equity),
        (h.revenue, native_equity),
        (nominal, equity),
    ]
    .into();
    year_end_close_routes(&mut h, routes, b"close-fx-routes");
    Fixture {
        h,
        foreign,
        nominal,
        counterparty,
        equity,
    }
}

impl Fixture {
    fn source(&mut self, side: Side, native: i128, base: i128, key: &[u8]) -> EntryRef {
        let rate = FxRateDocument::new(
            FxRateTerms {
                base_unit: self.h.usd,
                quote_unit: self.foreign,
                rate_num: u128::try_from(base).unwrap(),
                rate_den: u128::try_from(native).unwrap(),
                rounding: RoundingLaw::HalfEven,
            },
            self.h.day(),
            1_700_000_000_000_000_000,
            FxRatePurpose::SpotClose,
            format!("Closing fixture source {}", String::from_utf8_lossy(key)),
        )
        .unwrap();
        self.h
            .add_document(
                &rate
                    .document(self.h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
                    .unwrap(),
            )
            .unwrap();
        let opposite = if side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
        let proposal = self.h.proposal(
            vec![
                LegPayload::simple(side, self.nominal, Amount::new(self.foreign, native)),
                LegPayload::simple(
                    opposite,
                    self.counterparty,
                    Amount::new(self.foreign, native),
                ),
            ],
            key,
            EntryClass::ORIGINAL,
        );
        let root = Cx::detached_cancel_context();
        let mut budget = ArithmeticBudget::new(&root, BudgetLimits::uniform(1_000_000, 0), 4096);
        let spec = fa_journal::genesis::read_book_spec(&self.h.db)
            .unwrap()
            .unwrap();
        let proposal = value_proposal(
            &mut budget,
            proposal,
            &spec,
            &self.h.book.units,
            FxLawId::SpotClose,
            &[rate],
        )
        .unwrap();
        self.h
            .post(self.h.request(proposal, &["read", "post"]))
            .unwrap()
            .entry_ref()
    }

    fn close(&mut self, key: &[u8]) -> (EntryPayload, Posted) {
        let prepared = year_end_close_prepare(&self.h);
        let proposal = year_end_close_proposal(&self.h, &prepared, key);
        let plan = self
            .h
            .post_plan(self.h.request(proposal.clone(), &["read", "post", "close"]))
            .unwrap();
        let posted = self
            .h
            .publish_plan(
                plan,
                &Capability::embedded(PRINCIPAL, &["read", "post", "close"]).unwrap(),
            )
            .unwrap();
        (proposal, posted)
    }

    fn reversal_proposal(&self, target: EntryRef, key: &[u8]) -> EntryPayload {
        let (original, _) = read_entry(&self.h.db, target.vid).unwrap().unwrap();
        let mut legs = original.proposal.legs.clone();
        for leg in &mut legs {
            leg.side = if leg.side == Side::Debit {
                Side::Credit
            } else {
                Side::Debit
            };
            leg.settles.clear();
        }
        let mut proposal = self.h.proposal(legs, key, EntryClass::REVERSAL);
        proposal.base_totals = original.proposal.base_totals;
        proposal.evidence = original.proposal.evidence;
        proposal.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        proposal
    }

    fn reverse(&mut self, target: EntryRef, key: &[u8]) -> EntryRef {
        let proposal = self.reversal_proposal(target, key);
        self.h
            .post(self.h.request(proposal, &["read", "post"]))
            .unwrap()
            .entry_ref()
    }

    fn green(&self) {
        let verify = year_end_close_verify(&self.h, None);
        assert!(verify.is_green());
        assert!(!verify.needs_reclose);
        assert!(
            verify
                .residuals
                .iter()
                .all(|cell| cell.net == 0 && cell.base_net == 0)
        );
        assert_eq!(verify.base_unit, self.h.usd);
        let fx = fa_journal::fx::verify_fx_conversions(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            self.h.db.frontier().unwrap(),
        )
        .unwrap();
        assert!(fx.is_green(), "{:?}", fx.drift);
    }
}

/// No closing planner or functional register is reused by this assertion.
fn measure(h: &Harness, account: VId, unit: UnitId) -> (i128, i128) {
    let (start, end) = h.book.calendar.year_bounds(2026).unwrap();
    let mut native = 0_i128;
    let mut base = 0_i128;
    for row in h.db.vertices_at(h.db.frontier().unwrap()).unwrap() {
        if !row.labels.contains(&fa_model::symbols::label::ENTRY) {
            continue;
        }
        let (entry, _) = read_entry(&h.db, row.vid).unwrap().unwrap();
        if entry.proposal.class.is_control()
            || entry.proposal.class == EntryClass::PENDING
            || entry.proposal.effective_date < start
            || entry.proposal.effective_date > end
        {
            continue;
        }
        for leg in entry.proposal.legs {
            if leg.account_ref != account || leg.amount.unit != unit {
                continue;
            }
            let retained = leg.base_amount.unwrap_or_else(|| {
                assert_eq!(leg.amount.unit, h.usd);
                leg.amount
            });
            match leg.side {
                Side::Debit => {
                    native += leg.amount.mantissa;
                    base += retained.mantissa;
                }
                Side::Credit => {
                    native -= leg.amount.mantissa;
                    base -= retained.mantissa;
                }
            }
        }
    }
    (native, base)
}

#[test]
fn carrying_close_clears_zero_native_and_opposite_sign_functional_residuals() {
    for (credit_native, credit_base, debit_native, debit_base, expected) in [
        (100, 100, 100, 200, (0, 100)),
        (200, 200, 100, 300, (-100, 100)),
    ] {
        let mut f = fixture();
        f.source(Side::Credit, credit_native, credit_base, b"income");
        f.source(Side::Debit, debit_native, debit_base, b"refund");
        assert_eq!(measure(&f.h, f.nominal, f.foreign), expected);
        let prepared = year_end_close_prepare(&f.h);
        assert_eq!(prepared.basis().version, 2);
        let residual = prepared
            .residuals()
            .iter()
            .find(|cell| cell.account == f.nominal)
            .unwrap();
        assert_eq!((residual.net, residual.base_net), expected);
        assert_eq!(
            prepared.legs().len(),
            4,
            "source valuations remain separate"
        );
        let (proposal, _) = f.close(b"carrying-close");
        let totals = proposal.base_totals.unwrap();
        assert_eq!(totals.fx_law_oid, FxLawId::YearEndCloseCarrying.oid());
        assert!(totals.rate_doc_oids.is_empty());
        assert!(totals.residual.is_none());
        assert_eq!(measure(&f.h, f.nominal, f.foreign), (0, 0));
        assert_eq!(measure(&f.h, f.equity, f.foreign), expected);
        f.green();
    }
}

#[test]
fn carrying_close_zero_aggregate_across_three_valuations_is_a_noop() {
    let mut f = fixture();
    f.source(Side::Debit, 100, 100, b"one");
    f.source(Side::Debit, 100, 300, b"three");
    f.source(Side::Credit, 200, 400, b"two");
    let before = f.h.db.frontier().unwrap();
    let zero = year_end_close_prepare(&f.h);
    assert_eq!(zero.basis().version, 2);
    assert!(zero.is_noop());
    assert!(
        zero.residuals()
            .iter()
            .all(|cell| cell.net == 0 && cell.base_net == 0)
    );
    assert_eq!(f.h.db.frontier().unwrap(), before);
    f.source(Side::Credit, 50, 100, b"late-two");
    f.close(b"after-zero-close");
    assert_eq!(measure(&f.h, f.nominal, f.foreign), (0, 0));
    assert_eq!(measure(&f.h, f.equity, f.foreign), (-50, -100));
    f.green();
}

#[test]
fn carrying_close_preserves_native_history_recloses_only_new_buckets_and_reverses_exactly() {
    let mut f = fixture();
    f.h.post(f.h.request(f.h.invoice(500, b"native-income"), &["post"]))
        .unwrap();
    let native = year_end_close_prepare(&f.h);
    assert_eq!(native.basis().version, 1);
    assert!(native.legs().iter().all(|leg| leg.base_amount.is_none()));
    let (_, old_close) = f.close(b"native-v1-close");
    f.source(Side::Credit, 200, 300, b"foreign-income");
    let (first_proposal, first) = f.close(b"foreign-v2-close");
    assert_eq!(first_proposal.legs.len(), 2);
    assert!(year_end_close_verify(&f.h, Some(old_close.recorded_at())).is_green());
    let late_source = f.source(Side::Credit, 100, 200, b"late-foreign-income");
    let delta = year_end_close_prepare(&f.h);
    assert_eq!(
        delta.legs().len(),
        2,
        "old source and close buckets cancel exactly"
    );
    assert!(delta.legs().iter().all(|leg| {
        leg.amount == Amount::new(f.foreign, 100)
            && leg.base_amount == Some(Amount::new(f.h.usd, 200))
    }));
    let (_, second) = f.close(b"delta-v2-close");
    let before = f.h.db.frontier().unwrap();
    let retry =
        f.h.post(f.h.request(first_proposal, &["read", "post", "close"]))
            .unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), first.entry_ref());
    assert_eq!(f.h.db.frontier().unwrap(), before);
    f.green();
    // Generated Closing targets retain their existing nonreversible policy.
    // Correct the source, then close only the new source-derived delta.
    let denied = f.reversal_proposal(second.entry_ref(), b"direct-close-undo");
    let refusal =
        f.h.post(f.h.request(denied, &["read", "post"]))
            .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::REVERSAL_TARGET);
    assert!(refusal.message.contains("Closing"));
    let reversal = f.reverse(late_source, b"reverse-source");
    assert_eq!(measure(&f.h, f.nominal, f.foreign), (100, 200));
    let undo_delta = year_end_close_prepare(&f.h);
    assert_eq!(undo_delta.legs().len(), 2);
    assert!(
        undo_delta
            .legs()
            .iter()
            .filter(|leg| leg.account_ref == f.nominal)
            .all(|leg| leg.side == Side::Credit
                && leg.base_amount == Some(Amount::new(f.h.usd, 200)))
    );
    f.close(b"reclose-reversed-source");
    f.green();
    f.reverse(reversal, b"reverse-the-reversal");
    assert_eq!(year_end_close_prepare(&f.h).legs(), delta.legs());
    f.close(b"reclose-restored-source");
    f.green();
}

#[test]
fn carrying_close_mixes_native_par_amounts_with_foreign_retained_valuations() {
    let mut f = fixture();
    f.h.post(f.h.request(f.h.invoice(700, b"native-par-income"), &["post"]))
        .unwrap();
    f.source(Side::Credit, 100, 150, b"foreign-parallel-income");
    let prepared = year_end_close_prepare(&f.h);
    assert_eq!(prepared.basis().version, 2);
    assert_eq!(prepared.legs().len(), 4);
    assert!(
        prepared
            .legs()
            .iter()
            .filter(|leg| leg.amount.unit == f.h.usd)
            .all(|leg| leg.base_amount == Some(leg.amount))
    );
    f.close(b"mixed-close");
    assert_eq!(measure(&f.h, f.h.revenue, f.h.usd), (0, 0));
    assert_eq!(measure(&f.h, f.nominal, f.foreign), (0, 0));
    f.green();
}

#[test]
fn carrying_close_rejects_balanced_base_forgery_and_rewritten_retained_history() {
    let mut f = fixture();
    f.source(Side::Credit, 100, 150, b"forgery-source");
    let prepared = year_end_close_prepare(&f.h);
    let good = year_end_close_proposal(&f.h, &prepared, b"forgery-close");
    let mut forged = good.clone();
    for leg in &mut forged.legs {
        leg.base_amount.as_mut().unwrap().mantissa += 1;
    }
    forged.base_totals.as_mut().unwrap().debits += 1;
    forged.base_totals.as_mut().unwrap().credits += 1;
    forged.validate().unwrap();
    let before = f.h.db.frontier().unwrap();
    let refused =
        f.h.post(f.h.request(forged.clone(), &["read", "post", "close"]))
            .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-034", exit::CONFLICT));
    assert_eq!(f.h.db.frontier().unwrap(), before);
    let posted =
        f.h.post(f.h.request(good, &["read", "post", "close"]))
            .unwrap();
    f.green();
    let (original, _) = read_entry(&f.h.db, posted.entry_ref().vid)
        .unwrap()
        .unwrap();
    let rewritten = forged
        .seal(original.approvals, original.plan_certificate)
        .unwrap();
    let mut corruption = fgdb::WriteBatch::new(relation::IN_BOOK);
    for (key, value) in fa_model::entry_mirrors(&rewritten).unwrap() {
        corruption.set_vertex_property(posted.entry_ref().vid, key, Some(value));
    }
    f.h.write_raw(corruption);
    let cap = Capability::embedded(PRINCIPAL, &["read", "post", "close"]).unwrap();
    let result = prepare_year_end_close(
        &f.h.db,
        &f.h.ctx(),
        &f.h.book,
        &cap,
        &YearEndCloseRequest {
            fiscal_year: 2026,
            closing_period: "FY2026-CLOSE".into(),
        },
    );
    assert!(matches!(result, Err(_) | Ok(Err(_))));
    let verified = verify_year_end_close(&f.h.db, &f.h.ctx(), &f.h.book, &cap, 2026, None);
    assert!(matches!(verified, Err(_) | Ok(Err(_))));
    let fx = fa_journal::fx::verify_fx_conversions(
        &f.h.db,
        &f.h.ctx(),
        &f.h.book,
        f.h.db.frontier().unwrap(),
    );
    assert!(fx.is_err() || !fx.unwrap().is_green());
}

#[test]
fn carrying_close_accepts_dormant_foreign_only_routes_with_native_activity() {
    let mut f = fixture_with_foreign_only_routes(true);
    f.h.post(f.h.request(f.h.invoice(700, b"native-only-activity"), &["post"]))
        .unwrap();
    let prepared = year_end_close_prepare(&f.h);
    assert_eq!(prepared.basis().version, 2);
    assert_eq!(prepared.legs().len(), 2);
    assert!(
        prepared
            .legs()
            .iter()
            .all(|leg| { leg.amount.unit == f.h.usd && leg.base_amount == Some(leg.amount) })
    );
    f.close(b"native-close-with-dormant-foreign-routes");
    f.green();
}
