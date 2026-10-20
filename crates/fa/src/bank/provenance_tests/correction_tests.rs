//! Real facade correction flows over retained source bytes and reopened books.

use super::*;
use fa_model::{EntryOrigin, EntryPayload, EntryRef, EvidenceRef, LegPayload};
use fa_time::PeriodTransition;

const HEADER: &str = "sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference\n";

impl Harness {
    fn with_cash(seed: u8) -> Self {
        let mut h = Self::new(seed);
        let cx = h.cx();
        let unit = h.book.context().units.lookup("USD").unwrap();
        let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
        h.runtime
            .block_on(h.book.open_account(
                &cx,
                &AccountSpec {
                    code: "4000".into(),
                    name: "Revenue".into(),
                    account_type: AccountType::REVENUE.0,
                    normal_balance: 1,
                    is_leaf: true,
                    unit_policy: UnitPolicy::Single(unit),
                    parent_code: None,
                    limit: None,
                },
                day(),
                None,
                PRINCIPAL,
                day(),
                b"correction-revenue",
                &schema,
            ))
            .unwrap()
            .unwrap();
        h.runtime
            .block_on(h.book.create_periods(&cx, 2026, PRINCIPAL, &schema))
            .unwrap()
            .unwrap();
        h.runtime
            .block_on(h.book.transition_period(
                &cx,
                "FY2026-P03",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                day(),
                b"correction-period",
                &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        h
    }

    fn post_cash_legs(&mut self, key: &[u8], amounts: &[(i128, &str)]) -> EntryRef {
        let cx = self.cx();
        let context = self.book.context().clone();
        let unit = context.units.lookup("USD").unwrap();
        let evidence = self
            .runtime
            .block_on(self.book.upload_document(
                &cx,
                &cap(PRINCIPAL),
                fa_journal::UploadRequest {
                    kind: policy_kind(&EvidencePolicy::embedded().unwrap(), "Receipt").unwrap(),
                    mime: "text/plain".into(),
                    bytes: b"Human-supplied source receipt for bank correction tests".to_vec(),
                    asserted_grade: None,
                },
            ))
            .unwrap()
            .unwrap();
        let mut legs = Vec::new();
        let mut total = 0_i128;
        for (amount, reference) in amounts {
            let mut leg = LegPayload::simple(
                Side::Debit,
                account_vid(context.book_id, "1000"),
                Amount::new(unit, *amount),
            );
            leg.memo = Some(self.book.seal_text(&cx, reference).unwrap());
            legs.push(leg);
            total = total.checked_add(*amount).unwrap();
        }
        legs.push(LegPayload::simple(
            Side::Credit,
            account_vid(context.book_id, "4000"),
            Amount::new(unit, total),
        ));
        let proposal = EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: context.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(),
            document_date: None,
            description: self.book.seal_text(&cx, "documented cash receipt").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: evidence.oid,
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![EvidenceRef {
                document_oid: evidence.oid,
                doc_commit: evidence.doc_commit,
                role: 1,
            }],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        self.runtime
            .block_on(self.book.post(
                &cx,
                fa_journal::PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap(PRINCIPAL),
                },
            ))
            .unwrap()
            .unwrap()
            .entry_ref()
    }

    fn report(&mut self, manifest_oid: Oid, known_at: Option<CommitSeq>) -> BankMatchReport {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.match_bank_statement(
                &cx,
                &privileged_cap(PRINCIPAL),
                BankMatchRequest {
                    manifest_oid,
                    known_at,
                    date_window_days: 3,
                },
            ))
            .unwrap()
            .unwrap()
    }

    fn confirm(&mut self, request: BankConfirmationRequest) -> BankMatchRecorded {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.confirm_bank_statement_match(
                &cx,
                &privileged_cap(PRINCIPAL),
                request,
            ))
            .unwrap()
            .unwrap()
    }

    fn history(&mut self, known_at: Option<CommitSeq>) -> BankMatchHistory {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.bank_match_history(
                &cx,
                &Capability::embedded(PRINCIPAL, &["read", "reconcile"]).unwrap(),
                known_at,
                None,
            ))
            .unwrap()
            .unwrap()
    }

    fn unmatch(&mut self, recorded: &BankMatchRecorded) -> BankUnmatchRecorded {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.unmatch_bank_match(
                &cx,
                &Capability::embedded(PRINCIPAL, &["read", "reconcile"]).unwrap(),
                BankUnmatchRequest {
                    target: BankDecisionRef {
                        vid: recorded.match_vid,
                        digest: recorded.match_digest,
                    },
                },
            ))
            .unwrap()
            .unwrap()
    }

    fn reopened(mut self) -> Self {
        let cx = self.cx();
        drop(self.book);
        self.book = self
            .runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                self.vfs.clone(),
                Path::new(PATH),
                self.keys.clone(),
                Entropy::deterministic(901),
            ))
            .unwrap();
        self
    }
}

fn selection(report: &BankMatchReport, index: usize) -> BankConfirmationRequest {
    BankConfirmationRequest {
        manifest_oid: report.manifest_oid,
        line_ordinal: report.lines[index].line_ordinal,
        proposal_digest: report.proposals[index].oid().unwrap().0,
        source_known_at: report.known_at,
        date_window_days: report.date_window_days,
        proposer: report.proposals[index].principal,
    }
}

#[test]
fn immutable_unmatch_reopens_releases_and_reconfirms_without_changing_money() {
    let mut h = Harness::with_cash(171);
    let entry = h.post_cash_legs(b"two-cash-legs", &[(6000, "FIRST"), (4000, "SECOND")]);
    let source = format!(
        "{HEADER}1,BANK-CORRECTION,USD,2026-03-31,0.00,100.00,2026-03-31,2026-03-31,CRDT,60.00,Customer,FIRST\n1,BANK-CORRECTION,USD,2026-03-31,0.00,100.00,2026-03-31,2026-03-31,CRDT,40.00,Customer,SECOND\n"
    );
    let imported = import_selected(&mut h, &source, None).unwrap().unwrap();
    let report = h.report(imported.manifest_oid, None);
    assert_eq!(report.candidates.len(), 2);
    assert_eq!(report.proposals[0].matched_entry_ordinal, Some(0));
    assert_eq!(report.proposals[1].matched_entry_ordinal, Some(1));
    let original_request = selection(&report, 0);
    let original_card = report.proposals[0].decision_card.clone();
    let before_money = h
        .book
        .trial_balance(&h.cx(), &["FY2026-P03".into()])
        .unwrap();
    let before = h.head();
    let first = h.confirm(original_request.clone());
    assert_eq!(first.recorded_at.0, before.0 + 1);
    assert_eq!(first.confirmation.entry_ref, entry);
    assert_eq!(first.confirmation.leg_ordinal, 0);

    h = h.reopened();
    let active = h.history(None);
    assert_eq!(active.active.len(), 1);
    assert_eq!(active.active[0].match_vid, first.match_vid);
    assert_eq!(active.active[0].confirmation.decision_card, original_card);
    let before_retry = h.head();
    let retry = h.confirm(original_request.clone());
    assert!(retry.already_recorded);
    assert_eq!(retry.match_vid, first.match_vid);
    assert_eq!(retry.match_digest, first.match_digest);
    assert_eq!(retry.recorded_at, first.recorded_at);
    assert_eq!(h.head(), before_retry);

    let remaining = h.report(imported.manifest_oid, None);
    assert_eq!(
        remaining.candidates.len(),
        2,
        "full candidate ordinals are retained"
    );
    assert_eq!(remaining.consumed_cash_legs, vec![(entry.vid, 0)]);
    assert_eq!(remaining.confirmed_matches.len(), 1);
    assert_eq!(remaining.confirmed_matches[0].match_vid, first.match_vid);
    assert_eq!(remaining.proposals[0].matched_entry_ordinal, None);
    assert_eq!(remaining.proposals[1].matched_entry_ordinal, Some(1));
    let second = h.confirm(selection(&remaining, 1));
    assert_eq!(second.confirmation.entry_ref, entry);
    assert_eq!(second.confirmation.leg_ordinal, 1);
    assert_eq!(second.confirmation.candidate_ordinal, 1);

    let release = h.unmatch(&first);
    let released_at = h.head();
    assert_eq!(release.recorded_at, released_at);
    assert!(!release.already_recorded);
    assert_eq!(h.history(None).active[0].match_vid, second.match_vid);
    let original_retry = h.confirm(original_request);
    assert!(original_retry.already_recorded);
    assert_eq!(original_retry.match_vid, first.match_vid);
    assert_eq!(h.head(), released_at);
    assert_eq!(
        h.history(None).active.len(),
        1,
        "old retries cannot reactivate claims"
    );

    h = h.reopened();
    let release_retry = h.unmatch(&first);
    assert!(release_retry.already_recorded);
    assert_eq!(release_retry.unmatch_vid, release.unmatch_vid);
    assert_eq!(release_retry.unmatch_digest, release.unmatch_digest);
    assert_eq!(h.head(), released_at);
    let fresh = h.report(imported.manifest_oid, None);
    assert_eq!(fresh.confirmed_matches.len(), 1);
    assert_eq!(fresh.proposals[0].matched_entry_ordinal, Some(0));
    assert_eq!(fresh.proposals[1].matched_entry_ordinal, None);
    let reconfirmed = h.confirm(selection(&fresh, 0));
    assert_ne!(reconfirmed.match_vid, first.match_vid);
    let lineage = reconfirmed.confirmation.lineage.as_ref().unwrap();
    assert_eq!(lineage.line_generation, 1);
    assert_eq!(lineage.leg_generation, 1);
    let release_ref = BankDecisionRef {
        vid: release.unmatch_vid,
        digest: release.unmatch_digest,
    };
    assert_eq!(lineage.previous_line_unmatch.as_ref(), Some(&release_ref));
    assert_eq!(lineage.previous_leg_unmatch.as_ref(), Some(&release_ref));

    let historical = h.history(Some(first.recorded_at));
    assert_eq!(historical.confirmations.len(), 1);
    assert!(historical.unmatches.is_empty());
    assert_eq!(historical.active[0].match_vid, first.match_vid);
    let released = h.history(Some(released_at));
    assert_eq!(released.confirmations.len(), 2);
    assert_eq!(released.unmatches.len(), 1);
    assert_eq!(released.active.len(), 1);
    assert_eq!(released.active[0].match_vid, second.match_vid);
    let current = h.history(None);
    assert_eq!(current.confirmations.len(), 3);
    assert_eq!(current.unmatches.len(), 1);
    assert_eq!(current.active.len(), 2);
    assert!(
        !current
            .active
            .iter()
            .any(|recorded| recorded.match_vid == first.match_vid)
    );
    let cx = h.cx();
    let inventory = h
        .runtime
        .block_on(h.book.bank_confirmation_status(
            &cx,
            &privileged_cap(PRINCIPAL),
            BankStatusRequest {
                manifest_oid: imported.manifest_oid,
                known_at: None,
            },
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        inventory.confirmations.len(),
        3,
        "source status retains every generation"
    );
    let after_money = h.book.trial_balance(&cx, &["FY2026-P03".into()]).unwrap();
    assert_eq!(after_money.rows, before_money.rows);
    assert_eq!(after_money.unit_totals, before_money.unit_totals);
    assert_eq!(
        after_money.pending_unit_totals,
        before_money.pending_unit_totals
    );
}

#[test]
fn cash_claims_are_global_and_reuse_requires_a_review_after_the_release() {
    let mut h = Harness::with_cash(172);
    let entry = h.post_cash_legs(b"shared-cash", &[(5000, "SHARED")]);
    let source = |sequence| {
        format!(
            "{HEADER}{sequence},BANK-CORRECTION,USD,2026-03-31,0.00,50.00,2026-03-31,2026-03-31,CRDT,50.00,Customer,SHARED\n"
        )
    };
    let first_import = import_selected(&mut h, &source(1), None).unwrap().unwrap();
    let second_import = import_selected(&mut h, &source(2), None).unwrap().unwrap();
    let first_report = h.report(first_import.manifest_oid, None);
    let second_report = h.report(second_import.manifest_oid, None);
    let stale = selection(&second_report, 0);
    let first = h.confirm(selection(&first_report, 0));
    let second_while_occupied = h.report(second_import.manifest_oid, None);
    assert_eq!(second_while_occupied.candidates.len(), 1);
    assert_eq!(
        second_while_occupied.candidates[0].candidate.entry_ref,
        entry
    );
    assert_eq!(
        second_while_occupied.proposals[0].matched_entry_ordinal,
        None
    );
    assert!(second_while_occupied.confirmed_matches.is_empty());
    assert_eq!(
        second_while_occupied.consumed_cash_legs,
        vec![(entry.vid, 0)]
    );
    assert_eq!(
        second_while_occupied.occupied_bank_lines,
        vec![(
            first.confirmation.statement_oid,
            first.confirmation.line_ordinal
        )]
    );

    let cx = h.cx();
    let before = h.head();
    assert!(
        h.runtime
            .block_on(h.book.confirm_bank_statement_match(
                &cx,
                &privileged_cap(PRINCIPAL),
                stale.clone()
            ))
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), before);
    let release = h.unmatch(&first);
    let before = h.head();
    assert!(
        h.runtime
            .block_on(
                h.book
                    .confirm_bank_statement_match(&cx, &privileged_cap(PRINCIPAL), stale)
            )
            .unwrap()
            .is_err(),
        "a pre-release review cannot claim a new cash generation"
    );
    assert_eq!(h.head(), before);

    let fresh = h.report(second_import.manifest_oid, None);
    assert_eq!(fresh.proposals[0].matched_entry_ordinal, Some(0));
    assert!(fresh.consumed_cash_legs.is_empty());
    let second = h.confirm(selection(&fresh, 0));
    let lineage = second.confirmation.lineage.as_ref().unwrap();
    assert_eq!(lineage.line_generation, 0);
    assert_eq!(lineage.leg_generation, 1);
    assert_eq!(lineage.previous_line_unmatch, None);
    assert_eq!(
        lineage.previous_leg_unmatch,
        Some(BankDecisionRef {
            vid: release.unmatch_vid,
            digest: release.unmatch_digest,
        })
    );
    let current = h.history(None);
    assert_eq!(current.confirmations.len(), 2);
    assert_eq!(current.unmatches.len(), 1);
    assert_eq!(current.active.len(), 1);
    assert_eq!(current.active[0].match_vid, second.match_vid);
}

#[test]
fn metadata_history_hydrates_only_after_current_authority_and_explicit_prefix_admission() {
    let mut h = Harness::with_cash(173);
    h.post_cash_legs(b"history-cash", &[(5000, "HISTORY")]);
    let source = format!(
        "{HEADER}1,BANK-CORRECTION,USD,2026-03-31,0.00,50.00,2026-03-31,2026-03-31,CRDT,50.00,Customer,HISTORY\n"
    );
    let imported = import_selected(&mut h, &source, None).unwrap().unwrap();
    let report = h.report(imported.manifest_oid, None);
    let confirmed = h.confirm(selection(&report, 0));
    let pin = Capability::embedded(PRINCIPAL, &["read", "reconcile"])
        .unwrap()
        .known_at_most(confirmed.recorded_at);
    h.unmatch(&confirmed);
    h = h.reopened();
    assert!(h.book.db.delta_since(CommitSeq(0)).is_err());
    let cx = h.cx();
    let before = h.head();
    let admitted = h
        .book
        .admit_bank_match_history(&cx, &pin, Some(confirmed.recorded_at))
        .unwrap()
        .unwrap();
    assert_eq!(admitted, confirmed.recorded_at);
    assert!(h.book.db.delta_since(CommitSeq(0)).is_err());
    assert!(
        h.runtime
            .block_on(h.book.bank_match_history(&cx, &pin, None, None))
            .unwrap()
            .is_err(),
        "a pinned capability cannot silently select HEAD"
    );
    assert!(h.book.db.delta_since(CommitSeq(0)).is_err());
    let historical = h
        .runtime
        .block_on(h.book.bank_match_history(
            &cx,
            &pin,
            Some(confirmed.recorded_at),
            Some(imported.manifest.statement_oid),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(historical.known_at, confirmed.recorded_at);
    assert_eq!(historical.active.len(), 1);
    assert_eq!(historical.active[0].match_vid, confirmed.match_vid);
    assert!(historical.unmatches.is_empty());
    assert_eq!(h.head(), before);

    h.runtime
        .block_on(h.book.revoke_capability(
            &cx,
            Capability::embedded(PRINCIPAL, &["issue_capability"]).unwrap(),
            pin.commitment().unwrap(),
            day(),
            b"revoke-bank-history",
            "withdraw this historical reader's current authority",
        ))
        .unwrap()
        .unwrap();
    h = h.reopened();
    let cx = h.cx();
    let before = h.head();
    assert!(h.book.db.delta_since(CommitSeq(0)).is_err());
    assert!(
        h.runtime
            .block_on(
                h.book
                    .bank_match_history(&cx, &pin, Some(confirmed.recorded_at), None,)
            )
            .unwrap()
            .is_err(),
        "a historical selector cannot restore revoked current authority"
    );
    assert!(h.book.db.delta_since(CommitSeq(0)).is_err());
    assert_eq!(h.head(), before);
}
