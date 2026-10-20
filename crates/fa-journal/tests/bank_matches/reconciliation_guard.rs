//! Reconciled cash is protected inside each native monetary transaction,
//! including activation of previously invisible migration chunks.

use super::*;
use fa_journal::bank::{
    BankReconciliationPreparation, BankReconciliationRecorded, BankReconciliationRequest,
    bank_reconciliation_status, prepare_bank_reconciliation, reconcile_bank_statement,
};
use fa_journal::migration::read_run;
use fa_journal::post::{PostPreparation, prepare_post};
use fa_journal::refusal::{code, exit};
use fa_journal::rows::{edge_id, reversal_vid};

fn request(proposal: EntryPayload, capability: Capability) -> PostRequest {
    PostRequest {
        proposal,
        approvals: Vec::new(),
        capability,
        plan_certificate: None,
    }
}

fn post_request(h: &mut Harness, request: PostRequest) -> Result<Posted, Refusal> {
    let cx = h.cx();
    h.runtime
        .block_on(post(&mut h.db, &cx, &h.book, request))
        .unwrap()
}

fn confirmed_source(h: &mut Harness) -> (BankImportWitness, PostRequest, Posted) {
    let original = request(
        h.entry_payload(&[10_000], "WIRE", b"guard-original"),
        Capability::embedded(OWNER, &["post"]).unwrap(),
    );
    let posted = post_request(h, original.clone()).unwrap();
    let (import, line) = h.imported("WIRE", 10_000, b"guard-statement");
    let confirmation = h.request(import.clone(), line, posted.entry_ref(), 0);
    h.confirm(&cap(CONFIRMER), confirmation).unwrap();
    (import, original, posted)
}

fn close(h: &mut Harness, import: BankImportWitness) -> BankReconciliationRecorded {
    let request = BankReconciliationRequest {
        import,
        predecessors: Vec::new(),
        evaluated_known_at: h.head(),
    };
    let cx = h.cx();
    h.runtime
        .block_on(reconcile_bank_statement(
            &mut h.db,
            &cx,
            &h.book,
            &cap(CONFIRMER),
            request,
        ))
        .unwrap()
        .unwrap()
}

fn cites(h: &Harness, from: VId, to: VId) -> bool {
    h.db.edge_at(edge_id(relation::CITES, from, to), h.head())
        .unwrap()
        .is_some()
}

#[test]
fn cutoff_requires_reconcile_preserves_retry_and_keeps_authorized_drift_citations() {
    let mut h = Harness::new();
    let (import, original, posted) = confirmed_source(&mut h);
    let recorded = close(&mut h, import.clone());
    let head = h.head();

    // This identity already changed the cash included by the close. Its exact
    // retry returns that receipt without asking for newly introduced authority.
    let retry = post_request(&mut h, original).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), posted.recorded_at());
    assert_eq!(h.head(), head);

    let late = request(
        h.entry_payload(&[500], "late receipt", b"late"),
        Capability::embedded(OWNER, &["post"]).unwrap(),
    );
    let refusal = post_request(&mut h, late.clone()).unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit),
        (code::CAPABILITY, exit::SAFETY)
    );
    assert!(
        refusal
            .message
            .contains(&format!("{:032x}", recorded.attestation_vid.0))
    );
    assert!(refusal.message.contains(&day().to_string()));
    assert_eq!(h.head(), head, "a refused late post changes no native rows");

    let mut future = request(
        h.entry_payload(&[200], "later day", b"later-day"),
        Capability::embedded(OWNER, &["post"]).unwrap(),
    );
    future.proposal.effective_date = DateDay::from_ymd(2026, 3, 16).unwrap();
    let future = post_request(&mut h, future).unwrap();
    assert!(!cites(&h, future.entry_ref().vid, recorded.attestation_vid));

    let late = PostRequest {
        capability: cap(OWNER),
        ..late
    };
    let admitted = post_request(&mut h, late).unwrap();
    assert!(cites(
        &h,
        admitted.entry_ref().vid,
        recorded.attestation_vid
    ));
    let cx = h.cx();
    let status = h
        .runtime
        .block_on(bank_reconciliation_status(
            &mut h.db,
            &cx,
            &h.book,
            &cap(OWNER),
            import.manifest_oid(),
            None,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(status.reconciled_through, Some(day()));
    assert_eq!(status.reconciliations.len(), 1);
    let state = &status.reconciliations[0];
    assert!(state.balance_drift && state.cash_drift);
    assert_eq!(state.citing_entries, vec![admitted.entry_ref()]);
    assert_eq!(state.recorded, recorded);

    let again = request(
        h.entry_payload(&[1], "after drift", b"after-drift"),
        Capability::embedded(OWNER, &["post"]).unwrap(),
    );
    let head = h.head();
    assert_eq!(
        post_request(&mut h, again).unwrap_err().code,
        code::CAPABILITY
    );
    assert_eq!(h.head(), head, "drift does not remove the immutable cutoff");
}

#[test]
fn a_new_close_and_a_prepared_cash_post_conflict_in_either_commit_order() {
    for close_first in [true, false] {
        let mut h = Harness::new();
        let (import, _, _) = confirmed_source(&mut h);
        let cx = h.cx();
        let reviewed = h.head();
        let late = request(
            h.entry_payload(&[500], "racing receipt", b"race-late"),
            Capability::embedded(OWNER, &["post"]).unwrap(),
        );
        let PostPreparation::Ready(post) = prepare_post(&mut h.db, &cx, &h.book, late)
            .unwrap()
            .unwrap()
        else {
            panic!("fresh cash intent must prepare");
        };
        let BankReconciliationPreparation::Ready(close) = prepare_bank_reconciliation(
            &mut h.db,
            &cx,
            &h.book,
            &cap(CONFIRMER),
            BankReconciliationRequest {
                import,
                predecessors: Vec::new(),
                evaluated_known_at: reviewed,
            },
        )
        .unwrap()
        .unwrap() else {
            panic!("fresh close must prepare");
        };
        let refusal = if close_first {
            h.runtime
                .block_on(close.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap();
            h.runtime
                .block_on(post.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap_err()
        } else {
            h.runtime
                .block_on(post.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap();
            h.runtime
                .block_on(close.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap_err()
        };
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::CONFLICT, exit::CONFLICT)
        );
        assert_eq!(
            h.head().0,
            reviewed.0 + 1,
            "only the winning native transaction publishes"
        );
    }
}

#[test]
fn posting_witnesses_accounts_without_serializing_on_unrelated_native_rows() {
    let mut h = Harness::new();
    let (import, _, _) = confirmed_source(&mut h);
    close(&mut h, import);
    let mut future = request(
        h.entry_payload(&[100], "future receipt", b"narrow-witness"),
        Capability::embedded(OWNER, &["post"]).unwrap(),
    );
    future.proposal.effective_date = DateDay::from_ymd(2026, 3, 16).unwrap();
    let cx = h.cx();
    let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &cx, &h.book, future)
        .unwrap()
        .unwrap()
    else {
        panic!("fresh future cash intent must prepare");
    };
    // This is a substrate witness probe, not an accounting record. A global
    // vertex-population witness would unnecessarily invalidate the cash post.
    let mut unrelated = WriteBatch::new(relation::CITES);
    unrelated.create_vertex(VId(0x9001), Vec::new(), Vec::new());
    h.write(unrelated);
    let posted = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &cx))
        .unwrap()
        .unwrap();
    assert!(matches!(posted, Posted::Committed { .. }));
}

#[test]
fn a_multi_currency_cash_close_protects_only_its_attested_currency() {
    let mut h = Harness::with_currency_policy(None, None, true);
    let (import, _, _) = confirmed_source(&mut h);
    let recorded = close(&mut h, import.clone());
    let eur = h.book.units.lookup("EUR").unwrap();
    let mut other_currency = h.entry_payload(&[500], "EUR receipt", b"guard-eur");
    for leg in &mut other_currency.legs {
        leg.amount.unit = eur;
    }
    other_currency.unit_totals = EntryPayload::fold_unit_totals(&other_currency.legs).unwrap();
    let posted = post_request(
        &mut h,
        request(
            other_currency,
            Capability::embedded(OWNER, &["post"]).unwrap(),
        ),
    )
    .unwrap();
    assert!(!cites(&h, posted.entry_ref().vid, recorded.attestation_vid));
    let cx = h.cx();
    let status = h
        .runtime
        .block_on(bank_reconciliation_status(
            &mut h.db,
            &cx,
            &h.book,
            &cap(OWNER),
            import.manifest_oid(),
            None,
        ))
        .unwrap()
        .unwrap();
    let state = &status.reconciliations[0];
    assert_eq!(state.cash_balance, 10_000);
    assert!(!state.balance_drift && !state.cash_drift && !state.match_drift);
    assert!(state.citing_entries.is_empty());
    let protected = request(
        h.entry_payload(&[500], "USD receipt", b"guard-usd"),
        Capability::embedded(OWNER, &["post"]).unwrap(),
    );
    assert_eq!(
        post_request(&mut h, protected).unwrap_err().code,
        code::CAPABILITY
    );
}

#[test]
fn a_late_batch_member_refuses_every_staged_member_atomically() {
    let mut h = Harness::new();
    let (import, _, _) = confirmed_source(&mut h);
    let recorded = close(&mut h, import);
    let mut future = h.entry_payload(&[100], "future batch member", b"guard-batch-future");
    future.effective_date = DateDay::from_ymd(2026, 3, 16).unwrap();
    let late = h.entry_payload(&[100], "late batch member", b"guard-batch-late");
    let batch = PostBatch::new(
        b"guard-batch".to_vec(),
        vec![
            PostIntent::new(future, Vec::new()).unwrap(),
            PostIntent::new(late, Vec::new()).unwrap(),
        ],
    )
    .unwrap();
    let head = h.head();
    let cx = h.cx();
    let refusal = h
        .runtime
        .block_on(post_batch(
            &mut h.db,
            &cx,
            &h.book,
            Capability::embedded(OWNER, &["post"]).unwrap(),
            batch.clone(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::CAPABILITY);
    assert_eq!(
        h.head(),
        head,
        "the earlier staged future member also rolls back"
    );
    let posted = h
        .runtime
        .block_on(post_batch(
            &mut h.db,
            &cx,
            &h.book,
            cap(OWNER),
            batch.clone(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(posted.entries.len(), 2);
    assert!(!cites(&h, posted.entries[0].vid, recorded.attestation_vid));
    assert!(cites(&h, posted.entries[1].vid, recorded.attestation_vid));
    let head = h.head();
    let retry = h
        .runtime
        .block_on(post_batch(
            &mut h.db,
            &cx,
            &h.book,
            Capability::embedded(OWNER, &["post"]).unwrap(),
            batch,
        ))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(retry.recorded_at, posted.recorded_at);
    assert_eq!(h.head(), head);
}

#[test]
fn both_members_of_a_replacement_pair_need_reconciliation_authority() {
    let mut h = Harness::new();
    let (import, original, posted) = confirmed_source(&mut h);
    let recorded = close(&mut h, import);
    let mut reversal = original.proposal;
    reversal.class = EntryClass::REVERSAL;
    reversal.idempotency_key = b"guard-pair-reversal".to_vec();
    reversal.supersession = vec![Supersession {
        target: posted.entry_ref(),
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut reversal.legs {
        leg.side = if leg.side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
    }
    reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
    let mut replacement =
        h.entry_payload(&[10_500], "corrected receipt", b"guard-pair-replacement");
    replacement.class = EntryClass::REPLACEMENT;
    replacement.supersession = vec![Supersession {
        target: posted.entry_ref(),
        kind: SupersessionKind::Replaces,
        reason_code: 1,
    }];
    let head = h.head();
    let cx = h.cx();
    let refusal = h
        .runtime
        .block_on(fa_journal::post::post_replacement_pair(
            &mut h.db,
            &cx,
            &h.book,
            request(reversal.clone(), cap(OWNER)),
            request(
                replacement.clone(),
                Capability::embedded(OWNER, &["post"]).unwrap(),
            ),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::CAPABILITY);
    assert_eq!(
        h.head(),
        head,
        "the authorized first member cannot publish alone"
    );
    assert!(
        h.db.vertex(reversal_vid(posted.entry_ref().vid))
            .unwrap()
            .is_none()
    );
    let pair = h
        .runtime
        .block_on(fa_journal::post::post_replacement_pair(
            &mut h.db,
            &cx,
            &h.book,
            request(reversal.clone(), cap(OWNER)),
            request(replacement.clone(), cap(OWNER)),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(pair.0.recorded_at(), pair.1.recorded_at());
    assert!(cites(&h, pair.0.entry_ref().vid, recorded.attestation_vid));
    assert!(cites(&h, pair.1.entry_ref().vid, recorded.attestation_vid));
    let head = h.head();
    let retry = h
        .runtime
        .block_on(fa_journal::post::post_replacement_pair(
            &mut h.db,
            &cx,
            &h.book,
            request(reversal, Capability::embedded(OWNER, &["post"]).unwrap()),
            request(replacement, Capability::embedded(OWNER, &["post"]).unwrap()),
        ))
        .unwrap()
        .unwrap();
    assert!(matches!(retry.0, Posted::AlreadyRecorded { .. }));
    assert!(matches!(retry.1, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.0.entry_ref(), pair.0.entry_ref());
    assert_eq!(retry.1.entry_ref(), pair.1.entry_ref());
    assert_eq!(h.head(), head);
}

fn staged_opening(h: &mut Harness) -> (RunBody, RunControlRequest) {
    let opening = DateDay::from_ymd(2026, 1, 1).unwrap();
    let evidence = Document {
        book_id: h.book.book_id,
        kind: EvidencePolicy::embedded()
            .unwrap()
            .kind_by_name("Spreadsheet")
            .unwrap()
            .tag,
        mime: "text/csv".into(),
        grade: 3,
        retrieved_by: OWNER,
        bytes: b"account,unit,mantissa\n1000,USD,30000\n4000,USD,-30000\n".to_vec(),
    };
    let cx = h.cx();
    h.runtime
        .block_on(add_document(&mut h.db, &cx, &h.book, &evidence))
        .unwrap()
        .unwrap();
    let body = RunBody {
        book_id: h.book.book_id,
        run_key: "guard-opening".into(),
        source_system: "legacy-bank".into(),
        mode: RunMode::OpeningOnly,
        trial_balance: evidence.oid(),
        opening_date: opening,
        lines: vec![
            TrialBalanceLine {
                account_code: "1000".into(),
                unit: h.usd,
                mantissa: 30_000,
            },
            TrialBalanceLine {
                account_code: "4000".into(),
                unit: h.usd,
                mantissa: -30_000,
            },
        ],
        periods: Vec::new(),
        detail_base: Vec::new(),
        sole_opening_source: false,
    };
    let capability = Capability::embedded(OWNER, &["post", "migrate"]).unwrap();
    let open = RunControlRequest {
        proposal: open_proposal(
            &h.book,
            OWNER,
            &body,
            vec![evidence.evidence_ref(1)],
            b"guard-open-migration",
            seal(&h.book, "open invisible migration"),
        )
        .unwrap(),
        capability: capability.clone(),
        approvals: Vec::new(),
    };
    h.runtime
        .block_on(open_run(&mut h.db, &cx, &h.book, &body, open))
        .unwrap()
        .unwrap();
    let mut chunk = h.entry_payload(&[30_000], "legacy cash", b"guard-migration-chunk");
    chunk.class = EntryClass::MIGRATION;
    chunk.effective_date = opening;
    chunk.effective_period = Some(PeriodRef {
        calendar: h.book.calendar.id.clone(),
        code: "FY2026-OPEN".into(),
    });
    chunk.origin = EntryOrigin::Migration {
        run_ref: body.vid(),
        source_system: body.source_system.clone(),
        source_id: seal(&h.book, "legacy opening record"),
        source_recorded_at_ns: None,
        source_entered_by: None,
        source_approved_by: None,
        batch_oid: evidence.oid(),
    };
    chunk.evidence = vec![evidence.evidence_ref(1)];
    let approvals = h.approve(chunk.proposal_digest().unwrap());
    post_request(
        h,
        PostRequest {
            proposal: chunk,
            approvals,
            capability: capability.clone(),
            plan_certificate: None,
        },
    )
    .unwrap();
    let proposal = plan_run_transition(
        &h.db,
        &h.book,
        body.vid(),
        fa_journal::migration::kind::FINALIZE,
        OWNER,
        b"guard-finalize-migration",
        seal(&h.book, "activate migration"),
    )
    .unwrap()
    .unwrap();
    let approvals = h.approve(proposal.proposal_digest().unwrap());
    (
        body,
        RunControlRequest {
            proposal,
            capability,
            approvals,
        },
    )
}

#[test]
fn migration_finalize_cannot_activate_old_cash_without_reconciliation_authority() {
    for close_before_staging in [false, true] {
        let mut h = Harness::with_opening_date(Some(DateDay::from_ymd(2026, 3, 1).unwrap()));
        let (body, finalize, import, recorded) = if close_before_staging {
            let (import, _) =
                h.imported_lines("quiet statement", &[], b"migration-empty-statement");
            let recorded = close(&mut h, import.clone());
            let (body, finalize) = staged_opening(&mut h);
            (body, finalize, import, recorded)
        } else {
            let (body, finalize) = staged_opening(&mut h);
            let (import, _) =
                h.imported_lines("quiet statement", &[], b"migration-empty-statement");
            let recorded = close(&mut h, import.clone());
            (body, finalize, import, recorded)
        };
        let cx = h.cx();
        let head = h.head();
        let refusal = h
            .runtime
            .block_on(transition_run(&mut h.db, &cx, &h.book, finalize.clone()))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::CAPABILITY);
        assert_eq!(h.head(), head);
        assert_eq!(
            read_run(&h.db, body.vid(), None).unwrap().unwrap().state,
            RunState::Open
        );

        let admitted = h
            .runtime
            .block_on(transition_run(
                &mut h.db,
                &cx,
                &h.book,
                RunControlRequest {
                    capability: Capability::embedded(OWNER, &["post", "migrate", "reconcile"])
                        .unwrap(),
                    ..finalize.clone()
                },
            ))
            .unwrap()
            .unwrap();
        assert_eq!(admitted.to, RunState::Finalized);
        assert!(cites(&h, admitted.control_entry, recorded.attestation_vid));
        assert!(cites(
            &h,
            admitted.control_entry,
            account_vid(h.book.book_id, "1000")
        ));
        let status = h
            .runtime
            .block_on(bank_reconciliation_status(
                &mut h.db,
                &cx,
                &h.book,
                &cap(OWNER),
                import.manifest_oid(),
                None,
            ))
            .unwrap()
            .unwrap();
        let state = &status.reconciliations[0];
        assert_eq!(state.cash_balance, 30_000);
        assert!(state.balance_drift && state.cash_drift);
        assert_eq!(state.citing_entries.len(), 1);
        assert_eq!(state.citing_entries[0].vid, admitted.control_entry);

        let head = h.head();
        let retry = h
            .runtime
            .block_on(transition_run(&mut h.db, &cx, &h.book, finalize))
            .unwrap()
            .unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.recorded_at, admitted.recorded_at);
        assert_eq!(h.head(), head);
    }
}

#[test]
fn migration_activation_invalidates_a_prepared_close_even_without_an_existing_cutoff() {
    let mut h = Harness::with_opening_date(Some(DateDay::from_ymd(2026, 3, 1).unwrap()));
    let (_, finalize) = staged_opening(&mut h);
    let (import, _) = h.imported_lines("quiet statement", &[], b"activation-race-statement");
    let reviewed = h.head();
    let cx = h.cx();
    let BankReconciliationPreparation::Ready(prepared) = prepare_bank_reconciliation(
        &mut h.db,
        &cx,
        &h.book,
        &cap(CONFIRMER),
        BankReconciliationRequest {
            import,
            predecessors: Vec::new(),
            evaluated_known_at: reviewed,
        },
    )
    .unwrap()
    .unwrap() else {
        panic!("a zero-cash statement closes before invisible chunks activate");
    };
    h.runtime
        .block_on(transition_run(&mut h.db, &cx, &h.book, finalize))
        .unwrap()
        .unwrap();
    let refusal = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &cx))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit),
        (code::CONFLICT, exit::CONFLICT)
    );
    assert_eq!(h.head().0, reviewed.0 + 1);
}

#[test]
fn scheduled_reversal_is_blocked_without_reconcile_then_cites_the_close_when_authorized() {
    let mut h = Harness::with_time_policy(
        Some(DateDay::from_ymd(2026, 3, 1).unwrap()),
        Some(TimeZonePolicy::Utc),
    );
    let before = DateDay::from_ymd(2026, 3, 14).unwrap();
    let mut adjusting = h.entry_payload(&[100], "scheduled adjustment", b"guard-scheduled");
    adjusting.class = EntryClass::ADJUSTING;
    adjusting.effective_date = before;
    let target = post_request(
        &mut h,
        request(with_auto_reverse(adjusting, day()), cap(OWNER)),
    )
    .unwrap()
    .entry_ref();
    let mut offset = h.entry_payload(&[100], "offset", b"guard-offset");
    offset.effective_date = before;
    for leg in &mut offset.legs {
        leg.side = if leg.side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
    }
    offset.unit_totals = EntryPayload::fold_unit_totals(&offset.legs).unwrap();
    post_request(&mut h, request(offset, cap(OWNER))).unwrap();
    let (import, _) = h.imported_lines("quiet statement", &[], b"schedule-empty-statement");
    let recorded = close(&mut h, import);
    let cx = h.cx();
    let system = fa_journal::rows::system_principal(h.book.book_id);
    for authorized in [false, true] {
        let instant = fa_time::UtcInstant::parse(if authorized {
            "2026-03-15T00:00:01Z"
        } else {
            "2026-03-15T00:00:00Z"
        })
        .unwrap()
        .unix_ns();
        let tick = TickRequest {
            observed_utc_ns: instant,
            source: fa_journal::sweep::SOURCE_DAEMON_CLOCK,
            monotonic_ok: true,
            principal_ref: OWNER,
            capability: Capability::embedded(OWNER, &["witness"]).unwrap(),
            idempotency_key: format!("reconcile-schedule-tick-{authorized}").into_bytes(),
            description: seal(&h.book, "clock witness"),
        };
        h.runtime
            .block_on(record_tick(&mut h.db, &cx, &h.book, tick))
            .unwrap()
            .unwrap();
        let ops = if authorized {
            vec![Op::Post, Op::Reconcile]
        } else {
            vec![Op::Post]
        };
        let sweep = SweepRequest {
            principal_ref: system,
            capability: Capability::new(system, Profile::System, &ops, system).unwrap(),
            max_batch: 8,
        };
        let book = &h.book;
        let mut describe = |text: &str| Ok(seal(book, text));
        let batch = h
            .runtime
            .block_on(fa_journal::schedule::sweep_reversals_batch(
                &mut h.db,
                &cx,
                book,
                &sweep,
                &mut describe,
            ))
            .unwrap()
            .unwrap()
            .unwrap();
        if authorized {
            assert!(batch.blocked.is_empty());
            assert_eq!(batch.minted.len(), 1);
            assert_eq!(batch.minted[0].0, target);
            assert!(cites(&h, batch.minted[0].1.vid, recorded.attestation_vid));
        } else {
            assert!(batch.minted.is_empty());
            assert_eq!(batch.blocked.len(), 1);
            assert_eq!(batch.blocked[0].0, target);
            assert!(
                batch.blocked[0]
                    .1
                    .contains(&format!("{:032x}", recorded.attestation_vid.0))
            );
            assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
        }
    }
}

#[test]
fn opening_a_period_refuses_unauthorized_automatic_cash_effects_atomically() {
    let mut h = Harness::with_time_policy(None, Some(TimeZonePolicy::Utc));
    let april = DateDay::from_ymd(2026, 4, 1).unwrap();
    let mut adjusting = h.entry_payload(&[100], "April reversal", b"guard-open-target");
    adjusting.class = EntryClass::ADJUSTING;
    let target = post_request(
        &mut h,
        request(with_auto_reverse(adjusting, april), cap(OWNER)),
    )
    .unwrap()
    .entry_ref();
    let mut offset = h.entry_payload(&[100], "offset", b"guard-open-offset");
    for leg in &mut offset.legs {
        leg.side = if leg.side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
    }
    offset.unit_totals = EntryPayload::fold_unit_totals(&offset.legs).unwrap();
    post_request(&mut h, request(offset, cap(OWNER))).unwrap();
    let (import, _) = super::reconciliation_tests::statement(
        &mut h,
        "quiet April statement",
        &[],
        april,
        april,
        0,
        b"guard-open-statement",
    );
    let recorded = close(&mut h, import);
    let tick = TickRequest {
        observed_utc_ns: fa_time::UtcInstant::parse("2026-04-01T00:00:00Z")
            .unwrap()
            .unix_ns(),
        source: fa_journal::sweep::SOURCE_DAEMON_CLOCK,
        monotonic_ok: true,
        principal_ref: OWNER,
        capability: Capability::embedded(OWNER, &["witness"]).unwrap(),
        idempotency_key: b"guard-open-tick".to_vec(),
        description: seal(&h.book, "April clock witness"),
    };
    let cx = h.cx();
    h.runtime
        .block_on(record_tick(&mut h.db, &cx, &h.book, tick))
        .unwrap()
        .unwrap();
    let description = seal(&h.book, "open April with due reversals");
    let head = h.head();
    let refusal = h
        .runtime
        .block_on(transition_period(
            &mut h.db,
            &cx,
            &h.book,
            "FY2026-P04",
            PeriodTransition::Open,
            OWNER,
            1,
            b"guard-open-april",
            description.clone(),
            &Capability::embedded(OWNER, &["close"]).unwrap(),
            &[],
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::CAPABILITY);
    assert_eq!(h.head(), head);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    let opened = h
        .runtime
        .block_on(transition_period(
            &mut h.db,
            &cx,
            &h.book,
            "FY2026-P04",
            PeriodTransition::Open,
            OWNER,
            1,
            b"guard-open-april",
            description.clone(),
            &Capability::embedded(OWNER, &["close", "reconcile"]).unwrap(),
            &[],
        ))
        .unwrap()
        .unwrap();
    assert_eq!(opened.minted.len(), 1);
    assert_eq!(opened.minted[0].0, target);
    assert!(opened.blocked.is_empty());
    assert!(cites(&h, opened.minted[0].1.vid, recorded.attestation_vid));
    let head = h.head();
    let retry = h
        .runtime
        .block_on(transition_period(
            &mut h.db,
            &cx,
            &h.book,
            "FY2026-P04",
            PeriodTransition::Open,
            OWNER,
            1,
            b"guard-open-april",
            description,
            &Capability::embedded(OWNER, &["close"]).unwrap(),
            &[],
        ))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.minted, opened.minted);
    assert_eq!(retry.blocked, opened.blocked);
    assert_eq!(retry.recorded_at, opened.recorded_at);
    assert_eq!(h.head(), head);
}
