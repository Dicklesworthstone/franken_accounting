//! Request identity is independent of transport authority and shared by
//! ordinary entries, target-derived entries, and atomic batch outcomes.

use super::*;

fn fixture() -> Oracle {
    let mut oracle = Oracle::new(FiscalCalendar::monthly("cal", 1, 1).unwrap());
    for code in ["1000", "6000"] {
        oracle.add_account(Account {
            code: code.into(),
            is_leaf: true,
            unit: Some(1),
        });
    }
    oracle.create_periods(2026);
    oracle
        .transition("FY2026-P03", PeriodTransition::Open)
        .unwrap();
    oracle
}

fn intent(class: &str, key: &str) -> Intent {
    Intent {
        class: class.into(),
        date: DateDay::from_ymd(2026, 3, 15).unwrap(),
        discriminator: None,
        legs: vec![
            Leg {
                side: Side::Debit,
                account: "6000".into(),
                unit: 1,
                entity: None,
                mantissa: 10,
            },
            Leg {
                side: Side::Credit,
                account: "1000".into(),
                unit: 1,
                entity: None,
                mantissa: 10,
            },
        ],
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    }
}

fn posted(oracle: &mut Oracle, request: &Intent) -> usize {
    let index = oracle.journal_len();
    assert_eq!(
        oracle.post(request),
        Verdict::Posted {
            index,
            period: "FY2026-P03".into()
        }
    );
    index
}

#[test]
fn successful_outcomes_bind_approvals_but_not_capability_operations() {
    let mut oracle = fixture();
    let target = posted(&mut oracle, &intent("Original", "source"));
    let hold = posted(&mut oracle, &intent("Pending", "hold"));
    let mut reversal = intent("Reversal", "reversal");
    reversal.reverses = Some(target);
    for leg in &mut reversal.legs {
        leg.side = leg.side.flipped();
    }
    let mut resolution = intent("Resolution", "resolution");
    resolution.legs.clear();
    resolution.resolves = Some(Resolve {
        target: hold,
        posts: None,
    });
    for request in [intent("Original", "entry"), reversal, resolution.clone()] {
        let index = posted(&mut oracle, &request);
        let mut changed_approvals = request.clone();
        changed_approvals.approvals = 1;
        assert_eq!(
            oracle.post(&changed_approvals),
            Verdict::Refused {
                code: code::IDEMPOTENCY_CONFLICT
            }
        );
        let mut changed_authority = request.clone();
        changed_authority.ops.push("close".into());
        assert_eq!(oracle.post(&changed_authority), Verdict::Recorded { index });
        changed_authority.ops.clear();
        assert_eq!(
            oracle.post(&changed_authority),
            Verdict::Refused {
                code: code::CAPABILITY
            }
        );
        assert_eq!(oracle.post(&request), Verdict::Recorded { index });
    }
    resolution.key = b"new-resolution-key".to_vec();
    resolution.approvals = 1;
    assert_eq!(
        oracle.post(&resolution),
        Verdict::Refused {
            code: code::ALREADY_RESOLVED
        }
    );
    posted(&mut oracle, &intent("Original", "new-resolution-key"));

    let members = [intent("Original", "batch-0"), intent("Original", "batch-1")];
    let start = oracle.journal_len();
    let indices = vec![start, start + 1];
    assert_eq!(
        oracle.post_batch(b"batch", &members),
        BatchVerdict::Posted {
            indices: indices.clone()
        }
    );
    let mut changed = members.clone();
    changed[1].approvals = 1;
    assert_eq!(
        oracle.post_batch(b"batch", &changed),
        BatchVerdict::Refused {
            member: Some(1),
            code: code::IDEMPOTENCY_CONFLICT
        }
    );
    changed[1].approvals = 0;
    for member in &mut changed {
        member.ops.push("close".into());
    }
    assert_eq!(
        oracle.post_batch(b"batch", &changed),
        BatchVerdict::Recorded {
            indices: indices.clone()
        }
    );
    changed[1].ops.clear();
    assert_eq!(
        oracle.post_batch(b"batch", &changed),
        BatchVerdict::Refused {
            member: Some(1),
            code: code::CAPABILITY
        }
    );
    assert_eq!(oracle.journal_len(), start + 2);
    assert_eq!(
        oracle.post_batch(b"batch", &members),
        BatchVerdict::Recorded { indices }
    );
}

#[test]
fn malformed_or_refused_batches_do_not_reserve_keys() {
    let mut oracle = fixture();
    let request = intent("Original", "member");
    for (key, members, code) in [
        (b"empty".as_slice(), Vec::new(), code::STRUCTURE),
        (
            b"duplicate".as_slice(),
            vec![request.clone(), request.clone()],
            code::STRUCTURE,
        ),
        (
            b"member".as_slice(),
            vec![request.clone()],
            code::IDEMPOTENCY_CONFLICT,
        ),
    ] {
        assert_eq!(
            oracle.post_batch(key, &members),
            BatchVerdict::Refused { member: None, code }
        );
        assert_eq!(oracle.journal_len(), 0);
    }
    for key in ["empty", "duplicate", "member"] {
        posted(&mut oracle, &intent("Original", key));
    }
}

#[test]
fn system_sweeps_have_a_separate_key_scope_from_the_posting_actor() {
    let mut oracle = fixture();
    oracle.declare_time_zone();
    let caller = intent("Original", "scheduled");
    let caller_index = posted(&mut oracle, &caller);
    let reverse_on = DateDay::from_ymd(2026, 3, 16).unwrap();
    for key in ["scheduled-source-0", "scheduled-source-1"] {
        assert!(matches!(
            oracle.post_scheduled(&intent("Adjusting", key), reverse_on),
            Verdict::Posted { .. }
        ));
    }
    let tick = u64::try_from(reverse_on.0).unwrap() * 86_400_000_000_000;
    oracle.record_tick(tick).unwrap();
    let swept = oracle.sweep_reversals_batch(10).unwrap().unwrap();
    assert_eq!(swept.minted.len(), 2);
    assert!(swept.blocked.is_empty());
    assert_eq!(
        oracle.post(&caller),
        Verdict::Recorded {
            index: caller_index
        }
    );

    for key in ["timed-hold-0", "timed-hold-1"] {
        assert!(matches!(
            oracle.post_timed(&intent("Pending", key), 5),
            Verdict::Posted { .. }
        ));
    }
    oracle.record_tick(tick + 5).unwrap();
    let swept = oracle.sweep_batch(10).unwrap().unwrap();
    assert_eq!(swept.expired.len(), 2);
    // The two System expiries share a placeholder key in this model;
    // neither reserves the posting actor's key of the same bytes.
    posted(&mut oracle, &intent("Original", "expires"));
}
