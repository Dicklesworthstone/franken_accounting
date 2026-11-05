use super::*;
use std::cell::Cell;

#[test]
fn source_history_memo_retries_refusals_and_kernel_errors_before_caching_success() {
    let runtime = asupersync::runtime::RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let mut audits = SuccessfulHistoryAudits::default();
    let calls = Cell::new(0);
    let book = Id128([1; 16]);
    let at = CommitSeq(17);
    let source = VId(3);

    for message in ["first retained allocation", "second retained allocation"] {
        let refusal = audits
            .verify(&cx, book, at, source, || {
                calls.set(calls.get() + 1);
                Ok(Err(invalid(message)))
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.message, message);
        assert!(audits.sources.is_empty());
    }
    for message in ["native read failed", "retained entry is corrupt"] {
        let error = audits
            .verify(&cx, book, at, source, || {
                calls.set(calls.get() + 1);
                Err(KernelError::Corrupt(message.into()))
            })
            .unwrap_err();
        assert!(matches!(error, KernelError::Corrupt(value) if value == message));
        assert!(audits.sources.is_empty());
    }
    audits
        .verify(&cx, book, at, source, || {
            calls.set(calls.get() + 1);
            Ok(Ok(()))
        })
        .unwrap()
        .unwrap();
    for _ in 0..1_024 {
        audits
            .verify(&cx, book, at, source, || {
                calls.set(calls.get() + 1);
                Ok(Err(invalid("a successful source must be reused")))
            })
            .unwrap()
            .unwrap();
    }
    assert_eq!(calls.get(), 5);
    assert_eq!(audits.work.source_history_audits, calls.get());
    assert_eq!(audits.work.successful_reuses, 1_024);
}

#[test]
fn source_history_memo_separates_sources_books_and_prefixes() {
    let runtime = asupersync::runtime::RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let mut audits = SuccessfulHistoryAudits::default();
    let calls = Cell::new(0);
    let book = Id128([1; 16]);
    let other_book = Id128([2; 16]);
    let at = CommitSeq(17);
    let later = CommitSeq(18);
    let source = VId(3);
    let other_source = VId(4);
    // A return to an earlier coordinate also requires a fresh audit. The
    // memo retains only the current coordinate, never all historical books.
    for (book, at, source, expected_calls) in [
        (book, at, source, 1),
        (book, at, source, 1),
        (book, at, other_source, 2),
        (book, at, source, 2),
        (book, later, source, 3),
        (book, later, source, 3),
        (other_book, later, source, 4),
        (other_book, later, source, 4),
        (book, at, source, 5),
        (book, at, other_source, 6),
    ] {
        audits
            .verify(&cx, book, at, source, || {
                calls.set(calls.get() + 1);
                Ok(Ok(()))
            })
            .unwrap()
            .unwrap();
        assert_eq!(calls.get(), expected_calls);
    }
    assert_eq!(audits.work.source_history_audits, calls.get());
    assert_eq!(audits.work.successful_reuses, 4);
}

#[test]
fn source_history_memo_hit_checks_cancellation_before_reuse() {
    let runtime = asupersync::runtime::RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let mut audits = SuccessfulHistoryAudits::default();
    let book = Id128([1; 16]);
    let at = CommitSeq(17);
    let source = VId(3);
    audits
        .verify(&cx, book, at, source, || Ok(Ok(())))
        .unwrap()
        .unwrap();
    root.cancel_fast(asupersync::types::CancelKind::User);
    let result = audits.verify(&cx, book, at, source, || {
        panic!("a cache hit must not invoke another audit")
    });
    assert!(
        matches!(
            result,
            Err(KernelError::Txn(fgdb::WriteTxnError::Interrupted(_)))
        ),
        "{result:?}"
    );
    assert_eq!(audits.work.source_history_audits, 1);
    assert_eq!(audits.work.successful_reuses, 0);
}
