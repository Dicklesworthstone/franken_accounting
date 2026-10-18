use super::*;
use crate::findings::lookup::{FindingRunCursor, FindingRunPage, FindingRunPageRequest, MAX_FINDING_RUN_PAGE};
use crate::findings::review::{FindingReviewAction, FindingReviewRequest};

fn page(f: &mut Fixture, request: FindingRunPageRequest) -> Result<FindingRunPage, Refusal> {
    let cx = f.cx();
    f.runtime.block_on(f.book.finding_runs(&cx, PRINCIPAL, &cap(&["read"]), &request)).unwrap()
}

fn record_weekend(f: &mut Fixture, date: u8) -> RecordedFindings {
    f.post(date, "3000", "1000", 100);
    let certificate = f.certify("jet.weekend", None);
    f.record(certificate.digest()).unwrap()
}

#[test]
fn finding_inventory_distinguishes_unrecorded_empty_and_populated_runs_after_reopen() {
    let mut f = Fixture::new(201);
    let no_runs = page(&mut f, FindingRunPageRequest::default()).unwrap();
    assert_eq!(no_runs.total_recorded_runs, 0);
    assert!(no_runs.runs.is_empty());
    assert!(no_runs.next_cursor.is_none());
    let certificate = f.certify("jet.weekend", None);
    let before = f.head();
    assert!(page(&mut f, FindingRunPageRequest::default()).unwrap().runs.is_empty(), "retained certificate is not a recorded run");
    assert_eq!(f.head(), before);
    let empty = f.record(certificate.digest()).unwrap();
    assert!(empty.finding_ids.is_empty());
    let populated = record_weekend(&mut f, 10);
    let at = f.head();
    f = f.reopen();
    let all = page(&mut f, FindingRunPageRequest::default()).unwrap();
    assert_eq!(all.total_recorded_runs, 2);
    assert_eq!(all.runs.iter().map(|r| r.run_vid).collect::<Vec<_>>(), [empty.run_vid, populated.run_vid]);
    assert_eq!(all.runs.iter().map(|r| r.finding_count).collect::<Vec<_>>(), [0, 1]);
    for (summary, run) in all.runs.iter().zip([empty, populated]) {
        assert_eq!(summary.certificate_digest, run.certificate_digest);
        assert_eq!(summary.recorded_at, run.recorded_at);
        assert_eq!(summary.producer, run.producer);
        assert_eq!(summary.coordinate, run.report.coordinate);
        assert_eq!(summary.findings_digest, run.report.findings_digest);
        assert_eq!(summary.procedure, run.report.procedure);
        assert_eq!(summary.version, run.report.version);
    }
    assert_eq!(all.known_at, at);
    assert_eq!(all.checked_through, at);
    assert_eq!(f.head(), at);
}

#[test]
fn finding_inventory_cursor_pins_all_pages_across_new_runs_and_human_decisions() {
    let mut f = Fixture::new(202);
    let first = record_weekend(&mut f, 10);
    let second = record_weekend(&mut f, 11);
    let third = record_weekend(&mut f, 17);
    let at = f.head();
    let whole = page(&mut f, FindingRunPageRequest::default()).unwrap();
    let initial = page(&mut f, FindingRunPageRequest { limit: 1, ..Default::default() }).unwrap();
    assert_eq!(initial.runs, whole.runs[..1]);
    let cursor = initial.next_cursor.unwrap();
    assert_eq!(cursor.known_at(), at);
    let cursor_bytes = cursor.canonical_bytes().unwrap();
    assert_eq!(FindingRunCursor::decode(&cursor_bytes).unwrap(), cursor);
    let fourth = record_weekend(&mut f, 18);
    let reviewer = VId(204);
    let cx = f.cx();
    let decision = FindingReviewRequest {
        finding_vid: first.finding_ids[0], expected_previous: None,
        action: FindingReviewAction::Acknowledge, note: "Read original source".into(), evidence: vec![],
    };
    f.runtime.block_on(f.book.review_finding(&cx, reviewer,
        &Capability::embedded(reviewer, &["read", "approve"]).unwrap(), &decision)).unwrap().unwrap();
    f = f.reopen();
    let head = f.head();
    let middle = page(&mut f, FindingRunPageRequest {
        after: Some(FindingRunCursor::decode(&cursor_bytes).unwrap()), limit: 1, known_at: None,
    }).unwrap();
    assert_eq!(middle.runs, whole.runs[1..2]);
    assert_eq!(middle.runs[0].run_vid, second.run_vid);
    assert_eq!(middle.known_at, at);
    assert_eq!(middle.checked_through, head);
    assert_eq!(middle.inventory_digest, initial.inventory_digest);
    assert_eq!(middle.total_recorded_runs, 3);
    let last = page(&mut f, FindingRunPageRequest {
        after: middle.next_cursor, limit: 2, known_at: Some(at),
    }).unwrap();
    assert_eq!(last.runs, whole.runs[2..]);
    assert_eq!(last.runs[0].run_vid, third.run_vid);
    assert!(last.next_cursor.is_none());
    let fresh = page(&mut f, FindingRunPageRequest::default()).unwrap();
    assert_eq!(fresh.total_recorded_runs, 4);
    assert_eq!(fresh.runs.last().unwrap().run_vid, fourth.run_vid);
    assert_ne!(fresh.inventory_digest, initial.inventory_digest);
    assert_eq!(f.head(), head);
}

#[test]
fn finding_inventory_rejects_cross_book_or_changed_cursor_scope_and_malformed_framing() {
    let mut f = Fixture::new(203);
    record_weekend(&mut f, 10);
    record_weekend(&mut f, 11);
    let result = page(&mut f, FindingRunPageRequest { limit: 1, ..Default::default() }).unwrap();
    let cursor = result.next_cursor.unwrap();
    let bytes = cursor.canonical_bytes().unwrap();
    let at = f.head();
    let different = FindingRunPageRequest { after: Some(cursor.clone()), known_at: Some(CommitSeq(at.0 - 1)), limit: 1 };
    assert!(page(&mut f, different).is_err());
    // Fixed framing can decode altered values; validation against native data
    // must still refuse a public digest/anchor/book edited by the caller.
    for offset in [b"fa:finding-run-cursor:v1".len(), bytes.len() - 1, bytes.len() - 33] {
        let mut wrong = bytes.clone(); wrong[offset] ^= 0x80;
        let cursor = FindingRunCursor::decode(&wrong).unwrap();
        assert!(page(&mut f, FindingRunPageRequest { after: Some(cursor), limit: 1, known_at: None }).is_err());
    }
    for len in 0..bytes.len() { assert!(FindingRunCursor::decode(&bytes[..len]).is_err()); }
    let mut trailing = bytes.clone(); trailing.push(0);
    assert!(FindingRunCursor::decode(&trailing).is_err());
    let mut version = bytes; version[0] = b'x';
    assert!(FindingRunCursor::decode(&version).is_err());
    assert_eq!(f.head(), at);
    let mut other = Fixture::new(205);
    let other_at = other.head();
    assert!(page(&mut other, FindingRunPageRequest { after: Some(cursor), limit: 1, known_at: None }).is_err());
    assert_eq!(other.head(), other_at);
}

#[test]
fn finding_inventory_authority_precedes_invalid_size_cursor_and_future_cutoff() {
    let mut f = Fixture::new(206);
    let at = f.head();
    let cx = f.cx();
    let bad = FindingRunPageRequest { known_at: Some(CommitSeq(u64::MAX)), after: None, limit: 0 };
    for denied in [cap(&["post"]), cap(&["approve"]), cap(&["produce"]),
        cap(&["read"]).for_accounts(&["1000"]).unwrap(), cap(&["read"]).expiring_at(at)] {
        let r = f.runtime.block_on(f.book.finding_runs(&cx, PRINCIPAL, &denied, &bad)).unwrap().unwrap_err();
        assert_eq!(r.exit, exit::SAFETY);
        assert_eq!(f.head(), at);
    }
    for size in [0, MAX_FINDING_RUN_PAGE + 1, usize::MAX] {
        assert!(page(&mut f, FindingRunPageRequest { limit: size, ..Default::default() }).is_err());
    }
    assert!(page(&mut f, FindingRunPageRequest { known_at: Some(CommitSeq(at.0 + 1)), ..Default::default() }).is_err());
    assert!(page(&mut f, FindingRunPageRequest { known_at: Some(CommitSeq(0)), ..Default::default() }).unwrap().runs.is_empty());
    assert!(page(&mut f, FindingRunPageRequest { limit: MAX_FINDING_RUN_PAGE, ..Default::default() }).unwrap().runs.is_empty());
    assert_eq!(f.head(), at);
}

#[test]
fn finding_inventory_cannot_hide_deleted_roots_from_old_cursors_or_an_empty_live_scan() {
    let mut f = Fixture::new(207);
    record_weekend(&mut f, 10);
    let second = record_weekend(&mut f, 11);
    let initial = page(&mut f, FindingRunPageRequest { limit: 1, ..Default::default() }).unwrap();
    let cx = f.cx();
    let mut damage = WriteBatch::new(relation::DERIVED_FROM);
    damage.delete_vertex(second.run_vid);
    f.runtime.block_on(f.book.db.write(&cx.commit(), damage)).unwrap();
    let at = f.head();
    for request in [FindingRunPageRequest::default(), FindingRunPageRequest {
        after: initial.next_cursor, limit: 1, known_at: None,
    }] {
        assert!(!matches!(f.runtime.block_on(f.book.finding_runs(&cx, PRINCIPAL, &cap(&["read"]), &request)), Ok(Ok(_))));
    }
    assert_eq!(f.head(), at);
}

#[test]
fn finding_inventory_refuses_orphans_and_unreplayed_tampering_without_a_partial_page() {
    let mut f = Fixture::new(208);
    record_weekend(&mut f, 10);
    let second = record_weekend(&mut f, 11);
    let cx = f.cx();
    let cvid = crate::certificate_store::certificate_vid(f.book.context().book_id, &second.certificate_digest);
    let mut damage = WriteBatch::new(relation::DERIVED_FROM);
    damage.set_vertex_property(cvid, property::FA_PAYLOAD, Some(scalar_bytes("broken", b"broken".to_vec()).unwrap()));
    f.runtime.block_on(f.book.db.write(&cx.commit(), damage)).unwrap();
    let at = f.head();
    assert!(page(&mut f, FindingRunPageRequest::default()).is_err(), "no first-run-only success when second replay fails");
    assert_eq!(f.head(), at);
    let mut g = Fixture::new(209);
    record_weekend(&mut g, 10);
    g.post(11, "3000", "1000", 1);
    let unrecorded = g.certify("jet.weekend", None);
    let prepared = Prepared::new(unrecorded, g.book.context()).unwrap();
    let record = &prepared.records[1];
    let mut props = vec![
        (property::FA_PAYLOAD, scalar_bytes("payload", record.payload.clone()).unwrap()),
        (property::FA_DIGEST, scalar_bytes("digest", record.digest.to_vec()).unwrap()),
        (property::BOOK_ID, scalar_bytes("book", g.book.context().book_id.0.to_vec()).unwrap()),
    ];
    props.sort_by_key(|(key, _)| key.0);
    let mut orphan = WriteBatch::new(relation::DERIVED_FROM);
    orphan.create_vertex(record.vid, vec![label::FINDING], props);
    let cx = g.cx();
    g.runtime.block_on(g.book.db.write(&cx.commit(), orphan)).unwrap();
    let at = g.head();
    assert!(page(&mut g, FindingRunPageRequest { limit: 1, ..Default::default() }).is_err(), "orphan outside requested page is not silently omitted");
    assert_eq!(g.head(), at);
}
