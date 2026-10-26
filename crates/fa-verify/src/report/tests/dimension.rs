//! Independent byte fixtures for dimension-filtered report recomputation.
//! The complete authenticated prefix supplies hierarchy, tags and arithmetic;
//! the report's claimed value list and native attestations supply neither.

use super::*;

fn value_vid(book: &[u8; 16], dimension: &str, value: &str) -> u128 {
    let mut framed = Writer::default();
    framed
        .bytes(book)
        .bytes(dimension.as_bytes())
        .bytes(value.as_bytes());
    let hash = hash_parts(b"fa:vid:dimension-value:v1", &[&framed.buf]);
    u128::from_le_bytes(hash[..16].try_into().unwrap())
}

fn declaration(seq: u64, dimension: &str, code: &str, parent: Option<&str>) -> Record {
    let mut body = Writer::default();
    body.fixed(b"fa:dimension-value:v1")
        .bytes(dimension.as_bytes())
        .bytes(code.as_bytes())
        .bytes(code.as_bytes())
        .u8(u8::from(parent.is_some()));
    if let Some(parent) = parent {
        body.bytes(parent.as_bytes());
    }
    body.u8(0).u8(0);
    record(
        17,
        seq,
        0,
        format!("dimension-{seq}").as_bytes(),
        0,
        Some((17, &body.buf)),
        None,
        None,
    )
}

fn close(seq: u64, code: &str, day: i32) -> Record {
    let mut body = Writer::default();
    body.fixed(b"fa:dimension-close:v1")
        .bytes(b"cost_center")
        .bytes(code.as_bytes())
        .i32(day);
    record(
        17,
        seq,
        0,
        format!("close-{seq}").as_bytes(),
        0,
        Some((19, &body.buf)),
        None,
        None,
    )
}

/// A balanced posting with independently chosen tags on its two legs.
fn tagged(
    class: u16,
    seq: u64,
    day: i32,
    amount: i128,
    debit_tags: &[(u32, u128)],
    credit_tags: &[(u32, u128)],
) -> Record {
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(class)
        .i32(day)
        .u8(0);
    erasable(&mut w);
    w.u8(0).count(2);
    for (code, side, tags) in [("1000", 0, debit_tags), ("3000", 1, credit_tags)] {
        w.u8(side)
            .u128(account_id(code))
            .u32(1)
            .i128(amount)
            .u8(0)
            .count(tags.len());
        for (kind, value) in tags {
            w.u32(*kind).u128(*value);
        }
        w.u8(0).count(0);
    }
    w.u8(0)
        .count(0)
        .u8(0)
        .bytes(format!("tagged-{seq}").as_bytes())
        .u8(0)
        .fixed(&[0; 32])
        .u16(1)
        .u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(0);
    if class == 2 {
        w.u8(1).u8(0).u8(0).u8(0);
    } else {
        w.u8(0);
    }
    w.count(0).count(0);
    let len = w.buf.len();
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let entry_digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[]]);
    w.fixed(&proposal_digest).fixed(&entry_digest);
    // Derive the fixture envelope independently so an authenticated malformed
    // tag set reaches the verifier instead of being rejected by this builder.
    let mut account_vids = vec![account_id("1000"), account_id("3000")];
    account_vids.sort_unstable();
    let envelope = LeafEnvelope {
        kind: KIND_ENTRY,
        book_id: BOOK,
        branch_id: [0; 16],
        commit_seq: seq,
        within_commit_ordinal: 0,
        record_digest: entry_digest,
        class,
        effective_day: Some(day),
        account_vids,
        unit_ids: vec![1],
    };
    Record {
        bytes: w.buf,
        len,
        envelope,
    }
}

fn dimensions() -> Vec<Record> {
    let mut records = schema();
    records.push(declaration(3, "cost_center", "root", None));
    records.push(declaration(4, "cost_center", "child", Some("root")));
    records.push(declaration(5, "cost_center", "other", None));
    records
}

fn cash(posted: i128, pending: i128) -> Vec<ReportRow> {
    vec![rows(posted, pending).remove(0)]
}

fn dimension_bundle(
    records: &[Record],
    known_at: u64,
    selection: Selection,
    value: &str,
    included: &[&str],
    expected_rows: &[ReportRow],
) -> (Vec<u8>, SignedCheckpoint) {
    let (native, anchor) = bundle(records, known_at, selection.clone(), expected_rows);
    let mut r = Reader::new(&native);
    r.bytes(64, "bundle").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    let native_certificate =
        certificate(r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap()).unwrap();
    let tail = &native[native.len() - r.remaining()..];
    let mut output = Writer::default();
    output
        .fixed(DIMENSION_OUTPUT_FORMAT)
        .bytes(b"cost_center")
        .bytes(value.as_bytes())
        .count(included.len());
    for code in included {
        output.bytes(code.as_bytes());
    }
    output.bytes(native_certificate.output);

    let mut cert = Writer::default();
    cert.fixed(DIMENSION_CERTIFICATE_FORMAT)
        .bytes(b"fa-fold-over-prefix")
        .bytes(b"embedded-owner")
        .bytes(DIMENSION_OUTPUT_FORMAT)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(known_at)
        .u8(6);
    match selection {
        Selection::Periods(periods) | Selection::Activity(periods) => {
            cert.u8(
                if matches!(native_certificate.selection, Selection::Activity(_)) {
                    2
                } else {
                    0
                },
            )
            .count(periods.len());
            for period in periods {
                cert.bytes(period.as_bytes());
            }
        }
        Selection::AsOf(day) => {
            cert.u8(1).i32(day);
        }
        Selection::Statement(_) | Selection::OpenItems(_) | Selection::ExplainBalance { .. } => {
            panic!("dimension selection must be a trial balance")
        }
    }
    cert.bytes(b"cost_center")
        .bytes(value.as_bytes())
        .fixed(&native_certificate.registry_digest)
        .fixed(&native_certificate.journal_root)
        .u64(native_certificate.leaves)
        .count(8);
    for _ in 0..8 {
        cert.bytes(b"producer metadata is not an independent hierarchy proof");
    }
    cert.bytes(&output.buf)
        .fixed(&hash_parts(b"fa:report-output:v1", &[&output.buf]))
        .u8(0);
    let digest = hash_parts(DIMENSION_CERTIFICATE_FORMAT, &[&cert.buf]);
    cert.fixed(&digest);
    let mut out = Writer::default();
    out.bytes(REPORT_BUNDLE_FORMAT)
        .u16(1)
        .u16(0)
        .bytes(&cert.buf)
        .fixed(tail);
    (out.buf, anchor)
}

#[test]
fn dimension_rollups_recompute_unbalanced_tagged_rows() {
    let mut records = dimensions();
    records.push(tagged(
        1,
        6,
        10,
        100,
        &[(2, value_vid(&BOOK, "cost_center", "child"))],
        &[],
    ));
    records.push(tagged(
        1,
        7,
        10,
        40,
        &[(2, value_vid(&BOOK, "cost_center", "other"))],
        &[],
    ));
    records.push(tagged(1, 8, 10, 200, &[], &[]));
    let (bytes, anchor) = dimension_bundle(
        &records,
        8,
        Selection::AsOf(30),
        "root",
        &["child", "root"],
        &cash(100, 0),
    );
    let report = verify_fixture(&bytes, anchor).unwrap();
    assert_eq!(report.rows, cash(100, 0));
    let dimension = report.dimension.unwrap();
    assert_eq!(dimension.dimension, "cost_center");
    assert_eq!(dimension.value, "root");
    assert_eq!(dimension.values, ["child", "root"]);
    assert_eq!(report.checked_records, 8);
    // Whole-book verification still includes every leg and enforces footing.
    let (bytes, anchor) = bundle(&records, 8, Selection::AsOf(30), &rows(340, 0));
    assert_eq!(verify_fixture(&bytes, anchor).unwrap().rows, rows(340, 0));
}

#[test]
fn dimension_selectors_respect_recorded_history_and_effective_periods() {
    let mut records = dimensions();
    let child = value_vid(&BOOK, "cost_center", "child");
    records.push(tagged(1, 6, 10, 100, &[(2, child)], &[]));
    records.push(tagged(1, 7, 40, 50, &[(2, child)], &[]));
    for (at, selection, amount) in [
        (6, Selection::AsOf(58), 100),
        (7, Selection::AsOf(20), 100),
        (7, Selection::Periods(vec!["P2".into()]), 150),
        (7, Selection::Activity(vec!["P2".into()]), 50),
    ] {
        let (bytes, anchor) = dimension_bundle(
            &records,
            at,
            selection,
            "root",
            &["child", "root"],
            &cash(amount, 0),
        );
        assert_eq!(
            verify_fixture(&bytes, anchor).unwrap().rows,
            cash(amount, 0)
        );
    }
    let (bytes, anchor) =
        dimension_bundle(&records, 3, Selection::AsOf(58), "root", &["root"], &[]);
    let historical = verify_fixture(&bytes, anchor).unwrap();
    assert!(historical.rows.is_empty());
    assert_eq!(historical.dimension.unwrap().values, ["root"]);
}

#[test]
fn dimension_reports_prove_the_retained_instant_and_historical_tagged_fold() {
    use super::temporal::{selection, tick, with_time};

    let mut records = dimensions();
    let child = value_vid(&BOOK, "cost_center", "child");
    records.extend([
        tick(6, 100, false),
        tagged(1, 7, 10, 100, &[(2, child)], &[]),
        tick(8, 200, true),
        tagged(1, 9, 10, 50, &[(2, child)], &[]),
        tick(10, 300, true),
    ]);
    for (time, amount) in [
        (selection(150, 7, 7, (6, 100, false), None), 100),
        (
            selection(150, 10, 7, (6, 100, false), Some((8, 200, true))),
            100,
        ),
        (
            selection(200, 10, 9, (8, 200, true), Some((10, 300, true))),
            150,
        ),
        (selection(300, 10, 10, (10, 300, true), None), 150),
    ] {
        let (bytes, anchor) = dimension_bundle(
            &records,
            time.resolved_seq,
            Selection::AsOf(30),
            "root",
            &["child", "root"],
            &cash(amount, 0),
        );
        let (instant, _) = with_time(&bytes, &time);
        let report = verify_fixture(&instant, anchor).unwrap();
        assert_eq!(report.known_at, time.resolved_seq);
        assert_eq!(report.time_selection, Some(time));
        assert_eq!(report.rows, cash(amount, 0));
        assert_eq!(report.dimension.unwrap().values, ["child", "root"]);
    }

    let (bytes, anchor) = dimension_bundle(
        &records,
        7,
        Selection::AsOf(30),
        "root",
        &["child", "root"],
        &cash(100, 0),
    );
    let mut forged_time = selection(150, 10, 7, (6, 100, false), Some((8, 200, true)));
    forged_time.upper.as_mut().unwrap().observed_utc_ns = 201;
    let (forged, _) = with_time(&bytes, &forged_time);
    assert_eq!(
        verify_fixture(&forged, anchor).unwrap_err().predicate,
        "time_selection"
    );
}

#[test]
fn closing_a_dimension_keeps_its_historical_tagged_contributions() {
    let mut records = dimensions();
    records.push(tagged(
        1,
        6,
        10,
        100,
        &[(2, value_vid(&BOOK, "cost_center", "child"))],
        &[],
    ));
    records.push(close(7, "child", 20));
    let (bytes, anchor) = dimension_bundle(
        &records,
        7,
        Selection::AsOf(40),
        "root",
        &["child", "root"],
        &cash(100, 0),
    );
    assert_eq!(verify_fixture(&bytes, anchor).unwrap().rows, cash(100, 0));
}

#[test]
fn dimension_pending_balances_release_at_the_recorded_resolution() {
    let mut records = dimensions();
    records.push(tagged(
        2,
        6,
        10,
        75,
        &[(2, value_vid(&BOOK, "cost_center", "child"))],
        &[],
    ));
    let held = &records[5];
    let info = metadata::entry_info(&held.bytes[..held.len], &held.envelope).unwrap();
    let target = (info.identity, held.envelope.record_digest);
    records.push(record(
        3,
        7,
        40,
        b"dimension-void",
        0,
        None,
        Some(target),
        None,
    ));
    let (bytes, anchor) = dimension_bundle(
        &records,
        6,
        Selection::AsOf(20),
        "root",
        &["child", "root"],
        &cash(0, 75),
    );
    assert_eq!(verify_fixture(&bytes, anchor).unwrap().rows, cash(0, 75));
    let (bytes, anchor) = dimension_bundle(
        &records,
        7,
        Selection::AsOf(20),
        "root",
        &["child", "root"],
        &[],
    );
    assert!(verify_fixture(&bytes, anchor).unwrap().rows.is_empty());
}

#[test]
fn claimed_descendants_or_resealed_wrong_balances_never_supply_evidence() {
    let mut records = dimensions();
    records.push(tagged(
        1,
        6,
        10,
        100,
        &[(2, value_vid(&BOOK, "cost_center", "child"))],
        &[],
    ));
    for (values, expected) in [
        (vec!["root"], cash(100, 0)),
        (vec!["child", "other", "root"], cash(100, 0)),
        (vec!["child", "root"], cash(99, 0)),
    ] {
        let (bytes, anchor) =
            dimension_bundle(&records, 6, Selection::AsOf(30), "root", &values, &expected);
        assert_eq!(
            verify_fixture(&bytes, anchor).unwrap_err().predicate,
            "report_recomputation"
        );
    }
    let (bytes, anchor) =
        dimension_bundle(&records, 6, Selection::AsOf(30), "absent", &["absent"], &[]);
    assert_eq!(
        verify_fixture(&bytes, anchor).unwrap_err().predicate,
        "dimension_history"
    );
}

#[test]
fn dimension_tag_kind_and_book_namespace_are_both_bound() {
    let mut records = dimensions();
    records.push(declaration(6, "department", "child", None));
    records.push(tagged(
        1,
        7,
        10,
        25,
        &[(3, value_vid(&BOOK, "department", "child"))],
        &[],
    ));
    let (bytes, anchor) = dimension_bundle(
        &records,
        7,
        Selection::AsOf(30),
        "root",
        &["child", "root"],
        &[],
    );
    // A real value of another dimension is outside the selected subtree.
    assert!(verify_fixture(&bytes, anchor).unwrap().rows.is_empty());

    records.push(tagged(
        1,
        8,
        10,
        40,
        &[(2, value_vid(&[9; 16], "cost_center", "child"))],
        &[],
    ));
    let (bytes, anchor) = dimension_bundle(
        &records,
        8,
        Selection::AsOf(30),
        "root",
        &["child", "root"],
        &[],
    );
    // A foreign-book identity has no authenticated declaration here. It
    // cannot be silently excluded to manufacture a verified empty result.
    assert_eq!(
        verify_fixture(&bytes, anchor).unwrap_err().predicate,
        "dimension_tags",
    );
}

#[test]
fn malformed_dimension_lifecycle_cannot_define_a_report() {
    for invalid in [
        declaration(4, "cost_center", "root", None),
        declaration(4, "cost_center", "child", Some("absent")),
        close(4, "absent", 20),
    ] {
        let mut records = schema();
        records.push(declaration(3, "cost_center", "root", None));
        records.push(invalid);
        let (bytes, anchor) =
            dimension_bundle(&records, 4, Selection::AsOf(30), "root", &["root"], &[]);
        assert_eq!(
            verify_fixture(&bytes, anchor).unwrap_err().predicate,
            "dimension_history"
        );
    }
    let mut records = dimensions();
    records.push(close(6, "child", 20));
    records.push(close(7, "child", 25));
    let (bytes, anchor) = dimension_bundle(
        &records,
        7,
        Selection::AsOf(30),
        "root",
        &["child", "root"],
        &[],
    );
    assert_eq!(
        verify_fixture(&bytes, anchor).unwrap_err().predicate,
        "dimension_history"
    );
}

#[test]
fn altering_authenticated_dimension_control_bytes_is_detected() {
    let mut records = dimensions();
    let control = &mut records[3];
    let at = control
        .bytes
        .windows(5)
        .position(|bytes| bytes == b"child")
        .unwrap();
    control.bytes[at] = b'x';
    let (bytes, anchor) = dimension_bundle(
        &records,
        5,
        Selection::AsOf(30),
        "root",
        &["child", "root"],
        &[],
    );
    assert_eq!(
        verify_fixture(&bytes, anchor).unwrap_err().predicate,
        "record_derivation"
    );
}

#[test]
fn registered_dimension_tags_require_their_authenticated_kind_and_value() {
    for tag in [
        (2, value_vid(&BOOK, "department", "child")),
        (3, value_vid(&BOOK, "cost_center", "child")),
        (2, value_vid(&BOOK, "cost_center", "unknown")),
        (99, value_vid(&BOOK, "cost_center", "child")),
    ] {
        let mut records = dimensions();
        records.push(declaration(6, "department", "child", None));
        records.push(tagged(1, 7, 10, 100, &[tag], &[]));
        let (bytes, anchor) = dimension_bundle(
            &records,
            7,
            Selection::AsOf(30),
            "root",
            &["child", "root"],
            &[],
        );
        assert_eq!(
            verify_fixture(&bytes, anchor).unwrap_err().predicate,
            "dimension_tags",
            "forged tag {tag:?}",
        );
    }
}

#[test]
fn malformed_tag_sets_are_rejected_before_effective_or_pending_selection() {
    let child = value_vid(&BOOK, "cost_center", "child");
    for tags in [
        vec![(2, child), (2, child)],
        vec![(3, child), (2, child)],
        (1_u32..=65).map(|id| (id, child)).collect(),
    ] {
        for retired in [false, true] {
            let mut records = dimensions();
            records.push(tagged(if retired { 2 } else { 1 }, 6, 40, 100, &tags, &[]));
            if retired {
                let mut framed = Writer::default();
                framed
                    .bytes(&BOOK)
                    .bytes(&PRINCIPAL.to_le_bytes())
                    .bytes(b"tagged-6");
                let id = hash_parts(b"fa:vid:entry:v1", &[&framed.buf]);
                let target = (
                    u128::from_le_bytes(id[..16].try_into().unwrap()),
                    records.last().unwrap().envelope.record_digest,
                );
                records.push(record(
                    3,
                    7,
                    40,
                    b"retire-malformed-tags",
                    0,
                    None,
                    Some(target),
                    None,
                ));
            }
            let known_at = if retired { 7 } else { 6 };
            let (bytes, anchor) = dimension_bundle(
                &records,
                known_at,
                Selection::AsOf(20),
                "root",
                &["child", "root"],
                &[],
            );
            assert_eq!(
                verify_fixture(&bytes, anchor).unwrap_err().predicate,
                "record_derivation",
                "retired={retired}, tag_count={}",
                tags.len(),
            );
            // The same native canonical bound protects ordinary reports too.
            let (bytes, anchor) = bundle(&records, known_at, Selection::AsOf(20), &[]);
            assert_eq!(
                verify_fixture(&bytes, anchor).unwrap_err().predicate,
                "record_derivation",
            );
        }
    }
}
