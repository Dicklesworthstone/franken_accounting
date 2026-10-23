//! These tests provide the trusted checkpoint directly to the fold boundary;
//! checkpoint signatures are tested independently in `checkpoint`, and the
//! producer differential tests exercise the public signed-report entry point.
use super::*;
use crate::envelope::{
    ENTRY_DIGEST_DOMAIN, LeafEnvelope, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry,
};
use crate::proof::PREFIX_FORMAT;

const BOOK: [u8; 16] = [3; 16];
const PRINCIPAL: u128 = 7;
struct Record {
    bytes: Vec<u8>,
    len: usize,
    envelope: LeafEnvelope,
}
fn account_id(code: &str) -> u128 {
    crate::ads::account_vid(&BOOK, code)
}
fn erasable(w: &mut Writer) {
    w.fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(&[]);
}
#[allow(clippy::too_many_arguments)]
fn record(
    class: u16,
    seq: u64,
    day: i32,
    key: &[u8],
    amount: i128,
    schema: Option<(u16, &[u8])>,
    resolution: Option<(u128, [u8; 32])>,
    period: Option<&str>,
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
    w.u8(u8::from(period.is_some()));
    if let Some(period) = period {
        w.bytes(b"cy").bytes(period.as_bytes());
    }
    w.count(if amount == 0 { 0 } else { 2 });
    if amount != 0 {
        for (code, side) in [("1000", 0), ("3000", 1)] {
            w.u8(side)
                .u128(account_id(code))
                .u32(1)
                .i128(amount)
                .u8(0)
                .count(0)
                .u8(0)
                .count(0);
        }
    }
    w.u8(u8::from(schema.is_some()));
    if let Some((kind, body)) = schema {
        w.u8(1).u16(kind).bytes(body);
    }
    w.count(0).u8(0).bytes(key);
    if let Some((kind, _)) = schema {
        w.u8(3).u16(if kind == 13 { 13 } else { 1 }).fixed(&[0; 32]);
    } else {
        w.u8(0).fixed(&[0; 32]).u16(1);
    }
    w.u128(PRINCIPAL).u8(0).count(0).count(0);
    if class == 2 || resolution.is_some() {
        w.u8(1).u8(0).u8(u8::from(resolution.is_some()));
        if let Some((vid, digest)) = resolution {
            w.u128(vid).fixed(&digest).u8(1).u8(1);
        } else {
            w.u8(0);
        }
    } else {
        w.u8(0);
    }
    w.count(0).count(0);
    let len = w.buf.len();
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    // The record digest commits its acceptance envelope, which is opaque to
    // arithmetic verification. The kernel differential fixture supplies real ones.
    let entry_digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[]]);
    w.fixed(&proposal_digest).fixed(&entry_digest);
    let envelope = envelope_of_entry(&w.buf, len, seq, 0).unwrap();
    Record {
        bytes: w.buf,
        len,
        envelope,
    }
}
fn schema() -> Vec<Record> {
    let mut chart = Writer::default();
    chart.count(2);
    for (code, name, typ, normal) in [("1000", "Cash", 1, 0), ("3000", "Equity", 3, 1)] {
        chart
            .bytes(code.as_bytes())
            .bytes(name.as_bytes())
            .u8(typ)
            .u8(normal)
            .u8(1)
            .fixed(&1i64.to_le_bytes())
            .u8(0);
    }
    let mut periods = Writer::default();
    periods
        .fixed(b"fa:period-creation:v1")
        .bytes(b"cy")
        .i32(2026)
        .count(2);
    for (code, start, end, ordinal) in [("P1", 0, 31, 1), ("P2", 31, 59, 2)] {
        periods
            .bytes(code.as_bytes())
            .i32(2026)
            .u16(ordinal)
            .u8(0)
            .i32(start)
            .i32(end)
            .u8(0);
    }
    vec![
        record(17, 1, 0, b"chart", 0, Some((1, &chart.buf)), None, None),
        record(
            17,
            2,
            0,
            b"periods",
            0,
            Some((13, &periods.buf)),
            None,
            None,
        ),
    ]
}
fn signed(checkpoint: Checkpoint) -> SignedCheckpoint {
    SignedCheckpoint {
        checkpoint,
        state_oid: [0; 32],
        scope_index_root: [0; 32],
        substrate_chain_commitment: [0; 32],
        witness_policy_oid: None,
        time_evidence_oid: None,
        body_digest: [0; 32],
        oid: [0; 32],
        signed_by: vec![],
        not_judged: vec![],
    }
}
fn rows(posted: i128, pending: i128) -> Vec<ReportRow> {
    vec![
        ReportRow {
            account: account_id("1000"),
            code: "1000".into(),
            name: "Cash".into(),
            account_type: 1,
            unit: 1,
            debits: posted,
            credits: 0,
            debits_pending: pending,
            credits_pending: 0,
        },
        ReportRow {
            account: account_id("3000"),
            code: "3000".into(),
            name: "Equity".into(),
            account_type: 3,
            unit: 1,
            debits: 0,
            credits: posted,
            debits_pending: 0,
            credits_pending: pending,
        },
    ]
}
fn bundle(
    records: &[Record],
    known_at: u64,
    selection: Selection,
    expected_rows: &[ReportRow],
) -> (Vec<u8>, SignedCheckpoint) {
    let envelopes: Vec<_> = records.iter().map(|r| r.envelope.encode()).collect();
    let checkpoint = Checkpoint {
        book_id: BOOK,
        branch_id: [0; 16],
        through_seq: records.last().unwrap().envelope.commit_seq,
        leaf_count: records.len() as u64,
        root: root_of(&envelopes.iter().map(|e| leaf_hash(e)).collect::<Vec<_>>()),
    };
    let mut prefix = Writer::default();
    prefix
        .bytes(PREFIX_FORMAT)
        .fixed(&checkpoint.encode())
        .count(envelopes.len());
    for envelope in &envelopes {
        prefix.bytes(envelope);
    }
    let historical: Vec<_> = records
        .iter()
        .filter(|r| r.envelope.commit_seq <= known_at)
        .map(|r| leaf_hash(&r.envelope.encode()))
        .collect();
    let (codes, cutoff, activity) = match &selection {
        Selection::AsOf(day) => (
            if *day < 31 {
                vec!["P1".into()]
            } else {
                vec!["P1".into(), "P2".into()]
            },
            Some(*day),
            false,
        ),
        Selection::Periods(p) => (
            p.clone(),
            Some(if p.last().unwrap() == "P1" { 30 } else { 58 }),
            false,
        ),
        Selection::Activity(p) => (p.clone(), None, true),
    };
    let mut totals = BTreeMap::new();
    for row in expected_rows {
        let t = totals.entry(row.unit).or_insert([0i128; 4]);
        t[0] += row.debits;
        t[1] += row.credits;
        t[2] += row.debits_pending;
        t[3] += row.credits_pending;
    }
    let output = output(&codes, known_at, cutoff, activity, expected_rows, &totals);
    let mut cert = Writer::default();
    cert.fixed(CERTIFICATE_FORMAT)
        .bytes(b"fa-fold-over-prefix")
        .bytes(b"embedded-owner")
        .bytes(OUTPUT_FORMAT)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(known_at);
    match selection {
        Selection::AsOf(day) => {
            cert.u8(1).i32(day);
        }
        Selection::Periods(p) | Selection::Activity(p) => {
            cert.u8(if activity { 2 } else { 0 }).count(p.len());
            for code in p {
                cert.bytes(code.as_bytes());
            }
        }
    }
    cert.fixed(&[0; 32])
        .fixed(&root_of(&historical))
        .u64(historical.len() as u64)
        .count(7);
    for _ in 0..7 {
        cert.bytes(b"native read attestations are not outsider proofs");
    }
    cert.bytes(&output)
        .fixed(&hash_parts(b"fa:report-output:v1", &[&output]));
    let digest = hash_parts(CERTIFICATE_FORMAT, &[&cert.buf]);
    cert.fixed(&digest);
    let mut out = Writer::default();
    out.bytes(REPORT_BUNDLE_FORMAT)
        .u16(1)
        .u16(0)
        .bytes(&cert.buf)
        .bytes(b"external trusted fixture")
        .bytes(&prefix.buf)
        .count(records.len());
    for record in records {
        out.u32(record.len as u32).bytes(&record.bytes);
    }
    out.count(0);
    (out.buf, signed(checkpoint))
}
fn verify_fixture(bytes: &[u8], anchor: SignedCheckpoint) -> Result<VerifiedReport, ReportError> {
    verify_report_with(bytes, &[], None, None, |_, _| Ok(anchor))
}
#[test]
fn stock_activity_and_historical_reports_are_independently_recomputed() {
    let mut records = schema();
    records.push(record(1, 3, 10, b"jan", 100, None, None, None));
    records.push(record(1, 4, 40, b"feb", 200, None, None, None));
    for (known_at, selection, total) in [
        (4, Selection::AsOf(20), 100),
        (4, Selection::Periods(vec!["P2".into()]), 300),
        (4, Selection::Activity(vec!["P2".into()]), 200),
        (3, Selection::AsOf(58), 100),
    ] {
        let (bytes, anchor) = bundle(&records, known_at, selection, &rows(total, 0));
        let verified = verify_fixture(&bytes, anchor).unwrap();
        assert_eq!(verified.rows[0].debits, total);
        assert_eq!(verified.rows[1].credits, total);
        assert_eq!(verified.checked_records, 4);
    }
}
#[test]
fn pending_is_separate_and_resolution_releases_it_at_known_at() {
    let mut records = schema();
    records.push(record(2, 3, 10, b"hold", 75, None, None, None));
    let info =
        metadata::entry_info(&records[2].bytes[..records[2].len], &records[2].envelope).unwrap();
    let target = (info.identity, records[2].envelope.record_digest);
    records.push(record(3, 4, 40, b"void", 0, None, Some(target), None));
    let (bytes, anchor) = bundle(&records, 3, Selection::AsOf(20), &rows(0, 75));
    assert_eq!(
        verify_fixture(&bytes, anchor).unwrap().rows[0].debits_pending,
        75
    );
    let (bytes, anchor) = bundle(&records, 4, Selection::AsOf(20), &[]);
    assert!(verify_fixture(&bytes, anchor).unwrap().rows.is_empty());
}
#[test]
fn resealed_false_amount_or_account_label_does_not_verify() {
    let mut records = schema();
    records.push(record(1, 3, 10, b"posting", 100, None, None, None));
    let mut altered = rows(101, 0);
    let (bytes, anchor) = bundle(&records, 3, Selection::AsOf(20), &altered);
    assert_eq!(
        verify_fixture(&bytes, anchor).unwrap_err().predicate,
        "report_recomputation"
    );
    altered = rows(100, 0);
    altered[0].name = "fabricated label".into();
    let (bytes, anchor) = bundle(&records, 3, Selection::AsOf(20), &altered);
    assert_eq!(
        verify_fixture(&bytes, anchor).unwrap_err().predicate,
        "report_recomputation"
    );
    let (bytes, anchor) = bundle(&records, 3, Selection::AsOf(20), &[]);
    assert_eq!(
        verify_fixture(&bytes, anchor).unwrap_err().predicate,
        "report_recomputation"
    );
}
#[test]
fn incomplete_payloads_wrong_anchor_and_unsigned_self_trust_are_refused() {
    let mut records = schema();
    records.push(record(1, 3, 10, b"posting", 100, None, None, None));
    let (mut bytes, anchor) = bundle(&records, 3, Selection::AsOf(20), &rows(100, 0));
    assert_eq!(
        verify_report(&bytes, &[], None, None)
            .unwrap_err()
            .predicate,
        "checkpoint_signature"
    );
    let mut other = anchor.checkpoint;
    other.through_seq += 1;
    assert_eq!(
        verify_report_with(&bytes, &[], Some(&other), None, |_, _| Ok(anchor.clone()))
            .unwrap_err()
            .predicate,
        "recipient_checkpoint"
    );
    let last_payload = bytes
        .windows(records[2].bytes.len())
        .position(|w| w == records[2].bytes)
        .unwrap();
    bytes[last_payload + 38] ^= 1;
    assert_eq!(
        verify_fixture(&bytes, anchor).unwrap_err().predicate,
        "record_derivation"
    );
}
