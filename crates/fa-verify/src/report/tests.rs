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
/// One fixture leaf: each argument is one field of the encoded record.
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
    bundle_with_native_inputs(records, known_at, selection, expected_rows, 7)
}

fn bundle_with_native_inputs(
    records: &[Record],
    known_at: u64,
    selection: Selection,
    expected_rows: &[ReportRow],
    native_inputs: usize,
) -> (Vec<u8>, SignedCheckpoint) {
    let inputs = vec![b"native read attestations are not outsider proofs".to_vec(); native_inputs];
    bundle_with_input_values(records, known_at, selection, expected_rows, &inputs)
}

fn entry_fragment_attestation(known_at: u64) -> Vec<u8> {
    let statement = format!(
        "MATCH (n:EntryFragment) FOR SYSTEM_TIME AS OF SEQ {known_at} RETURN n,n._fa_payload,n._fa_digest,n.book_id ORDER BY n"
    );
    let mut input = b"fgdb:native-result-certificate:v1".to_vec();
    input.push(1);
    input.extend_from_slice(&[0; 32]);
    input.extend_from_slice(&known_at.to_be_bytes());
    input.extend_from_slice(&[0; 128]);
    input.push(4); // TemporalPattern
    input.extend_from_slice(&(statement.len() as u64).to_be_bytes());
    input.extend_from_slice(statement.as_bytes());
    input
}

fn bundle_with_input_values(
    records: &[Record],
    known_at: u64,
    selection: Selection,
    expected_rows: &[ReportRow],
    native_inputs: &[Vec<u8>],
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
        Selection::Statement(_)
        | Selection::CustomStatement(_)
        | Selection::Consolidation(_)
        | Selection::OpenItems(_)
        | Selection::ExplainBalance { .. } => {
            panic!("use the report-family fixture")
        }
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
        Selection::Statement(_)
        | Selection::CustomStatement(_)
        | Selection::Consolidation(_)
        | Selection::OpenItems(_)
        | Selection::ExplainBalance { .. } => {
            panic!("use the report-family fixture")
        }
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
        .count(native_inputs.len());
    for input in native_inputs {
        cert.bytes(input);
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
    verify_report_with(bytes, &[], None, None, None, |_, _| Ok(anchor))
}

/// Change only the transport minor and insert an empty source-manifest list.
/// The authenticated checkpoint, certificate, records and all later registry
/// or functional inputs remain byte-for-byte identical.
pub(super) fn with_empty_source_manifest_list(bytes: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(bytes);
    assert_eq!(r.bytes(64, "format").unwrap(), REPORT_BUNDLE_FORMAT);
    assert!(matches!(r.u16("major").unwrap(), 1..=3));
    let minor_offset = bytes.len() - r.remaining();
    assert_eq!(r.u16("minor").unwrap(), 0);
    for field in ["certificate", "checkpoint", "prefix"] {
        r.bytes(MAX_REPORT_BUNDLE_BYTES, field).unwrap();
    }
    let n = r.count(MAX_ROWS, 8, "records").unwrap();
    for _ in 0..n {
        r.u32("proposal_len").unwrap();
        r.bytes(MAX_RECORD_BYTES, "record").unwrap();
    }
    let n = r.count(MAX_ROWS, 12, "migrations").unwrap();
    for _ in 0..n {
        r.u64("open_index").unwrap();
        r.bytes(MAX_RECORD_BYTES, "body").unwrap();
    }
    let after_bodies = bytes.len() - r.remaining();
    let mut changed = bytes.to_vec();
    changed[minor_offset..minor_offset + 2].copy_from_slice(&1u16.to_le_bytes());
    changed.splice(after_bodies..after_bodies, 0u32.to_le_bytes());
    changed
}

#[test]
fn original_and_fragment_source_closures_reproduce_the_same_report() {
    let mut records = schema();
    records.push(record(1, 3, 10, b"fragment-closure", 125, None, None, None));
    for count in [6, 7, 8, 9] {
        let (bytes, anchor) =
            bundle_with_native_inputs(&records, 3, Selection::AsOf(20), &rows(125, 0), count);
        let checked = verify_fixture(&bytes, anchor);
        if count == 7 || count == 8 {
            let checked = checked.unwrap();
            assert_eq!(checked.checked_records, 3);
            assert_eq!(checked.rows[0].debits, 125);
            assert_eq!(checked.rows[1].credits, 125);
        } else {
            assert!(
                checked.is_err(),
                "incomplete or extra closure with {count} inputs"
            );
        }
    }
}

#[test]
fn entry_fragment_closure_preserves_the_source_profile_and_rejects_malformed_tails() {
    let mut records = schema();
    records.push(record(
        1,
        3,
        10,
        b"entry-fragment-closure",
        125,
        None,
        None,
        None,
    ));
    let opaque = b"native read attestations are not outsider proofs".to_vec();
    // Both an inline migration run and a fragmented run can coexist with an
    // EntryFragment input, without claiming there was a BindSource control.
    for original in [7, 8] {
        let mut inputs = vec![opaque.clone(); original];
        inputs.push(entry_fragment_attestation(3));
        let (bytes, anchor) =
            bundle_with_input_values(&records, 3, Selection::AsOf(20), &rows(125, 0), &inputs);
        assert_eq!(verify_fixture(&bytes, anchor).unwrap().rows, rows(125, 0));
    }
    let valid = entry_fragment_attestation(3);
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut wrong_snapshot = valid.clone();
    let snapshot_at = b"fgdb:native-result-certificate:v1".len() + 1 + 32;
    wrong_snapshot[snapshot_at..snapshot_at + 8].copy_from_slice(&2u64.to_be_bytes());
    let mut wrong_version = valid.clone();
    wrong_version[b"fgdb:native-result-certificate:v1".len()] = 2;
    for tail in [
        trailing,
        wrong_snapshot,
        wrong_version,
        entry_fragment_attestation(2),
    ] {
        let mut inputs = vec![opaque.clone(); 7];
        inputs.push(tail);
        let (bytes, anchor) =
            bundle_with_input_values(&records, 3, Selection::AsOf(20), &rows(125, 0), &inputs);
        assert!(verify_fixture(&bytes, anchor).is_err());
    }
    for inputs in [
        vec![valid.clone(); 8],
        [vec![opaque.clone(); 7], vec![valid.clone(), opaque.clone()]].concat(),
        [vec![opaque.clone(); 7], vec![valid.clone(), valid]].concat(),
        vec![opaque; 11],
    ] {
        let (bytes, anchor) =
            bundle_with_input_values(&records, 3, Selection::AsOf(20), &rows(125, 0), &inputs);
        assert!(verify_fixture(&bytes, anchor).is_err());
    }
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
fn atomic_pending_resolution_replays_in_either_journal_identity_order() {
    for resolution_first in [false, true] {
        let mut records = schema();
        let hold = record(2, 3, 10, b"atomic-hold", 75, None, None, None);
        let info = metadata::entry_info(&hold.bytes[..hold.len], &hold.envelope).unwrap();
        let target = (info.identity, hold.envelope.record_digest);
        let resolution = record(3, 3, 40, b"atomic-void", 0, None, Some(target), None);
        // Journal ordinals follow entry identity, not batch execution order.
        // Both payloads are authenticated at the same atomic frontier.
        if resolution_first {
            records.extend([resolution, hold]);
        } else {
            records.extend([hold, resolution]);
        }
        records[3].envelope.within_commit_ordinal = 1;
        for known_at in [2, 3] {
            let (bytes, anchor) = bundle(&records, known_at, Selection::AsOf(20), &[]);
            assert!(verify_fixture(&bytes, anchor).unwrap().rows.is_empty());
        }
    }
}

#[test]
fn atomic_resolution_still_requires_one_authentic_nonfuture_pending_target() {
    for corruption in ["class", "future", "identity", "digest", "duplicate"] {
        let mut records = schema();
        let hold = record(
            if corruption == "class" { 1 } else { 2 },
            if corruption == "future" { 4 } else { 3 },
            10,
            b"target",
            75,
            None,
            None,
            None,
        );
        let info = metadata::entry_info(&hold.bytes[..hold.len], &hold.envelope).unwrap();
        let mut target = (info.identity, hold.envelope.record_digest);
        if corruption == "identity" {
            target.0 ^= 1;
        }
        if corruption == "digest" {
            target.1[0] ^= 1;
        }
        let resolution = record(3, 3, 40, b"release", 0, None, Some(target), None);
        if corruption == "future" {
            records.extend([resolution, hold]);
        } else {
            records.extend([hold, resolution]);
            records[3].envelope.within_commit_ordinal = 1;
        }
        if corruption == "duplicate" {
            let mut duplicate = record(3, 3, 40, b"duplicate", 0, None, Some(target), None);
            duplicate.envelope.within_commit_ordinal = 2;
            records.push(duplicate);
        }
        let known_at = records.last().unwrap().envelope.commit_seq;
        let (bytes, anchor) = bundle(&records, known_at, Selection::AsOf(20), &[]);
        assert_eq!(
            verify_fixture(&bytes, anchor).unwrap_err().predicate,
            "pending_resolution",
            "{corruption}"
        );
    }
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
        verify_report_with(&bytes, &[], Some(&other), None, None, |_, _| Ok(
            anchor.clone()
        ))
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

mod explain;
mod open_items;
mod source_binding;
mod statements;
mod summary;
mod temporal;

// Hand-written definition and expected output, without the producer evaluator
// or this verifier's statement fold. The extra unit is deliberately all zero.
fn native_statement_fixture(amount: i128, omit_mapping: bool) -> (Vec<u8>, SignedCheckpoint) {
    let mut records = schema();
    records.push(record(1, 3, 10, b"jan", 100, None, None, None));
    records.push(record(1, 4, 40, b"feb", 200, None, None, None));
    records.push(record(1, 5, 10, b"later-knowledge", 50, None, None, None));
    let (tb, anchor) = bundle(
        &records,
        4,
        Selection::Periods(vec!["P2".into()]),
        &rows(300, 0),
    );
    let mut old = Reader::new(&tb);
    old.bytes(64, "format").unwrap();
    old.u16("major").unwrap();
    old.u16("minor").unwrap();
    let native = certificate(old.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap()).unwrap();
    let signed = old.bytes(1024, "checkpoint").unwrap();
    let prefix = old.bytes(MAX_REPORT_BUNDLE_BYTES, "prefix").unwrap();
    let mut definition = Writer::default();
    definition
        .fixed(b"FA-STATEMENT-DEF\0")
        .u16(1)
        .u16(0)
        .bytes(b"test-balance")
        .bytes(b"Independent balance")
        .u32(1)
        .u8(0)
        .count(3);
    for (code, typ, sign) in [("assets", 1, 0), ("equity", 3, 1)] {
        definition
            .bytes(code.as_bytes())
            .bytes(code.as_bytes())
            .u8(0)
            .count(1)
            .u8(typ)
            .u8(sign);
    }
    definition
        .bytes(b"balance")
        .bytes(b"balance")
        .u8(1)
        .count(1)
        .bytes(b"assets")
        .count(1)
        .bytes(b"equity")
        .count(1)
        .bytes(b"balance");
    let definition_digest = hash_parts(
        b"fa:statement-definition:v1",
        &[
            &(definition.buf.len() as u32).to_le_bytes(),
            &definition.buf,
        ],
    );
    let mut output = Writer::default();
    output
        .fixed(b"FA-STATEMENT\0")
        .u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(4)
        .bytes(b"test-balance")
        .u32(1)
        .fixed(&definition_digest)
        .bytes(&definition.buf)
        .count(2);
    for (label, period, through) in [("current", "P2", 58), ("comparative", "P1", 30)] {
        output
            .bytes(label.as_bytes())
            .count(1)
            .bytes(period.as_bytes())
            .u8(0)
            .i32(through);
    }
    output.count(6);
    for code in ["assets", "equity", "balance"] {
        for unit in [1, 7] {
            let nonzero = code != "balance" && unit == 1;
            output
                .bytes(code.as_bytes())
                .bytes(code.as_bytes())
                .u32(unit)
                .count(2)
                .i128(if nonzero { amount } else { 0 })
                .i128(if nonzero { 100 } else { 0 });
        }
    }
    output.count(if omit_mapping { 1 } else { 2 });
    for (code, name, typ, line) in [
        ("1000", "Cash", 1, "assets"),
        ("3000", "Equity", 3, "equity"),
    ] {
        if omit_mapping && typ == 3 {
            continue;
        }
        output
            .u128(account_id(code))
            .bytes(code.as_bytes())
            .bytes(name.as_bytes())
            .u8(typ)
            .u8(1)
            .bytes(line.as_bytes());
    }
    let mut cert = Writer::default();
    cert.fixed(STATEMENT_CERTIFICATE_FORMAT)
        .bytes(b"fa-fold-over-prefix")
        .bytes(b"embedded-owner")
        .bytes(b"fa:statement:v1")
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(4)
        .u8(2)
        .bytes(&definition.buf)
        .count(1)
        .bytes(b"P2")
        .count(1)
        .bytes(b"P1")
        .fixed(&[0; 32])
        .fixed(&native.journal_root)
        .u64(native.leaves)
        .count(7);
    for _ in 0..7 {
        cert.bytes(b"not an outsider proof");
    }
    cert.bytes(&output.buf)
        .fixed(&hash_parts(b"fa:report-output:v1", &[&output.buf]))
        .u8(0);
    let digest = hash_parts(STATEMENT_CERTIFICATE_FORMAT, &[&cert.buf]);
    cert.fixed(&digest);
    let mut result = Writer::default();
    result
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(1)
        .u16(0)
        .bytes(&cert.buf)
        .bytes(signed)
        .bytes(prefix)
        .count(records.len());
    for record in records {
        result.u32(record.len as u32).bytes(&record.bytes);
    }
    result.count(0);
    (result.buf, anchor)
}

#[test]
fn native_statement_uses_recipient_units_comparatives_and_authenticated_mappings() {
    let (bytes, anchor) = native_statement_fixture(300, false);
    let report = verify_report_with_units(&bytes, &[], None, None, Some(&[1, 7]), |_, _| {
        Ok(anchor.clone())
    })
    .unwrap();
    assert!(report.rows.is_empty());
    assert_eq!(report.unit_universe_source, "recipient-supplied");
    let statement = report.statement.unwrap();
    assert_eq!(statement.columns.len(), 2);
    assert_eq!(statement.lines[0].amounts, [300, 100]);
    assert_eq!(statement.lines[1].amounts, [0, 0]);
    assert_eq!(statement.lines[4].amounts, [0, 0]);
    assert_eq!(
        verify_fixture(&bytes, anchor.clone())
            .unwrap_err()
            .predicate,
        "statement_units"
    );
    assert_eq!(
        verify_report_with_units(&bytes, &[], None, None, Some(&[7]), |_, _| Ok(
            anchor.clone()
        ))
        .unwrap_err()
        .predicate,
        "statement_units"
    );
    assert_eq!(
        verify_report_with_units(&bytes, &[], None, None, Some(&[1]), |_, _| Ok(anchor))
            .unwrap_err()
            .predicate,
        "report_recomputation"
    );
    for (amount, omitted) in [(301, false), (300, true)] {
        let (bytes, anchor) = native_statement_fixture(amount, omitted);
        assert_eq!(
            verify_report_with_units(&bytes, &[], None, None, Some(&[1, 7]), |_, _| Ok(anchor))
                .unwrap_err()
                .predicate,
            "report_recomputation"
        );
    }
}

#[test]
fn recipient_statement_unit_lists_are_validated_before_untrusted_bytes() {
    for units in [vec![], vec![2, 1], vec![1, 1], (0..4097).collect()] {
        assert_eq!(
            verify_statement_report(&[], &[], None, None, &units)
                .unwrap_err()
                .predicate,
            "statement_units"
        );
    }
    let records = schema();
    let (bytes, _) = bundle(&records, 2, Selection::AsOf(30), &[]);
    assert_eq!(
        verify_statement_report(&bytes, &[], None, None, &[1])
            .unwrap_err()
            .predicate,
        "supported_report"
    );
}

#[path = "tests/dimension.rs"]
mod dimension_tests;

#[path = "tests/class_laws.rs"]
mod class_laws;
