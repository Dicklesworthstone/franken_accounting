//! Independent amount vectors and hostile complete-bundle fixtures.

use super::super::{
    FUNCTIONAL_CERTIFICATE_FORMAT, REPORT_BUNDLE_FORMAT, certificate, verify_report_with_inputs,
};
use super::*;
use crate::checkpoint::SignedCheckpoint;
use crate::envelope::{
    CUSTODY_DIGEST_DOMAIN, ENTRY_DIGEST_DOMAIN, KIND_ENTRY, KIND_IMPORT_RECEIPT,
    PROPOSAL_DIGEST_DOMAIN, check_record, envelope_of_entry, envelope_of_record,
};
use crate::proof::{Checkpoint, PREFIX_FORMAT};
use crate::tree::{leaf_hash, root_of};

const BOOK: [u8; 16] = [3; 16];
const PRINCIPAL: u128 = 7;
#[derive(Clone)]
struct Record {
    bytes: Vec<u8>,
    len: usize,
    envelope: LeafEnvelope,
}
#[derive(Clone)]
struct RateFixture {
    oid: [u8; 32],
    commitment: [u8; 32],
    document: Vec<u8>,
}
#[derive(Clone)]
struct TestLeg {
    code: &'static str,
    debit: bool,
    unit: u32,
    native: i128,
    base: Option<i128>,
    entity: Option<&'static str>,
}
fn id(code: &str) -> u128 {
    crate::ads::account_vid(&BOOK, code)
}
fn erasable(w: &mut Writer) {
    w.fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(&[]);
}
fn finish(mut w: Writer, seq: u64) -> Record {
    let len = w.buf.len();
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    w.fixed(&proposal).fixed(&digest);
    let envelope = envelope_of_entry(&w.buf, len, seq, 0).unwrap();
    Record {
        bytes: w.buf,
        len,
        envelope,
    }
}
fn prefix(class: u16, day: i32) -> Writer {
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(class)
        .i32(day)
        .u8(0);
    erasable(&mut w);
    w.u8(0);
    w
}
fn schema_record(seq: u64, kind: u16, body: &[u8]) -> Record {
    let mut w = prefix(17, 0);
    w.count(0)
        .u8(1)
        .u8(1)
        .u16(kind)
        .bytes(body)
        .count(0)
        .u8(0)
        .bytes(if kind == 1 { b"chart" } else { b"periods" })
        .u8(3)
        .u16(if kind == 13 { 13 } else { 1 })
        .fixed(&[0; 32])
        .u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(0)
        .u8(0)
        .count(0)
        .count(0);
    finish(w, seq)
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
            .fixed(&(-1i64).to_le_bytes())
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
        schema_record(1, 1, &chart.buf),
        schema_record(2, 13, &periods.buf),
    ]
}
fn book(entities: &[&str]) -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(2)
        .fixed(&BOOK)
        .bytes(b"Functional fixture")
        .u32(0)
        .bytes(b"cy")
        .u8(0)
        .u8(0)
        .u8(1);
    if !entities.is_empty() {
        w.u8(0).count(entities.len());
        for entity in entities {
            w.bytes(entity.as_bytes()).bytes(entity.as_bytes()).u32(0);
        }
    }
    w.buf
}
fn rate_fixture(num: u128, den: u128, purpose: u8, date: i32) -> RateFixture {
    let mut rate = Writer::default();
    rate.fixed(b"FA-FX-RATE\0")
        .u16(1)
        .u32(0)
        .u32(1)
        .u128(num)
        .u128(den)
        .u16(3)
        .i32(date)
        .u64(123)
        .u8(purpose)
        .bytes(b"fixture source");
    let commitment = crate::document::doc_commit(11, &rate.buf);
    let oid = framed_hash(b"fa:oid:document:v1", &[&BOOK, &commitment]);
    let mut document = Writer::default();
    document
        .u16(1)
        .fixed(&BOOK)
        .u8(11)
        .bytes(b"application/vnd.fa.fx-rate")
        .u64(rate.buf.len() as u64)
        .fixed(&commitment)
        .u8(2)
        .u128(PRINCIPAL)
        .u8(0)
        .bytes(&rate.buf);
    RateFixture {
        oid,
        commitment,
        document: document.buf,
    }
}
fn intake(rate: &RateFixture, seq: u64) -> Record {
    let mut w = Writer::default();
    w.u16(1)
        .fixed(&BOOK)
        .fixed(&rate.oid)
        .u32(0)
        .fixed(&[0; 32])
        .u8(1)
        .u8(1)
        .u128(PRINCIPAL)
        .u128(PRINCIPAL)
        .fixed(&rate.commitment)
        .u8(0)
        .count(0);
    let len = w.buf.len();
    let digest = framed_hash(CUSTODY_DIGEST_DOMAIN, &[&w.buf]);
    w.fixed(&digest);
    let envelope = envelope_of_record(KIND_IMPORT_RECEIPT, &w.buf, len, seq, 0).unwrap();
    Record {
        bytes: w.buf,
        len,
        envelope,
    }
}
fn handle(record: &Record) -> (u128, [u8; 32]) {
    let info = metadata::entry_info(&record.bytes[..record.len], &record.envelope).unwrap();
    (info.identity, record.envelope.record_digest)
}
#[allow(clippy::too_many_arguments)]
fn entry(
    seq: u64,
    class: u16,
    day: i32,
    key: &[u8],
    legs: &[TestLeg],
    claim: Option<(u16, &RateFixture, Option<(u16, i128)>)>,
    reverses: Option<&Record>,
    resolves: Option<&Record>,
) -> Record {
    let mut w = prefix(class, day);
    w.count(legs.len());
    let mut native: BTreeMap<u32, (i128, i128)> = BTreeMap::new();
    let mut base = (0, 0);
    for leg in legs {
        w.u8(u8::from(!leg.debit))
            .u128(id(leg.code))
            .u32(leg.unit)
            .i128(leg.native)
            .u8(u8::from(leg.base.is_some()));
        if let Some(amount) = leg.base {
            w.u32(0).i128(amount);
            if leg.debit {
                base.0 += amount;
            } else {
                base.1 += amount;
            }
        }
        w.count(usize::from(leg.entity.is_some()));
        if let Some(entity) = leg.entity {
            let digest = framed_hash(
                b"fa:vid:dimension-value:v1",
                &[&BOOK, b"legal_entity", entity.as_bytes()],
            );
            w.u32(1)
                .u128(u128::from_le_bytes(digest[..16].try_into().unwrap()));
        }
        w.u8(0).count(0);
        let sum = native.entry(leg.unit).or_default();
        if leg.debit {
            sum.0 += leg.native;
        } else {
            sum.1 += leg.native;
        }
    }
    w.u8(0).count(native.len());
    for (unit, (debits, credits)) in native {
        w.u32(unit).i128(debits).i128(credits);
    }
    w.u8(u8::from(claim.is_some()));
    if let Some((law, rate, residual)) = claim {
        w.u32(0)
            .i128(base.0)
            .i128(base.1)
            .fixed(&valuation::law_oid(law))
            .count(1)
            .fixed(&rate.oid)
            .u8(u8::from(residual.is_some()));
        if let Some((ordinal, amount)) = residual {
            w.u16(ordinal).u32(0).i128(amount);
        }
    }
    w.bytes(key)
        .u8(0)
        .fixed(&[0; 32])
        .u16(1)
        .u128(PRINCIPAL)
        .u8(0)
        .count(usize::from(claim.is_some()));
    if let Some((_, rate, _)) = claim {
        w.fixed(&rate.oid).fixed(&rate.commitment).u8(3);
    }
    w.count(usize::from(reverses.is_some()));
    if let Some(target) = reverses {
        let (identity, digest) = handle(target);
        w.u128(identity).fixed(&digest).u8(1).u16(0);
    }
    if class == 2 || resolves.is_some() {
        w.u8(1).u8(0).u8(u8::from(resolves.is_some()));
        if let Some(target) = resolves {
            let (identity, digest) = handle(target);
            w.u128(identity).fixed(&digest).u8(1).u8(1);
        } else {
            w.u8(0);
        }
    } else {
        w.u8(0);
    }
    w.count(0).count(0);
    finish(w, seq)
}
fn residual_legs() -> Vec<TestLeg> {
    [
        ("1000", true, 8, 3),
        ("3000", false, 4, 2),
        ("3000", false, 4, 1),
    ]
    .into_iter()
    .map(|(code, debit, native, base)| TestLeg {
        code,
        debit,
        unit: 1,
        native,
        base: Some(base),
        entity: None,
    })
    .collect()
}
fn pair(native: i128, base: i128) -> Vec<TestLeg> {
    [("1000", true), ("3000", false)]
        .into_iter()
        .map(|(code, debit)| TestLeg {
            code,
            debit,
            unit: 1,
            native,
            base: Some(base),
            entity: None,
        })
        .collect()
}
fn unhex(s: &str) -> Vec<u8> {
    let bytes: Vec<_> = s
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    bytes
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn registries() -> Vec<(String, Vec<u8>)> {
    let mut result = Vec::new();
    for source in [
        include_str!("../tests/registries.hex"),
        include_str!("registries.hex"),
    ] {
        let bytes = unhex(source);
        let mut r = Reader::new(&bytes);
        let count = r.count(6, 8, "registries").unwrap();
        for _ in 0..count {
            result.push((
                text(&mut r, 64, "registry.name").unwrap().into(),
                r.bytes(1024 * 1024, "registry.bytes").unwrap().to_vec(),
            ));
        }
        r.finish("registries").unwrap();
    }
    result
}
fn closure(docs: &[(String, Vec<u8>)]) -> [u8; 32] {
    let mut bytes = Vec::new();
    for (name, document) in docs {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&hash_parts(b"fa:registry-canonical-digest:v1", &[document]));
    }
    hash_parts(b"fa:report-registry-closure:v2", &[&bytes])
}
fn definitions() -> registry::FunctionalRegistry {
    let docs = registries();
    let inputs: Vec<_> = docs
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    registry::verify_functional(&inputs, &closure(&docs)).unwrap()
}
fn replay_fixture(
    records: &[Record],
    selected: Selection,
    known_at: u64,
    spec: &[u8],
    rates: &[RateFixture],
) -> Result<(VerifiedFunctionalTrialBalance, Vec<u8>), ReportError> {
    let envelopes: Vec<_> = records
        .iter()
        .map(|record| record.envelope.clone())
        .collect();
    let raw: Vec<_> = records
        .iter()
        .map(|record| (record.len, record.bytes.as_slice()))
        .collect();
    let legs = envelopes
        .iter()
        .zip(&raw)
        .map(|(envelope, (len, bytes))| check_record(envelope, bytes, *len).unwrap())
        .collect::<Vec<_>>();
    let mut infos = BTreeMap::new();
    let mut schema = metadata::Schema::default();
    for (index, record) in records.iter().enumerate() {
        if record.envelope.kind != KIND_ENTRY || record.envelope.commit_seq > known_at {
            continue;
        }
        let info = metadata::entry_info(&record.bytes[..record.len], &record.envelope)?;
        if let Some((kind, bytes)) = info.schema {
            schema.apply(kind, bytes, &BOOK, record.envelope.commit_seq)?;
        }
        infos.insert(index, info);
    }
    let by_digest: BTreeMap<_, _> = infos
        .keys()
        .map(|index| (envelopes[*index].record_digest, *index))
        .collect();
    let releases: BTreeMap<_, _> = infos
        .iter()
        .filter_map(|(index, info)| {
            info.resolution
                .map(|(_, digest)| (by_digest[&digest], envelopes[*index].commit_seq))
        })
        .collect();
    let cert = Certificate {
        book: BOOK,
        branch: [0; 16],
        known_at,
        time_selection: None,
        selection: selected,
        dimension: None,
        functional: true,
        registry_digest: [0; 32],
        journal_root: [0; 32],
        leaves: 0,
        output: &[],
        output_digest: [0; 32],
        digest: [0; 32],
    };
    let mut documents: Vec<_> = rates
        .iter()
        .map(|rate| (rate.oid, rate.document.as_slice()))
        .collect();
    documents.sort_by_key(|(oid, _)| *oid);
    replay(
        &cert,
        &definitions(),
        spec,
        &documents,
        &schema,
        &envelopes,
        &raw,
        &legs,
        &infos,
        &releases,
    )
}
fn basic() -> (Vec<Record>, RateFixture) {
    let rate = rate_fixture(1, 3, 1, 10);
    let mut records = schema();
    records.push(intake(&rate, 3));
    records.push(entry(
        4,
        1,
        10,
        b"valued",
        &residual_legs(),
        Some((1, &rate, Some((1, 1)))),
        None,
        None,
    ));
    records.push(entry(
        5,
        2,
        10,
        b"hold",
        &pair(3, 1),
        Some((1, &rate, None)),
        None,
        None,
    ));
    (records, rate)
}
#[test]
fn direct_conversion_residual_and_pending_cells_replay_in_all_three_selectors() {
    let (records, rate) = basic();
    for selected in [
        Selection::AsOf(20),
        Selection::Periods(vec!["P1".into()]),
        Selection::Activity(vec!["P1".into()]),
    ] {
        let (result, _) =
            replay_fixture(&records, selected, 5, &book(&[]), &[rate.clone()]).unwrap();
        let cash = result
            .cells
            .iter()
            .find(|cell| cell.account == id("1000"))
            .unwrap();
        let equity = result
            .cells
            .iter()
            .find(|cell| cell.account == id("3000"))
            .unwrap();
        assert_eq!((cash.debits, cash.credits, cash.entry_count), (3, 0, 1));
        assert_eq!(
            (equity.debits, equity.credits, equity.entry_count),
            (0, 3, 1)
        );
        assert_eq!(
            result.pending.iter().map(|cell| cell.debits).sum::<i128>(),
            1
        );
        assert_eq!(
            result.pending.iter().map(|cell| cell.credits).sum::<i128>(),
            1
        );
        assert_eq!((result.entries, result.watermark), (1, Some(5)));
        assert_eq!(result.accounts.len(), 2);
    }
}
#[test]
fn later_effective_release_changes_historical_stock_and_preserves_its_witness() {
    let (mut records, rate) = basic();
    records.push(entry(
        6,
        3,
        40,
        b"release",
        &[],
        None,
        None,
        Some(&records[4]),
    ));
    let (before, _) = replay_fixture(
        &records,
        Selection::AsOf(20),
        5,
        &book(&[]),
        &[rate.clone()],
    )
    .unwrap();
    let (after, _) = replay_fixture(&records, Selection::AsOf(20), 6, &book(&[]), &[rate]).unwrap();
    assert_eq!(before.cells, after.cells);
    assert!(!before.pending.is_empty());
    assert!(after.pending.is_empty());
    assert_eq!(after.watermark, Some(6));
    assert_ne!(before.fold_digest, after.fold_digest);
}
#[test]
fn exact_reversals_preserve_original_rate_date_and_residual_assignment() {
    let (mut records, rate) = basic();
    let reversed: Vec<_> = residual_legs()
        .into_iter()
        .map(|mut leg| {
            leg.debit = !leg.debit;
            leg
        })
        .collect();
    records.push(entry(
        6,
        4,
        40,
        b"reverse",
        &reversed,
        Some((1, &rate, Some((1, 1)))),
        Some(&records[3]),
        None,
    ));
    let (result, _) = replay_fixture(
        &records,
        Selection::AsOf(58),
        6,
        &book(&[]),
        &[rate.clone()],
    )
    .unwrap();
    assert!(
        result
            .cells
            .iter()
            .all(|cell| cell.debits == 3 && cell.credits == 3)
    );
    let mut forged = reversed;
    forged[1].base = Some(1);
    forged[2].base = Some(2);
    records[5] = entry(
        6,
        4,
        40,
        b"reverse",
        &forged,
        Some((1, &rate, Some((2, 1)))),
        Some(&records[3]),
        None,
    );
    assert_eq!(
        replay_fixture(&records, Selection::AsOf(58), 6, &book(&[]), &[rate])
            .unwrap_err()
            .predicate,
        "functional_reversal"
    );
}
#[test]
fn average_date_is_the_authenticated_period_end_and_out_of_scope_claims_are_checked() {
    let rate = rate_fixture(5, 4, 3, 30);
    let mut records = schema();
    records.push(intake(&rate, 3));
    records.push(entry(
        4,
        1,
        10,
        b"average",
        &pair(100, 125),
        Some((3, &rate, None)),
        None,
        None,
    ));
    let (result, _) = replay_fixture(
        &records,
        Selection::Activity(vec!["P1".into()]),
        4,
        &book(&[]),
        &[rate.clone()],
    )
    .unwrap();
    assert_eq!(
        result.cells.iter().map(|cell| cell.debits).sum::<i128>(),
        125
    );
    records[3] = entry(
        4,
        1,
        10,
        b"average",
        &pair(100, 124),
        Some((3, &rate, None)),
        None,
        None,
    );
    assert_eq!(
        replay_fixture(&records, Selection::AsOf(0), 4, &book(&[]), &[rate])
            .unwrap_err()
            .predicate,
        "functional_valuation"
    );
}
#[test]
fn entity_fallback_is_declared_and_residuals_cannot_cross_partitions() {
    let (records, rate) = basic();
    let (single, _) = replay_fixture(
        &records,
        Selection::AsOf(20),
        5,
        &book(&["A"]),
        &[rate.clone()],
    )
    .unwrap();
    assert!(
        single
            .cells
            .iter()
            .all(|cell| cell.entity.as_deref() == Some("A"))
    );
    assert_eq!(
        replay_fixture(
            &records,
            Selection::AsOf(20),
            5,
            &book(&["A", "B"]),
            &[rate.clone()]
        )
        .unwrap_err()
        .predicate,
        "functional_entity"
    );
    let mut doubled = residual_legs();
    for leg in &mut doubled {
        leg.entity = Some("A");
    }
    let mut second = residual_legs();
    for leg in &mut second {
        leg.entity = Some("B");
    }
    doubled.extend(second);
    let mut records = schema();
    records.push(intake(&rate, 3));
    records.push(entry(
        4,
        1,
        10,
        b"two-residuals",
        &doubled,
        Some((1, &rate, Some((1, 1)))),
        None,
        None,
    ));
    assert_eq!(
        replay_fixture(
            &records,
            Selection::AsOf(20),
            4,
            &book(&["A", "B"]),
            &[rate]
        )
        .unwrap_err()
        .predicate,
        "functional_residual"
    );
}
#[test]
fn rate_closure_rejects_missing_extra_tampered_and_late_or_missing_intake() {
    let (records, rate) = basic();
    assert_eq!(
        replay_fixture(&records, Selection::AsOf(20), 5, &book(&[]), &[])
            .unwrap_err()
            .predicate,
        "functional_rates"
    );
    let extra = rate_fixture(2, 3, 1, 10);
    assert_eq!(
        replay_fixture(
            &records,
            Selection::AsOf(20),
            5,
            &book(&[]),
            &[rate.clone(), extra]
        )
        .unwrap_err()
        .predicate,
        "functional_rates"
    );
    let mut changed = rate.clone();
    let last = changed.document.len() - 1;
    changed.document[last] ^= 1;
    assert_eq!(
        replay_fixture(&records, Selection::AsOf(20), 5, &book(&[]), &[changed])
            .unwrap_err()
            .predicate,
        "functional_rates"
    );
    let mut missing = records.clone();
    missing.remove(2);
    assert_eq!(
        replay_fixture(
            &missing,
            Selection::AsOf(20),
            5,
            &book(&[]),
            &[rate.clone()]
        )
        .unwrap_err()
        .predicate,
        "functional_rate_visibility"
    );
    let mut late = records;
    late[2] = intake(&rate, 5);
    assert_eq!(
        replay_fixture(&late, Selection::AsOf(20), 5, &book(&[]), &[rate.clone()])
            .unwrap_err()
            .predicate,
        "functional_rate_visibility"
    );
    late[2] = intake(&rate, 4);
    replay_fixture(&late, Selection::AsOf(20), 5, &book(&[]), &[rate]).unwrap();
}
#[test]
fn unsupported_laws_and_wrong_date_do_not_become_trusted_base_amounts() {
    let (mut records, rate) = basic();
    records[3] = entry(
        4,
        1,
        10,
        b"unsupported",
        &residual_legs(),
        Some((4, &rate, Some((1, 1)))),
        None,
        None,
    );
    assert_eq!(
        replay_fixture(&records, Selection::AsOf(0), 5, &book(&[]), &[rate])
            .unwrap_err()
            .predicate,
        "supported_report"
    );
    let wrong_date = rate_fixture(1, 3, 1, 11);
    let mut records = schema();
    records.push(intake(&wrong_date, 3));
    records.push(entry(
        4,
        1,
        10,
        b"wrong-date",
        &pair(3, 1),
        Some((1, &wrong_date, None)),
        None,
        None,
    ));
    assert_eq!(
        replay_fixture(&records, Selection::AsOf(20), 4, &book(&[]), &[wrong_date])
            .unwrap_err()
            .predicate,
        "functional_valuation"
    );
}
fn pack(
    records: &[Record],
    selected: &Selection,
    known_at: u64,
    spec: &[u8],
    rates: &[RateFixture],
    output: &[u8],
) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
    let docs = registries();
    let mut last = None;
    let mut ordinal = 0u32;
    let historical: Vec<_> = records
        .iter()
        .filter(|record| {
            record.envelope.kind == KIND_ENTRY && record.envelope.commit_seq <= known_at
        })
        .map(|record| {
            let mut envelope = record.envelope.clone();
            if last != Some(envelope.commit_seq) {
                last = Some(envelope.commit_seq);
                ordinal = 0;
            }
            envelope.within_commit_ordinal = ordinal;
            ordinal += 1;
            leaf_hash(&envelope.encode())
        })
        .collect();
    let mut cert = Writer::default();
    cert.fixed(FUNCTIONAL_CERTIFICATE_FORMAT)
        .bytes(b"fa-fold-over-prefix")
        .bytes(b"embedded-owner")
        .bytes(OUTPUT_FORMAT)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(known_at)
        .u8(8);
    selection(&mut cert, selected).unwrap();
    cert.fixed(&closure(&docs))
        .fixed(&root_of(&historical))
        .u64(historical.len() as u64)
        .count(8);
    for _ in 0..8 {
        cert.bytes(b"native read witnesses are opaque");
    }
    cert.bytes(output)
        .fixed(&hash_parts(b"fa:report-output:v1", &[output]))
        .u8(0);
    let pin = hash_parts(FUNCTIONAL_CERTIFICATE_FORMAT, &[&cert.buf]);
    cert.fixed(&pin);
    assert!(certificate(&cert.buf).unwrap().functional);
    let all: Vec<_> = records
        .iter()
        .map(|record| record.envelope.encode())
        .collect();
    let checkpoint = Checkpoint {
        book_id: BOOK,
        branch_id: [0; 16],
        through_seq: records
            .iter()
            .map(|record| record.envelope.commit_seq)
            .max()
            .unwrap(),
        leaf_count: all.len() as u64,
        root: root_of(&all.iter().map(|bytes| leaf_hash(bytes)).collect::<Vec<_>>()),
    };
    let mut prefix = Writer::default();
    prefix
        .bytes(PREFIX_FORMAT)
        .fixed(&checkpoint.encode())
        .count(all.len());
    for envelope in &all {
        prefix.bytes(envelope);
    }
    let mut w = Writer::default();
    w.bytes(REPORT_BUNDLE_FORMAT)
        .u16(3)
        .u16(0)
        .bytes(&cert.buf)
        .bytes(b"externally trusted fixture")
        .bytes(&prefix.buf)
        .count(records.len());
    for record in records {
        w.u32(record.len as u32).bytes(&record.bytes);
    }
    w.count(0).count(docs.len());
    for (name, bytes) in docs {
        w.bytes(name.as_bytes()).bytes(&bytes);
    }
    w.bytes(spec).count(rates.len());
    let mut rates: Vec<_> = rates.iter().collect();
    rates.sort_by_key(|rate| rate.oid);
    for rate in rates {
        w.fixed(&rate.oid).bytes(&rate.document);
    }
    let signed = SignedCheckpoint {
        checkpoint,
        state_oid: [0; 32],
        scope_index_root: [0; 32],
        substrate_chain_commitment: [0; 32],
        witness_policy_oid: None,
        time_evidence_oid: None,
        body_digest: [0; 32],
        oid: [0; 32],
        signed_by: Vec::new(),
        not_judged: Vec::new(),
    };
    (w.buf, signed, pin)
}
#[test]
fn v3_complete_bundle_requires_independent_inputs_and_rejects_resealed_output() {
    let (records, rate) = basic();
    let selected = Selection::AsOf(20);
    let spec = book(&[]);
    let (expected, output) =
        replay_fixture(&records, selected.clone(), 5, &spec, &[rate.clone()]).unwrap();
    let (bundle, signed, pin) = pack(&records, &selected, 5, &spec, &[rate.clone()], &output);
    let verify = |bytes: &[u8], pin: Option<&[u8; 32]>| {
        verify_report_with_inputs(bytes, &[], None, None, pin, None, |_, _| Ok(signed.clone()))
    };
    assert_eq!(
        verify(&bundle, None).unwrap_err().predicate,
        "report_input_authority"
    );
    let verified = verify(&bundle, Some(&pin)).unwrap();
    assert_eq!(verified.functional_trial_balance, Some(expected));
    assert_eq!(verified.output, output);
    assert_eq!(
        verify(&bundle, Some(&[99; 32])).unwrap_err().predicate,
        "recipient_certificate"
    );
    let mut changed = output;
    let last = changed.len() - 1;
    changed[last] ^= 1;
    let (forged, _, forged_pin) = pack(&records, &selected, 5, &spec, &[rate], &changed);
    assert_eq!(
        verify(&forged, Some(&forged_pin)).unwrap_err().predicate,
        "report_recomputation"
    );
}
#[test]
fn registry_semantic_changes_refuse_even_under_a_new_matching_closure() {
    let mut docs = registries();
    let bytes = &mut docs[4].1;
    let needle = b"entry_effective_date";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap();
    bytes[offset] = b'X';
    let inputs: Vec<_> = docs
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    assert_eq!(
        registry::verify_functional(&inputs, &closure(&docs))
            .err()
            .unwrap()
            .predicate,
        "registry_closure"
    );
}
