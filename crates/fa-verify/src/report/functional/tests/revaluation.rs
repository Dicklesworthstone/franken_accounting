//! Independently encoded source commitments and hand-calculated adjustments.
use super::*;

pub(super) fn chart() -> [(&'static str, u8, u32); 4] {
    [
        ("1000", 1, 1),
        ("1290", 1, 0),
        ("3000", 3, 1),
        ("4700", 4, 0),
    ]
}

fn control(seq: u64, tag: u8, kind: u16, body: &[u8], key: &[u8]) -> Record {
    let mut w = prefix(if tag == 1 { 17 } else { 16 }, 0);
    w.count(0).u8(1).u8(tag);
    if tag == 1 {
        w.u16(kind).bytes(body);
    } else {
        w.fixed(body);
    }
    w.count(0)
        .u8(0)
        .bytes(key)
        .u8(3)
        .u16(1)
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

fn transition(seq: u64, from: u8, to: u8) -> Record {
    transition_header(seq, from, to, if from == 0 { 0 } else { 30 }, b"cy", b"P1")
}

fn transition_header(
    seq: u64,
    from: u8,
    to: u8,
    day: i32,
    calendar: &[u8],
    period: &[u8],
) -> Record {
    let mut body = Writer::default();
    body.bytes(b"cy").bytes(b"P1").u8(from).u8(to).u16(1).u8(0);
    let original = control(seq, 0, 0, &body.buf, &seq.to_le_bytes());
    let mut header = prefix(16, day);
    let header_len = header.buf.len();
    *header.buf.last_mut().unwrap() = 1;
    header
        .bytes(calendar)
        .bytes(period)
        .fixed(&original.bytes[header_len..original.len]);
    finish(header, seq)
}

fn route_body() -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"FA-FX-ROUTES\0")
        .u16(1)
        .i32(0)
        .u32(0)
        .count(1)
        .u128(id("1000"))
        .u128(id("1290"))
        .u128(id("4700"));
    w.buf
}

fn declarations() -> Vec<Record> {
    let mut records = schema();
    let mut body = Writer::default();
    body.count(chart().len());
    for (code, kind, unit) in chart() {
        body.bytes(code.as_bytes())
            .bytes(code.as_bytes())
            .u8(kind)
            .u8(u8::from(matches!(kind, 2..=4)))
            .u8(1)
            .fixed(&i64::from(unit).to_le_bytes())
            .u8(0);
    }
    records[0] = schema_record(1, 1, &body.buf);
    records.push(transition(3, 0, 1));
    records.push(control(4, 1, 14, &route_body(), b"fx-routes"));
    records
}

fn close_rate(numerator: u128, denominator: u128) -> RateFixture {
    let mut rate = rate_fixture(numerator, denominator, 2, 30);
    // MIME is retained in DocumentRecord but not the content commitment.
    let old = b"application/vnd.fa.fx-rate";
    let start = rate
        .document
        .windows(old.len())
        .position(|w| w == old)
        .unwrap();
    let mut document = Writer::default();
    document
        .fixed(&rate.document[..start - 4])
        .bytes(b"application/vnd.franken.fx-rate.v1")
        .fixed(&rate.document[start + old.len()..]);
    rate.document = document.buf;
    rate
}

fn source_digest(route: &Record, rate: &RateFixture, sources: &[&Record]) -> [u8; 32] {
    let mut w = Writer::default();
    w.fixed(&BOOK)
        .bytes(b"cy")
        .bytes(b"P1")
        .i32(0)
        .i32(31)
        .u8(1)
        .u128(id("1000"))
        .u8(0)
        .u32(1)
        .u32(0)
        .u128(handle(route).0)
        .fixed(&framed_hash(
            b"fa:fx-revaluation-routes:v1",
            &[&BOOK, &route_body()],
        ))
        .fixed(&rate.oid)
        .fixed(&rate.commitment);
    for code in ["1000", "1290", "4700"] {
        let (_, kind, unit) = chart()
            .into_iter()
            .find(|(name, _, _)| *name == code)
            .unwrap();
        w.u128(id(code))
            .bytes(code.as_bytes())
            .bytes(code.as_bytes())
            .u8(kind)
            .u8(u8::from(matches!(kind, 2..=4)))
            .u8(1)
            .u64(1)
            .u8(0)
            .u32(unit)
            .bytes(&[]);
    }
    // Every supplied source has its sole selected contribution at ordinal0.
    // This explicit list is the hostile fixture's assertion, never obtained
    // from the verifier's source-selection or revaluation implementation.
    for record in sources {
        w.u64(record.envelope.commit_seq)
            .u128(handle(record).0)
            .fixed(&record.envelope.record_digest)
            .u64(0);
    }
    hash_parts(b"fa:fx-revaluation-source:v1", &[&w.buf])
}

fn adjustment(
    seq: u64,
    observed: u64,
    key: &[u8],
    delta: i128,
    route: &Record,
    rate: &RateFixture,
    sources: &[&Record],
) -> Record {
    let mut basis = Writer::default();
    basis
        .fixed(b"FA-FX-REVALUE\0")
        .u16(1)
        .bytes(b"P1")
        .i32(30)
        .u64(observed)
        .u128(id("1000"))
        .u8(0)
        .u128(handle(route).0)
        .fixed(&framed_hash(
            b"fa:fx-revaluation-routes:v1",
            &[&BOOK, &route_body()],
        ))
        .fixed(&rate.oid)
        .fixed(&rate.commitment)
        .fixed(&source_digest(route, rate, sources));
    let legs: Vec<_> = ["1290", "4700"]
        .into_iter()
        .enumerate()
        .map(|(ordinal, code)| TestLeg {
            code,
            debit: (ordinal == 0) == (delta > 0),
            unit: 0,
            native: delta.abs(),
            base: Some(delta.abs()),
            entity: None,
        })
        .collect();
    let original = entry(seq, 10, 30, key, &legs, Some((2, rate, None)), None, None);
    let mut header = prefix(10, 30);
    let header_len = header.buf.len();
    header.buf[2..4].copy_from_slice(&1u16.to_le_bytes());
    *header.buf.last_mut().unwrap() = 1;
    header
        .bytes(b"cy")
        .bytes(b"P1")
        .fixed(&original.bytes[header_len..original.len])
        .count(1)
        .u16(16)
        .bytes(&basis.buf);
    finish(header, seq)
}

pub(super) fn history() -> (Vec<Record>, Vec<RateFixture>) {
    let spot = rate_fixture(11, 10, 1, 10);
    let close = close_rate(6, 5);
    let mut records = declarations();
    let source = entry(
        6,
        1,
        10,
        b"capital",
        &pair(100, 110),
        Some((1, &spot, None)),
        None,
        None,
    );
    let revaluation = adjustment(8, 7, b"first-close", 10, &records[3], &close, &[&source]);
    records.extend([intake(&spot, 5), source, intake(&close, 7), revaluation]);
    (records, vec![spot, close])
}

fn replay(
    records: &[Record],
    rates: &[RateFixture],
) -> Result<(VerifiedFunctionalTrialBalance, Vec<u8>), ReportError> {
    replay_fixture(
        records,
        Selection::AsOf(30),
        records.last().unwrap().envelope.commit_seq,
        &book(&[]),
        rates,
    )
}

fn net(report: &VerifiedFunctionalTrialBalance, code: &str) -> i128 {
    let row = report
        .cells
        .iter()
        .find(|row| row.account == id(code))
        .unwrap();
    row.debits - row.credits
}

fn mutate_basis(record: &Record, mutate: impl FnOnce(&mut Vec<u8>)) -> Record {
    let info = metadata::entry_info(&record.bytes[..record.len], &record.envelope).unwrap();
    let raw = info.fx_revaluation_basis.unwrap();
    let mut changed = raw.to_vec();
    mutate(&mut changed);
    let mut w = Writer::default();
    w.fixed(&record.bytes[..record.len - raw.len() - 4])
        .bytes(&changed);
    finish(w, record.envelope.commit_seq)
}

#[test]
fn aggregate_revaluation_reprices_the_exposure_and_only_the_repeated_delta_offline() {
    let (mut records, mut rates) = history();
    let (report, _) = replay(&records, &rates).unwrap();
    assert_eq!(
        (
            net(&report, "1000"),
            net(&report, "1290"),
            net(&report, "3000"),
            net(&report, "4700")
        ),
        (110, 10, -110, -10)
    );
    let second = close_rate(13, 10);
    let next = adjustment(
        10,
        9,
        b"second-close",
        10,
        &records[3],
        &second,
        &[&records[5], &records[7]],
    );
    records.extend([intake(&second, 9), next]);
    rates.push(second);
    let (report, output) = replay(&records, &rates).unwrap();
    assert_eq!(
        (
            net(&report, "1000"),
            net(&report, "1290"),
            net(&report, "4700")
        ),
        (110, 20, -20)
    );
    let verified = migration::verify_packed(&records, 10, &rates, &output, &[]).unwrap();
    assert_eq!(verified.output, output);
    assert_eq!(verified.functional_trial_balance.unwrap(), report);
    let (old, _) =
        replay_fixture(&records, Selection::AsOf(30), 8, &book(&[]), &rates[..2]).unwrap();
    assert_eq!(
        net(&old, "1290"),
        10,
        "later quotes and adjustments do not alter historical proof"
    );
}

#[test]
fn revaluation_refuses_forged_basis_balanced_wrong_delta_and_unsupported_allocations() {
    let (records, rates) = history();
    for offset in [30usize, 38, 55, 71, 103, 135, 167] {
        let mut bad = records.clone();
        bad[7] = mutate_basis(&records[7], |raw| raw[offset] ^= 1);
        assert!(replay(&bad, &rates).is_err(), "basis byte {offset}");
    }
    let mut bad = records.clone();
    bad[7] = adjustment(
        8,
        7,
        b"wrong-delta",
        20,
        &records[3],
        &rates[1],
        &[&records[5]],
    );
    assert_eq!(
        replay(&bad, &rates).unwrap_err().predicate,
        "functional_revaluation"
    );
    bad[7] = mutate_basis(&records[7], |raw| {
        raw[14..16].copy_from_slice(&2u16.to_le_bytes())
    });
    assert_eq!(
        replay(&bad, &rates).unwrap_err().predicate,
        "supported_report"
    );
    assert!(
        replay(&records, &rates[..1]).is_err(),
        "closing evidence cannot be omitted"
    );
    let mut no_receipt = records.clone();
    no_receipt[6] = intake(&rates[1], 9);
    assert!(
        replay(&no_receipt, &rates).is_err(),
        "a later receipt cannot authorize the original source observation"
    );
}

#[test]
fn revaluation_revalidates_the_whole_source_and_control_basis_before_publication() {
    let (records, rates) = history();
    for malformed in [
        transition_header(3, 0, 1, 1, b"cy", b"P1"),
        transition_header(3, 0, 1, 0, b"other", b"P1"),
        transition_header(3, 0, 1, 0, b"cy", b"P2"),
    ] {
        let mut bad = records.clone();
        bad[2] = malformed;
        assert_eq!(
            replay(&bad, &rates).unwrap_err().predicate,
            "functional_revaluation",
            "an invalid period transition cannot establish an open source period",
        );
    }
    let extra = entry(
        8,
        1,
        10,
        b"backdated",
        &pair(100, 110),
        Some((1, &rates[0], None)),
        None,
        None,
    );
    for intervening in [extra, transition(8, 1, 2)] {
        let mut bad = records[..7].to_vec();
        bad.push(intervening);
        bad.push(adjustment(
            9,
            7,
            b"stale-review",
            10,
            &records[3],
            &rates[1],
            &[&records[5]],
        ));
        assert_eq!(
            replay(&bad, &rates).unwrap_err().predicate,
            "functional_revaluation"
        );
    }
    let mut bad = records.clone();
    bad.push(adjustment(
        8,
        7,
        b"duplicate-source",
        10,
        &records[3],
        &rates[1],
        &[&records[5]],
    ));
    assert_eq!(
        replay(&bad, &rates).unwrap_err().predicate,
        "functional_revaluation"
    );
    let mut closed = records[..7].to_vec();
    let mut close = Writer::default();
    close.bytes(b"1000").i32(30);
    closed.push(control(8, 1, 3, &close.buf, b"close-source"));
    closed.push(adjustment(
        9,
        7,
        b"closed-source",
        10,
        &records[3],
        &rates[1],
        &[&records[5]],
    ));
    assert_eq!(
        replay(&closed, &rates).unwrap_err().predicate,
        "functional_revaluation"
    );
    for sibling in [
        entry(
            8,
            1,
            10,
            b"same-publication-source",
            &pair(100, 110),
            Some((1, &rates[0], None)),
            None,
            None,
        ),
        transition(8, 1, 2),
    ] {
        let mut co_published = records.clone();
        co_published.push(sibling);
        assert_eq!(
            replay(&co_published, &rates).unwrap_err().predicate,
            "functional_revaluation",
            "the same publication cannot conceal an unobserved source or period effect"
        );
    }
}

#[test]
fn revaluation_checks_hidden_periods_and_exact_inherited_reversals() {
    let (mut records, rates) = history();
    let mut poisoned = records.clone();
    poisoned[7] = adjustment(
        8,
        7,
        b"hidden-wrong",
        20,
        &records[3],
        &rates[1],
        &[&records[5]],
    );
    assert!(
        replay_fixture(
            &poisoned,
            Selection::Activity(vec!["P2".into()]),
            8,
            &book(&[]),
            &rates
        )
        .is_err()
    );
    let undo_legs = [
        TestLeg {
            code: "1290",
            debit: false,
            unit: 0,
            native: 10,
            base: Some(10),
            entity: None,
        },
        TestLeg {
            code: "4700",
            debit: true,
            unit: 0,
            native: 10,
            base: Some(10),
            entity: None,
        },
    ];
    let undo = entry(
        9,
        4,
        30,
        b"undo",
        &undo_legs,
        Some((2, &rates[1], None)),
        Some(&records[7]),
        None,
    );
    records.push(undo);
    let (report, _) = replay(&records, &rates).unwrap();
    assert_eq!((net(&report, "1290"), net(&report, "4700")), (0, 0));
    let mut forged = undo_legs;
    forged[0].native = 11;
    forged[0].base = Some(11);
    forged[1].native = 11;
    forged[1].base = Some(11);
    records[8] = entry(
        9,
        4,
        30,
        b"forged-undo",
        &forged,
        Some((2, &rates[1], None)),
        Some(&records[7]),
        None,
    );
    assert!(replay(&records, &rates).is_err());
}

#[test]
fn revaluation_includes_migrated_exposure_only_after_authenticated_finalization() {
    let spot = rate_fixture(11, 10, 1, 10);
    let close = close_rate(6, 5);
    let body = migration::body(0, false);
    let mut records = declarations();
    let source = entry_with_migration(
        7,
        12,
        10,
        b"migrated-cash",
        &pair(100, 110),
        Some((1, &spot, None)),
        None,
        None,
        Some(migration::run()),
    );
    let adjustment = adjustment(
        10,
        9,
        b"migrated-close",
        10,
        &records[3],
        &close,
        &[&source],
    );
    records.extend([
        intake(&spot, 5),
        migration::control(6, 0, migration::run(), &body),
        source,
        migration::control(8, 1, migration::run(), &body),
        intake(&close, 9),
        adjustment,
    ]);
    let rates = [spot, close];
    let bodies = [(5, body.as_slice())];
    let (report, output) = replay_migration_fixture(
        &records,
        Selection::AsOf(30),
        10,
        &book(&[]),
        &rates,
        &bodies,
    )
    .unwrap();
    assert_eq!((net(&report, "1000"), net(&report, "1290")), (110, 10));
    assert!(migration::verify_packed(&records, 10, &rates, &output, &bodies).is_ok());
    for (seq, kind) in [(8, 2), (10, 1), (11, 1)] {
        let mut bad = records.clone();
        bad[7] = migration::control(seq, kind, migration::run(), &body);
        assert!(
            replay_migration_fixture(&bad, Selection::AsOf(30), 11, &book(&[]), &rates, &bodies)
                .is_err()
        );
    }
}

#[test]
fn cumulative_revaluation_half_even_rounds_both_exposure_signs_exactly() {
    for numerator in [3, 5] {
        for positive in [false, true] {
            let spot = rate_fixture(1, 1, 1, 10);
            let close = close_rate(numerator, 2);
            let mut records = declarations();
            let mut legs = pair(1, 1);
            if !positive {
                for leg in &mut legs {
                    leg.debit = !leg.debit;
                }
            }
            let source = entry(
                6,
                1,
                10,
                b"one-unit",
                &legs,
                Some((1, &spot, None)),
                None,
                None,
            );
            // Both 1.5 and 2.5 round to the even integer 2; the signed
            // exposure carries 1 before close and its adjustment is ±1.
            let delta = if positive { 1 } else { -1 };
            let close_entry = adjustment(
                8,
                7,
                b"half-even-close",
                delta,
                &records[3],
                &close,
                &[&source],
            );
            records.extend([intake(&spot, 5), source, intake(&close, 7), close_entry]);
            let (report, _) = replay(&records, &[spot, close]).unwrap();
            assert_eq!(net(&report, "1000"), delta);
            assert_eq!(net(&report, "1290"), delta);
        }
    }
}
