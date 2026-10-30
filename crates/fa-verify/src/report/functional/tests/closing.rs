//! Independent fiscal-close commitments and hand-calculated carrying cohorts.
use super::*;

pub(super) fn chart() -> [(&'static str, u8); 4] {
    [("1000", 1), ("3000", 3), ("4000", 4), ("5000", 5)]
}

fn control(seq: u64, class: u16, day: i32, body: &[u8], key: &[u8]) -> Record {
    let mut w = prefix(class, day);
    w.count(0)
        .u8(1)
        .fixed(body)
        .count(0)
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
    let mut body = Writer::default();
    body.u8(0)
        .bytes(b"cy")
        .bytes(b"FY1970-CLOSE")
        .u8(from)
        .u8(to)
        .u16(1)
        .u8(0);
    let original = control(seq, 16, 364, &body.buf, &seq.to_le_bytes());
    let mut header = prefix(16, 364);
    let len = header.buf.len();
    *header.buf.last_mut().unwrap() = 1;
    header
        .bytes(b"cy")
        .bytes(b"FY1970-CLOSE")
        .fixed(&original.bytes[len..original.len]);
    finish(header, seq)
}

fn route_body() -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"FA-CLOSING-ROUTES").u16(1).i32(0).count(2);
    let mut sources = [id("4000"), id("5000")];
    sources.sort();
    for source in sources {
        w.u128(source).u128(id("3000"));
    }
    w.buf
}

fn routes(seq: u64, key: &[u8]) -> Record {
    let mut body = Writer::default();
    body.u8(1).u16(12).bytes(&route_body());
    control(seq, 17, 0, &body.buf, key)
}

fn declarations() -> Vec<Record> {
    let mut chart_bytes = Writer::default();
    chart_bytes.count(chart().len());
    for (code, kind) in chart() {
        chart_bytes
            .bytes(code.as_bytes())
            .bytes(code.as_bytes())
            .u8(kind)
            .u8(u8::from(matches!(kind, 2..=4)))
            .u8(1)
            .fixed(&(-1i64).to_le_bytes())
            .u8(0);
    }
    let mut periods = Writer::default();
    periods
        .fixed(b"fa:period-creation:v1")
        .bytes(b"cy")
        .i32(1970)
        .count(3);
    for (code, start, end, ordinal, kind) in [
        ("P1", 0, 31, 1, 0),
        ("P2", 31, 59, 2, 0),
        ("FY1970-CLOSE", 364, 365, 3, 3),
    ] {
        periods
            .bytes(code.as_bytes())
            .i32(1970)
            .u16(ordinal)
            .u8(kind)
            .i32(start)
            .i32(end)
            .u8(0);
    }
    vec![
        schema_record(1, 1, &chart_bytes.buf),
        schema_record(2, 13, &periods.buf),
        transition(3, 0, 1),
        routes(4, b"closing-routes"),
    ]
}

/// Hand-encoded complete immutable unit table, independent of registry replay.
fn unit_table_digest() -> [u8; 32] {
    let rows = [
        ("USD", 2, 1, Some(840)),
        ("EUR", 2, 1, Some(978)),
        ("GBP", 2, 1, Some(826)),
        ("JPY", 0, 1, Some(392)),
        ("CHF", 2, 1, Some(756)),
        ("CAD", 2, 1, Some(124)),
        ("AUD", 2, 1, Some(36)),
        ("KWD", 3, 1, Some(414)),
        ("BTC", 8, 2, None),
        ("ETH", 18, 2, None),
        ("SHARE", 6, 3, None),
        ("HOUR", 2, 4, None),
        ("EACH", 0, 5, None),
    ];
    let mut table = Writer::default();
    table.count(rows.len());
    for (id, (code, scale, kind, iso)) in rows.into_iter().enumerate() {
        let mut definition = Writer::default();
        definition
            .fixed(b"FAU\0")
            .u16(1)
            .u16(0)
            .u32(id as u32)
            .bytes(code.as_bytes())
            .u16(0)
            .u8(scale)
            .u8(kind)
            .u8(u8::from(iso.is_some()));
        if let Some(iso) = iso {
            definition.u16(iso);
        }
        definition.u16(3);
        table.bytes(&definition.buf);
    }
    framed_hash(b"fa:unit-table:v1", &[&table.buf])
}

fn source_digest(
    version: u16,
    route: &Record,
    sources: &[(&Record, &[u64])],
    spec: &[u8],
) -> [u8; 32] {
    let mut w = Writer::default();
    w.fixed(&BOOK)
        .i32(1970)
        .i32(0)
        .i32(364)
        .u8(1)
        .u128(handle(route).0)
        .fixed(&framed_hash(
            b"fa:closing-routes:v1",
            &[&BOOK, &route_body()],
        ));
    if version == 2 {
        w.fixed(spec)
            .fixed(&unit_table_digest())
            .fixed(&valuation::law_oid(8));
    }
    let mut codes = ["4000", "5000"];
    codes.sort_by_key(|code| id(code));
    for source in codes {
        for code in [source, "3000"] {
            let (_, kind) = chart().into_iter().find(|(name, _)| *name == code).unwrap();
            w.u128(id(code))
                .bytes(code.as_bytes())
                .bytes(code.as_bytes())
                .u8(kind)
                .u8(u8::from(matches!(kind, 2..=4)))
                .u8(1)
                .u64(1)
                .u8(1)
                .bytes(&[]);
        }
    }
    // Explicit fixture contributions, never supplied by the implementation's
    // source-selection routine. Their order is (publication, actual entry VID).
    for (source, ordinals) in sources {
        for ordinal in *ordinals {
            w.u128(handle(source).0)
                .u64(source.envelope.commit_seq)
                .fixed(&source.envelope.record_digest)
                .u64(*ordinal);
        }
    }
    hash_parts(
        if version == 2 {
            b"fa:year-end-close-source:v2"
        } else {
            b"fa:year-end-close-source:v1"
        },
        &[&w.buf],
    )
}

fn pair_to(debit: &'static str, credit: &'static str, native: i128, base: i128) -> Vec<TestLeg> {
    [(debit, true), (credit, false)]
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

fn carrying_legs() -> Vec<TestLeg> {
    // Reduced fractions are ordered as tuples: (6,5) precedes (11,10).
    let mut legs = pair_to("3000", "4000", 100, 120);
    legs.swap(0, 1);
    legs.extend(pair_to("4000", "3000", 100, 110));
    legs
}

#[allow(clippy::too_many_arguments)]
fn close(
    seq: u64,
    observed: u64,
    version: u16,
    key: &[u8],
    legs: &[TestLeg],
    route: &Record,
    sources: &[(&Record, &[u64])],
    spec: &[u8],
) -> Record {
    let mut basis = Writer::default();
    basis
        .fixed(b"FA-YEAR-CLOSE\0")
        .u16(version)
        .i32(1970)
        .bytes(b"FY1970-CLOSE")
        .i32(364)
        .u64(observed)
        .u128(handle(route).0)
        .fixed(&framed_hash(
            b"fa:closing-routes:v1",
            &[&BOOK, &route_body()],
        ))
        .fixed(&source_digest(version, route, sources, spec));
    let original = entry(seq, 8, 364, key, legs, None, None, None);
    let proposal = &original.bytes[..original.len];
    let mut r = crate::envelope::proposal_after_legs(proposal).unwrap();
    assert!(!r.present("control").unwrap());
    let n = r.count(4096, 36, "totals").unwrap();
    for _ in 0..n {
        r.fixed::<36>("total").unwrap();
    }
    let base_offset = proposal.len() - r.remaining();
    assert!(!r.present("base").unwrap());
    let mut header = prefix(8, 364);
    let header_len = header.buf.len();
    header.buf[2..4].copy_from_slice(&1u16.to_le_bytes());
    *header.buf.last_mut().unwrap() = 1;
    header
        .bytes(b"cy")
        .bytes(b"FY1970-CLOSE")
        .fixed(&proposal[header_len..base_offset]);
    header.u8(u8::from(version == 2));
    if version == 2 {
        let gross = |debit| {
            legs.iter()
                .filter(|leg| leg.debit == debit)
                .map(|leg| leg.base.unwrap())
                .sum::<i128>()
        };
        header
            .u32(0)
            .i128(gross(true))
            .i128(gross(false))
            .fixed(&valuation::law_oid(8))
            .count(0)
            .u8(0);
    }
    header
        .fixed(&proposal[base_offset + 1..])
        .count(1)
        .u16(12)
        .bytes(&basis.buf);
    finish(header, seq)
}

pub(super) fn history() -> (Vec<Record>, Vec<RateFixture>) {
    let spec = book(&[]);
    let rates = vec![rate_fixture(11, 10, 1, 10), rate_fixture(6, 5, 1, 20)];
    let mut records = declarations();
    records.push(intake(&rates[0], 5));
    records.push(entry(
        6,
        1,
        10,
        b"sale",
        &pair_to("1000", "4000", 100, 110),
        Some((1, &rates[0], None)),
        None,
        None,
    ));
    records.push(intake(&rates[1], 7));
    records.push(entry(
        8,
        1,
        20,
        b"return",
        &pair_to("4000", "1000", 100, 120),
        Some((1, &rates[1], None)),
        None,
        None,
    ));
    let closing = close(
        9,
        8,
        2,
        b"carrying-close",
        &carrying_legs(),
        &records[3],
        &[(&records[5], &[1]), (&records[7], &[0])],
        &spec,
    );
    records.push(closing);
    (records, rates)
}

fn replay(
    records: &[Record],
    rates: &[RateFixture],
) -> Result<(VerifiedFunctionalTrialBalance, Vec<u8>), ReportError> {
    replay_fixture(
        records,
        Selection::AsOf(364),
        records
            .iter()
            .map(|record| record.envelope.commit_seq)
            .max()
            .unwrap(),
        &book(&[]),
        rates,
    )
}

fn verify_packed(
    records: &[Record],
    known: u64,
    rates: &[RateFixture],
    output: &[u8],
) -> Result<crate::report::VerifiedReport, ReportError> {
    let (bundle, signed, pin) = pack(
        records,
        &Selection::AsOf(364),
        known,
        &book(&[]),
        rates,
        output,
    );
    verify_report_with_inputs(
        &bundle,
        &[],
        Some(&signed.checkpoint),
        None,
        Some(&pin),
        None,
        |_, _| Ok(signed.clone()),
    )
}

fn net(report: &VerifiedFunctionalTrialBalance, code: &str) -> i128 {
    report
        .cells
        .iter()
        .filter(|cell| cell.account == id(code))
        .map(|cell| cell.debits - cell.credits)
        .sum()
}

fn mutate_basis(record: &Record, mutate: impl FnOnce(&mut [u8])) -> Record {
    let mut raw = record.bytes[..record.len].to_vec();
    let start = raw
        .windows(14)
        .position(|bytes| bytes == b"FA-YEAR-CLOSE\0")
        .unwrap();
    mutate(&mut raw[start..]);
    let mut w = Writer::default();
    w.fixed(&raw);
    finish(w, record.envelope.commit_seq)
}

#[test]
fn carrying_close_preserves_zero_native_nonzero_base_loss_in_complete_bundle() {
    let (records, rates) = history();
    let (report, output) = replay(&records, &rates).unwrap();
    assert_eq!(
        (
            net(&report, "1000"),
            net(&report, "3000"),
            net(&report, "4000")
        ),
        (-10, 10, 0)
    );
    assert_eq!(report.entries, 3);
    let verified = verify_packed(&records, 9, &rates, &output).unwrap();
    assert_eq!(verified.output, output);
    assert_eq!(verified.functional_trial_balance.unwrap(), report);
    assert!(
        replay(&records, &rates[..1]).is_err(),
        "original rates remain necessary even though law8 has none"
    );
}

#[test]
fn repeated_close_and_later_backdate_preserve_historical_observation() {
    let (mut records, rates) = history();
    let (_, old_output) = replay(&records, &rates).unwrap();
    records.push(entry(
        10,
        1,
        10,
        b"later-sale",
        &pair_to("1000", "4000", 50, 55),
        Some((1, &rates[0], None)),
        None,
        None,
    ));
    let second = close(
        11,
        10,
        2,
        b"second-close",
        &pair_to("4000", "3000", 50, 55),
        &records[3],
        &[
            (&records[5], &[1]),
            (&records[7], &[0]),
            (&records[8], &[0, 2]),
            (&records[9], &[1]),
        ],
        &book(&[]),
    );
    records.push(second);
    let (report, output) = replay(&records, &rates).unwrap();
    assert_eq!(
        (
            net(&report, "1000"),
            net(&report, "3000"),
            net(&report, "4000")
        ),
        (45, -45, 0)
    );
    assert_eq!(
        verify_packed(&records, 11, &rates, &output).unwrap().output,
        output
    );
    assert_eq!(
        verify_packed(&records, 9, &rates, &old_output)
            .unwrap()
            .output,
        old_output
    );
}

#[test]
fn resealed_forged_source_route_observation_and_balanced_amounts_are_refused() {
    let (records, rates) = history();
    let (_, output) = replay(&records, &rates).unwrap();
    // Fiscal year, closing date, observation, route VID/digest and source digest.
    for offset in [16usize, 36, 40, 48, 64, 96] {
        let mut bad = records.clone();
        bad[8] = mutate_basis(&records[8], |raw| raw[offset] ^= 1);
        assert!(
            verify_packed(&bad, 9, &rates, &output).is_err(),
            "basis byte {offset}"
        );
    }
    let mut wrong = carrying_legs();
    wrong[0].base = Some(121);
    wrong[1].base = Some(121);
    let mut bad = records.clone();
    bad[8] = close(
        9,
        8,
        2,
        b"false-balanced-close",
        &wrong,
        &records[3],
        &[(&records[5], &[1]), (&records[7], &[0])],
        &book(&[]),
    );
    assert_eq!(
        verify_packed(&bad, 9, &rates, &output)
            .unwrap_err()
            .predicate,
        "functional_closing"
    );
    // The close is outside the selected activity, but its source law still matters.
    assert_eq!(
        replay_fixture(
            &bad,
            Selection::Activity(vec!["P1".into()]),
            9,
            &book(&[]),
            &rates
        )
        .unwrap_err()
        .predicate,
        "functional_closing"
    );
    bad[8] = mutate_basis(&records[8], |raw| {
        raw[14..16].copy_from_slice(&3u16.to_le_bytes())
    });
    assert_eq!(
        replay(&bad, &rates).unwrap_err().predicate,
        "supported_report"
    );
}

#[test]
fn carrying_source_binds_complete_book_parameters_and_immutable_unit_definitions() {
    let (records, rates) = history();
    let (_, output) = replay(&records, &rates).unwrap();
    let mut spec = book(&[]);
    let name = b"Functional fixture";
    let start = spec
        .windows(name.len())
        .position(|value| value == name)
        .unwrap();
    spec[start] = b'N';
    let (bundle, signed, pin) = pack(&records, &Selection::AsOf(364), 9, &spec, &rates, &output);
    assert_eq!(
        verify_report_with_inputs(
            &bundle,
            &[],
            Some(&signed.checkpoint),
            None,
            Some(&pin),
            None,
            |_, _| Ok(signed.clone())
        )
        .unwrap_err()
        .predicate,
        "functional_closing"
    );

    let mut docs = registries();
    let unit_document = &mut docs.iter_mut().find(|(name, _)| name == "units").unwrap().1;
    let key = b"rounding_default";
    let value = unit_document
        .windows(key.len())
        .position(|bytes| bytes == key)
        .unwrap()
        + key.len();
    assert_eq!(unit_document[value], 2, "canonical integer value tag");
    assert_eq!(&unit_document[value + 1..value + 17], &3i128.to_le_bytes());
    unit_document[value + 1..value + 17].copy_from_slice(&4i128.to_le_bytes());
    let (bundle, signed, pin) = pack_with_registries(
        &records,
        &Selection::AsOf(364),
        9,
        &book(&[]),
        &rates,
        &output,
        &docs,
    );
    assert_eq!(
        verify_report_with_inputs(
            &bundle,
            &[],
            Some(&signed.checkpoint),
            None,
            Some(&pin),
            None,
            |_, _| Ok(signed.clone())
        )
        .unwrap_err()
        .predicate,
        "functional_closing",
        "matching identifiers and scales cannot substitute a changed immutable unit table"
    );
}

#[test]
fn close_revalidates_intervening_source_period_and_route_effects() {
    let (records, rates) = history();
    let mut closed_account = Writer::default();
    closed_account.bytes(b"4000").i32(364);
    for intervening in [
        entry(
            9,
            1,
            10,
            b"intervening-sale",
            &pair_to("1000", "4000", 50, 55),
            Some((1, &rates[0], None)),
            None,
            None,
        ),
        transition(9, 1, 2),
        routes(9, b"new-map"),
        schema_record(9, 3, &closed_account.buf),
    ] {
        let mut bad = records[..8].to_vec();
        bad.push(intervening);
        bad.push(close(
            10,
            8,
            2,
            b"stale-close",
            &carrying_legs(),
            &records[3],
            &[(&records[5], &[1]), (&records[7], &[0])],
            &book(&[]),
        ));
        assert_eq!(
            replay(&bad, &rates).unwrap_err().predicate,
            "functional_closing"
        );
    }
}

fn promotion(seq: u64, to: u8) -> Record {
    let draft = 123u128;
    let key = framed_hash(
        b"fa:draft-record-key:v1",
        &[&[2], &draft.to_le_bytes(), &[]],
    );
    let mut w = prefix(25, 364);
    w.buf[2..4].copy_from_slice(&1u16.to_le_bytes());
    w.count(0)
        .u8(1)
        .u8(3)
        .u128(draft)
        .u8(1)
        .u8(to)
        .count(1)
        .u8(0)
        .u128(456)
        .u16(0)
        .count(0)
        .u8(0)
        .bytes(&key)
        .u8(3)
        .u16(11)
        .fixed(&[7; 32])
        .u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(0)
        .u8(0)
        .count(0)
        .count(0)
        .count(0);
    finish(w, seq)
}

#[test]
fn singleton_draft_promotion_is_allowed_but_source_changing_siblings_are_refused() {
    let (records, rates) = history();
    let (_, output) = replay(&records, &rates).unwrap();
    let mut good = records.clone();
    good.push(promotion(9, 2));
    good[9].envelope.within_commit_ordinal = 1;
    assert_eq!(
        verify_packed(&good, 9, &rates, &output).unwrap().output,
        output
    );
    for sibling in [
        entry(
            9,
            1,
            10,
            b"sibling-sale",
            &pair_to("1000", "4000", 50, 55),
            Some((1, &rates[0], None)),
            None,
            None,
        ),
        routes(9, b"sibling-map"),
        transition(9, 1, 2),
        promotion(9, 3),
    ] {
        let mut bad = records.clone();
        bad.push(sibling);
        bad[9].envelope.within_commit_ordinal = 1;
        assert_eq!(
            verify_packed(&bad, 9, &rates, &output)
                .unwrap_err()
                .predicate,
            "functional_closing"
        );
    }
}

fn native_pair(debit: &'static str, credit: &'static str, amount: i128) -> Vec<TestLeg> {
    pair_to(debit, credit, amount, amount)
        .into_iter()
        .map(|mut leg| {
            leg.unit = 0;
            leg.base = None;
            leg
        })
        .collect()
}

#[test]
fn prior_native_close_must_reproduce_before_it_can_feed_a_carrying_close() {
    let mut records = declarations();
    records.push(entry(
        5,
        1,
        10,
        b"native-sale",
        &native_pair("1000", "4000", 42),
        None,
        None,
        None,
    ));
    let old = close(
        6,
        5,
        1,
        b"native-close",
        &native_pair("4000", "3000", 42),
        &records[3],
        &[(&records[4], &[1])],
        &book(&[]),
    );
    records.push(old);
    let rate = rate_fixture(11, 10, 1, 10);
    records.push(intake(&rate, 7));
    records.push(entry(
        8,
        1,
        10,
        b"foreign-sale",
        &pair_to("1000", "4000", 100, 110),
        Some((1, &rate, None)),
        None,
        None,
    ));
    let latest = close(
        9,
        8,
        2,
        b"carrying-close",
        &pair_to("4000", "3000", 100, 110),
        &records[3],
        &[
            (&records[4], &[1]),
            (&records[5], &[0]),
            (&records[7], &[1]),
        ],
        &book(&[]),
    );
    records.push(latest);
    let rates = [rate];
    let (report, output) = replay(&records, &rates).unwrap();
    assert_eq!(
        (
            net(&report, "1000"),
            net(&report, "3000"),
            net(&report, "4000")
        ),
        (152, -152, 0)
    );
    verify_packed(&records, 9, &rates, &output).unwrap();
    records[5] = close(
        6,
        5,
        1,
        b"native-close",
        &native_pair("4000", "3000", 41),
        &records[3],
        &[(&records[4], &[1])],
        &book(&[]),
    );
    let mut forged = native_pair("4000", "3000", 1);
    for leg in &mut forged {
        leg.base = Some(leg.native);
    }
    forged.extend(pair_to("4000", "3000", 100, 110));
    records[8] = close(
        9,
        8,
        2,
        b"carrying-close",
        &forged,
        &records[3],
        &[
            (&records[4], &[1]),
            (&records[5], &[0]),
            (&records[7], &[1]),
        ],
        &book(&[]),
    );
    assert_eq!(
        verify_packed(&records, 9, &rates, &output)
            .unwrap_err()
            .predicate,
        "functional_closing",
        "recomputing the later commitment cannot launder a false earlier close"
    );
}

#[test]
fn migrated_nominal_sources_require_activation_before_the_close_observation() {
    let body = migration::body(0, false);
    let run = migration::run();
    let rate = rate_fixture(11, 10, 1, 10);
    let mut records = declarations();
    records.push(migration::control(5, 0, run, &body));
    records.push(intake(&rate, 6));
    records.push(entry_with_migration(
        7,
        12,
        10,
        b"migrated-sale",
        &pair_to("1000", "4000", 100, 110),
        Some((1, &rate, None)),
        None,
        None,
        Some(run),
    ));
    records.push(migration::control(8, 1, run, &body));
    records.push(close(
        9,
        8,
        2,
        b"migrated-close",
        &pair_to("4000", "3000", 100, 110),
        &records[3],
        &[(&records[6], &[1])],
        &book(&[]),
    ));
    let rates = [rate];
    let bodies = [(4, body.as_slice())];
    let (report, output) = replay_migration_fixture(
        &records,
        Selection::AsOf(364),
        9,
        &book(&[]),
        &rates,
        &bodies,
    )
    .unwrap();
    assert_eq!(
        (
            net(&report, "1000"),
            net(&report, "3000"),
            net(&report, "4000")
        ),
        (110, -110, 0)
    );
    let mut selector = Writer::default();
    selector.u8(8).u8(1).i32(364);
    let (bundle, signed, pin) = pack_profile_with_migrations(
        &records,
        9,
        &book(&[]),
        &rates,
        &output,
        CertificateProfile {
            format: FUNCTIONAL_CERTIFICATE_FORMAT,
            output_format: OUTPUT_FORMAT,
            selector: &selector.buf,
        },
        &registries(),
        &bodies,
    );
    assert_eq!(
        verify_report_with_inputs(
            &bundle,
            &[],
            Some(&signed.checkpoint),
            None,
            Some(&pin),
            None,
            |_, _| Ok(signed.clone())
        )
        .unwrap()
        .output,
        output
    );
    for terminal in [
        migration::control(8, 2, run, &body),
        migration::control(9, 1, run, &body),
        migration::control(10, 1, run, &body),
    ] {
        let mut bad = records.clone();
        bad[7] = terminal;
        bad.sort_by_key(|record| record.envelope.commit_seq);
        assert!(
            replay_migration_fixture(&bad, Selection::AsOf(364), 10, &book(&[]), &rates, &bodies)
                .is_err(),
            "abandoned, co-published and later activation cannot support the saved observation"
        );
    }
    let mut stale = records.clone();
    stale[8] = close(
        9,
        7,
        2,
        b"preactivation-review",
        &pair_to("4000", "3000", 100, 110),
        &records[3],
        &[(&records[6], &[1])],
        &book(&[]),
    );
    assert_eq!(
        replay_migration_fixture(&stale, Selection::AsOf(364), 9, &book(&[]), &rates, &bodies)
            .unwrap_err()
            .predicate,
        "functional_closing"
    );
}
