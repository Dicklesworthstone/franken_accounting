//! Hand-calculated lead schedules and an independent wire encoder. These
//! fixtures authenticate the entire source prefix, including omitted dates,
//! pending reservations, reversals and migration controls.
#[path = "cash_flow.rs"]
mod cash_flow;

use super::*;
use crate::report::{
    RollForwardAccount, RollForwardBucket, RollForwardMovement, RollForwardRow, VerifiedRollForward,
};

fn seal(mut bytes: Vec<u8>, seq: u64) -> Record {
    let len = bytes.len();
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&bytes]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    bytes.extend_from_slice(&proposal);
    bytes.extend_from_slice(&digest);
    let envelope = envelope_of_entry(&bytes, len, seq, 0).unwrap();
    Record {
        bytes,
        len,
        envelope,
    }
}

fn dated((record, id): (Record, u128), day: i32) -> (Record, u128) {
    let mut bytes = record.bytes[..record.len].to_vec();
    bytes[38..42].copy_from_slice(&day.to_le_bytes());
    (seal(bytes, record.envelope.commit_seq), id)
}

fn attributed(record: Record, rule: Option<[u8; 32]>, reasons: &[u16]) -> Record {
    // Only the known fixture's origin and empty supersession list are replaced.
    // The expected classification below never calls the metadata decoder.
    let raw = &record.bytes[..record.len];
    let mut r = crate::envelope::proposal_after_legs(raw).unwrap();
    assert!(!r.present("control").unwrap());
    assert_eq!(r.u32("unit totals").unwrap(), 0);
    assert!(!r.present("base totals").unwrap());
    r.bytes(1024, "key").unwrap();
    let start = raw.len() - r.remaining();
    r.fixed::<35>("native origin").unwrap();
    assert_eq!(r.u128("principal").unwrap(), PRINCIPAL);
    assert!(!r.present("session").unwrap());
    assert_eq!(r.u32("evidence").unwrap(), 0);
    assert_eq!(r.u32("supersession").unwrap(), 0);
    let tail = &raw[raw.len() - r.remaining()..];
    let mut w = Writer::default();
    w.fixed(&raw[..start]);
    if let Some(rule) = rule {
        w.u8(1).fixed(&rule).fixed(&[8; 16]).fixed(&[9; 32]);
    } else {
        w.u8(0).fixed(&[0; 32]).u16(1);
    }
    w.u128(PRINCIPAL).u8(0).count(0).count(reasons.len());
    for (i, reason) in reasons.iter().enumerate() {
        w.u128(100 + i as u128).fixed(&[6; 32]).u8(6).u16(*reason);
    }
    w.fixed(tail);
    seal(w.buf, record.envelope.commit_seq)
}

fn classification(class: u16, reason: &str, rule: Option<[u8; 32]>) -> RollForwardBucket {
    RollForwardBucket {
        class,
        reason_code: reason.into(),
        rule_digest: rule,
    }
}

fn schedule(
    known_at: u64,
    from: i32,
    through: i32,
    codes: &[&str],
    units: &[u32],
) -> VerifiedRollForward {
    let accounts: Vec<_> = codes
        .iter()
        .map(|code| {
            let account = displayed(code);
            RollForwardAccount {
                id: account.account,
                code: account.code,
                name: account.name,
                account_type: account.account_type,
                is_leaf: true,
            }
        })
        .collect();
    let rows = accounts
        .iter()
        .flat_map(|account| {
            units.iter().map(|&unit_id| RollForwardRow {
                account_id: account.id,
                unit_id,
                opening: 0,
                activity: Vec::new(),
                net_change: 0,
                closing: 0,
            })
        })
        .collect();
    VerifiedRollForward {
        book_id: BOOK,
        known_at,
        label: "Native lead schedule".into(),
        effective_from: from,
        effective_through: through,
        source_certificate_digest: [0; 32],
        accounts,
        units: units.to_vec(),
        buckets: Vec::new(),
        rows,
        movements: Vec::new(),
    }
}

fn movement(
    record: &Record,
    ordinal: u32,
    code: &str,
    debit: bool,
    amount: i128,
    bucket: &RollForwardBucket,
) -> RollForwardMovement {
    RollForwardMovement {
        entry_digest: record.envelope.record_digest,
        leg_index: ordinal,
        recorded_seq: record.envelope.commit_seq,
        effective_day: record.envelope.effective_day.unwrap(),
        account_id: account_id(code),
        unit_id: 1,
        bucket: bucket.clone(),
        debits: if debit { amount } else { 0 },
        credits: if debit { 0 } else { amount },
    }
}

fn stock(debits: i128, credits: i128) -> Vec<ReportRow> {
    let mut result = rows(debits, 0);
    result[0].credits = credits;
    result[1].debits = credits;
    result
}

fn expected_bytes(report: &VerifiedRollForward) -> Vec<u8> {
    // Encode the published native format independently of roll_forward::encode.
    fn bucket(w: &mut Writer, value: &RollForwardBucket) {
        w.u16(value.class)
            .bytes(value.reason_code.as_bytes())
            .u8(u8::from(value.rule_digest.is_some()));
        if let Some(rule) = value.rule_digest {
            w.fixed(&rule);
        }
    }
    let mut w = Writer::default();
    w.fixed(b"FA-ROLL-FORWARD\0")
        .u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(report.known_at)
        .bytes(report.label.as_bytes())
        .i32(report.effective_from)
        .i32(report.effective_through)
        .count(report.accounts.len());
    for account in &report.accounts {
        w.u128(account.id)
            .bytes(account.code.as_bytes())
            .bytes(account.name.as_bytes())
            .u8(account.account_type)
            .u8(u8::from(account.is_leaf));
    }
    w.count(report.units.len());
    for unit in &report.units {
        w.u32(*unit);
    }
    w.count(report.buckets.len());
    for value in &report.buckets {
        bucket(&mut w, value);
    }
    w.count(report.rows.len());
    for row in &report.rows {
        w.u128(row.account_id)
            .u32(row.unit_id)
            .i128(row.opening)
            .count(row.activity.len());
        for amount in &row.activity {
            w.i128(*amount);
        }
        w.i128(row.net_change).i128(row.closing);
    }
    w.count(report.movements.len());
    for entry in &report.movements {
        w.fixed(&entry.entry_digest)
            .u32(entry.leg_index)
            .u64(entry.recorded_seq)
            .i32(entry.effective_day)
            .u128(entry.account_id)
            .u32(entry.unit_id);
        bucket(&mut w, &entry.bucket);
        w.i128(entry.debits).i128(entry.credits);
    }
    w.buf
}

fn source_bundle(
    records: &[Record],
    known_at: u64,
    through: i32,
    expected_rows: &[ReportRow],
    bodies: &[(u64, Vec<u8>)],
) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
    let mut last_seq = None;
    let mut ordinal = 0;
    let envelopes: Vec<_> = records
        .iter()
        .map(|record| {
            if last_seq != Some(record.envelope.commit_seq) {
                ordinal = 0;
                last_seq = Some(record.envelope.commit_seq);
            }
            let mut envelope = record.envelope.clone();
            envelope.within_commit_ordinal = ordinal;
            ordinal += 1;
            envelope
        })
        .collect();
    let hashes: Vec<_> = envelopes.iter().map(|e| leaf_hash(&e.encode())).collect();
    let checkpoint = Checkpoint {
        book_id: BOOK,
        branch_id: [0; 16],
        through_seq: envelopes.last().unwrap().commit_seq,
        leaf_count: hashes.len() as u64,
        root: root_of(&hashes),
    };
    let mut prefix = Writer::default();
    prefix
        .bytes(PREFIX_FORMAT)
        .fixed(&checkpoint.encode())
        .count(envelopes.len());
    for envelope in &envelopes {
        prefix.bytes(&envelope.encode());
    }
    let historical: Vec<_> = envelopes
        .iter()
        .zip(&hashes)
        .filter(|(e, _)| e.commit_seq <= known_at)
        .map(|(_, hash)| *hash)
        .collect();
    let periods = if through < 0 {
        vec![]
    } else if through < 31 {
        vec!["P1".into()]
    } else {
        vec!["P1".into(), "P2".into()]
    };
    let mut totals = BTreeMap::new();
    for row in expected_rows {
        let total = totals.entry(row.unit).or_insert([0i128; 4]);
        for (sum, value) in total.iter_mut().zip([
            row.debits,
            row.credits,
            row.debits_pending,
            row.credits_pending,
        ]) {
            *sum = sum.checked_add(value).expect("fixture native totals fit");
        }
    }
    let output = output(
        &periods,
        known_at,
        Some(through),
        false,
        expected_rows,
        &totals,
    );
    let docs = registries();
    let mut source = Writer::default();
    source
        .fixed(CERTIFICATE_FORMAT)
        .bytes(b"fa-fold-over-prefix")
        .bytes(b"embedded-owner")
        .bytes(OUTPUT_FORMAT)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(known_at)
        .u8(1)
        .i32(through)
        .fixed(&closure(&docs))
        .fixed(&root_of(&historical))
        .u64(historical.len() as u64)
        .count(7);
    for _ in 0..7 {
        source.bytes(b"opaque native read");
    }
    source
        .bytes(&output)
        .fixed(&hash_parts(b"fa:report-output:v1", &[&output]));
    let source_digest = hash_parts(CERTIFICATE_FORMAT, &[&source.buf]);
    source.fixed(&source_digest);
    let mut bundle = Writer::default();
    bundle
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(&source.buf)
        .bytes(b"externally trusted fixture")
        .bytes(&prefix.buf)
        .count(records.len());
    for record in records {
        bundle.u32(record.len as u32).bytes(&record.bytes);
    }
    bundle.count(bodies.len());
    for (index, body) in bodies {
        bundle.u64(*index).bytes(body);
    }
    bundle.count(docs.len());
    for (name, bytes) in docs {
        bundle.bytes(name.as_bytes()).bytes(&bytes);
    }
    (bundle.buf, signed(checkpoint), source_digest)
}

fn outer(
    source: &[u8],
    accounts: &[u128],
    units: &[u32],
    label: &str,
    from: i32,
    through: i32,
    output: &[u8],
) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    w.bytes(b"fa:roll-forward-certificate:v1")
        .bytes(source)
        .count(accounts.len());
    for account in accounts {
        w.u128(*account);
    }
    w.count(units.len());
    for unit in units {
        w.u32(*unit);
    }
    w.bytes(label.as_bytes())
        .i32(from)
        .i32(through)
        .bytes(output);
    let pin = hash_parts(
        b"fa:roll-forward-certificate-digest:v1",
        &[&(w.buf.len() as u32).to_le_bytes(), &w.buf],
    );
    w.fixed(&pin);
    (w.buf, pin)
}

fn wrap(native: &[u8], report: &VerifiedRollForward) -> (Vec<u8>, [u8; 32]) {
    let mut r = Reader::new(native);
    assert_eq!(r.bytes(64, "format").unwrap(), REPORT_BUNDLE_FORMAT);
    assert_eq!(r.u16("major").unwrap(), 2);
    assert_eq!(r.u16("minor").unwrap(), 0);
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "source").unwrap();
    let tail = &native[native.len() - r.remaining()..];
    let mut ids: Vec<_> = report.accounts.iter().map(|account| account.id).collect();
    ids.sort_unstable();
    let (certificate, pin) = outer(
        source,
        &ids,
        &report.units,
        &report.label,
        report.effective_from,
        report.effective_through,
        &expected_bytes(report),
    );
    let mut bundle = Writer::default();
    bundle
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(&certificate)
        .fixed(tail);
    (bundle.buf, pin)
}

fn verify(
    native: &[u8],
    anchor: SignedCheckpoint,
    expected: &VerifiedRollForward,
) -> Result<VerifiedReport, ReportError> {
    let (bundle, pin) = wrap(native, expected);
    verify_report_with(&bundle, &[], None, None, Some(&pin), |_, _| Ok(anchor))
}

#[test]
fn opening_inclusive_activity_zero_units_and_backdated_known_at_recompute() {
    let mut records = schema();
    for (seq, day, debit, amount) in [
        (3, 9, true, 100),
        (4, 10, true, 40),
        (5, 20, false, 15),
        (6, 31, true, 999),
        (7, 8, true, 7),
    ] {
        records.push(
            dated(
                posting(
                    1,
                    seq,
                    &seq.to_le_bytes(),
                    &[leg("1000", debit, amount), leg("3000", !debit, amount)],
                    None,
                    None,
                ),
                day,
            )
            .0,
        );
    }
    for (known_at, opening) in [(6, 100), (7, 107)] {
        let mut expected = schedule(known_at, 10, 20, &["1000", "3000"], &[0, 1]);
        let bucket = classification(1, "", None);
        expected.buckets = vec![bucket.clone()];
        for row in &mut expected.rows {
            let sign = if row.account_id == account_id("1000") {
                1
            } else {
                -1
            };
            row.activity = vec![if row.unit_id == 1 { 25 * sign } else { 0 }];
            if row.unit_id == 1 {
                row.opening = opening * sign;
                row.net_change = 25 * sign;
                row.closing = (opening + 25) * sign;
            }
        }
        for (index, debit, amount) in [(3, true, 40), (4, false, 15)] {
            expected.movements.extend([
                movement(&records[index], 0, "1000", debit, amount, &bucket),
                movement(&records[index], 1, "3000", !debit, amount, &bucket),
            ]);
        }
        let (native, anchor, source_pin) =
            source_bundle(&records, known_at, 20, &stock(opening + 40, 15), &[]);
        let actual = verify(&native, anchor, &expected).unwrap();
        expected.source_certificate_digest = source_pin;
        assert_eq!(actual.roll_forward, Some(expected.clone()));
        assert_eq!(actual.output, expected_bytes(&expected));
        assert!(actual.rows.is_empty());
        assert_eq!(actual.unit_universe_source, "authenticated-registry");
        assert_eq!(actual.checked_records, 7);
    }
}

fn offsetting(amount: i128) -> (Vec<Record>, VerifiedRollForward) {
    let mut records = schema();
    let legs = [leg("1000", true, amount), leg("3000", false, amount)];
    let (original, id) = dated(posting(1, 3, b"offsetting", &legs, None, None), 10);
    let (undo, _) = dated(reverse(&original, id, 4, b"offsetting-undo", &legs), 20);
    let buckets = vec![
        classification(1, "", None),
        classification(4, "supersession:1", None),
    ];
    let mut expected = schedule(4, 10, 20, &["1000"], &[1]);
    expected.rows[0].activity = vec![amount, -amount];
    expected.movements = vec![
        movement(&original, 0, "1000", true, amount, &buckets[0]),
        movement(&undo, 0, "1000", false, amount, &buckets[1]),
    ];
    expected.buckets = buckets;
    records.extend([original, undo]);
    (records, expected)
}

#[test]
fn offsetting_movements_remain_complete_even_when_every_net_is_zero() {
    let (records, expected) = offsetting(40);
    let (native, anchor, _) = source_bundle(&records, 4, 20, &stock(40, 40), &[]);
    assert_eq!(
        verify(&native, anchor.clone(), &expected)
            .unwrap()
            .roll_forward
            .unwrap()
            .movements
            .len(),
        2
    );
    let mut omitted = expected.clone();
    omitted.movements.clear();
    assert!(verify(&native, anchor.clone(), &omitted).is_err());
    let mut shifted = expected.clone();
    shifted.rows[0].opening = 1;
    shifted.rows[0].closing = 1;
    assert!(verify(&native, anchor.clone(), &shifted).is_err());
    let mut changed_citation = expected;
    changed_citation.movements[0].leg_index = 1;
    assert!(verify(&native, anchor, &changed_citation).is_err());
}

#[test]
fn sorted_distinct_reasons_and_literal_rule_version_are_authenticated() {
    let mut records = schema();
    let record = posting(
        1,
        3,
        b"rule-origin",
        &[leg("1000", true, 10), leg("3000", false, 10)],
        None,
        None,
    )
    .0;
    records.push(attributed(record, Some([7; 32]), &[2, 1, 2]));
    let bucket = classification(1, "supersession:1,2", Some([7; 32]));
    let mut expected = schedule(3, 10, 20, &["1000"], &[1]);
    expected.buckets = vec![bucket.clone()];
    expected.rows[0].activity = vec![10];
    expected.rows[0].net_change = 10;
    expected.rows[0].closing = 10;
    expected.movements = vec![movement(&records[2], 0, "1000", true, 10, &bucket)];
    let (native, anchor, _) = source_bundle(&records, 3, 20, &rows(10, 0), &[]);
    assert!(verify(&native, anchor.clone(), &expected).is_ok());
    for bad in [
        classification(7, "supersession:1,2", Some([7; 32])),
        classification(1, "supersession:2,1", Some([7; 32])),
        classification(1, "supersession:1,2", None),
        classification(1, "supersession:1,2", Some([9; 32])),
    ] {
        let mut tampered = expected.clone();
        tampered.buckets[0] = bad.clone();
        tampered.movements[0].bucket = bad;
        assert!(verify(&native, anchor.clone(), &tampered).is_err());
    }
}

#[test]
fn pending_reservations_never_become_activity_and_posting_resolutions_keep_their_date() {
    for posts in [false, true] {
        let mut records = schema();
        let legs = [leg("1000", true, 75), leg("3000", false, 75)];
        let (pending, id) = posting(2, 3, b"pending", &legs, None, None);
        let (resolution, _) = dated(
            posting(
                3,
                4,
                b"resolved",
                if posts { &legs } else { &[] },
                None,
                Some((id, pending.envelope.record_digest)),
            ),
            20,
        );
        records.extend([pending, resolution]);
        for known_at in [3, 4] {
            let mut expected = schedule(known_at, 10, 20, &["1000"], &[1]);
            let source_rows = if known_at == 3 {
                rows(0, 75)
            } else if posts {
                rows(75, 0)
            } else {
                vec![]
            };
            if posts && known_at == 4 {
                let bucket = classification(3, "", None);
                expected.buckets.push(bucket.clone());
                expected.rows[0].activity = vec![75];
                expected.rows[0].net_change = 75;
                expected.rows[0].closing = 75;
                expected
                    .movements
                    .push(movement(&records[3], 0, "1000", true, 75, &bucket));
            }
            let (native, anchor, _) = source_bundle(&records, known_at, 20, &source_rows, &[]);
            let actual = verify(&native, anchor, &expected).unwrap();
            assert_eq!(actual.output, expected_bytes(&expected));
        }
    }
}

#[test]
fn finalized_migration_uses_original_movement_time_and_mode_visibility() {
    use super::super::explain::{migration_body, migration_record};
    use crate::envelope::Leg;
    for (mode, sole, day, terminal, counts) in [
        (0, false, 9, 1, true),
        (1, false, 9, 1, true),
        (2, false, 9, 1, false),
        (2, true, 9, 1, true),
        (2, false, 10, 1, true),
        (0, false, 9, 2, false),
    ] {
        let (run, body, digest) = migration_body(mode, sole);
        let mut records = schema();
        let legs = [
            Leg {
                account: account_id("1000"),
                unit: 1,
                debit: true,
                mantissa: 35,
            },
            Leg {
                account: account_id("3000"),
                unit: 1,
                debit: false,
                mantissa: 35,
            },
        ];
        records.extend([
            migration_record(run, digest, Some(0), 3, 10, &[]),
            migration_record(run, digest, None, 4, day, &legs),
            migration_record(run, digest, Some(terminal), 6, 10, &[]),
        ]);
        for known_at in [4, 6] {
            for from in [0, 10] {
                let visible = counts && known_at == 6;
                let mut expected = schedule(known_at, from, 20, &["1000"], &[1]);
                if visible {
                    expected.rows[0].closing = 35;
                    if day < from {
                        expected.rows[0].opening = 35;
                    } else {
                        let bucket = classification(12, "", None);
                        expected.buckets.push(bucket.clone());
                        expected.rows[0].activity = vec![35];
                        expected.rows[0].net_change = 35;
                        expected.movements.push(movement(
                            &records[3],
                            0,
                            "1000",
                            true,
                            35,
                            &bucket,
                        ));
                    }
                }
                let source_rows = if visible { rows(35, 0) } else { vec![] };
                let (native, anchor, _) =
                    source_bundle(&records, known_at, 20, &source_rows, &[(2, body.clone())]);
                let actual = verify(&native, anchor, &expected).unwrap_or_else(|error|
                    panic!("mode={mode}, sole={sole}, day={day}, terminal={terminal}, known_at={known_at}, from={from}: {error}"));
                assert_eq!(actual.output, expected_bytes(&expected));
            }
        }
    }
}

#[test]
fn extreme_dates_and_large_signed_cancellation_are_exact() {
    let mut records = schema();
    records.push(
        dated(
            posting(
                1,
                3,
                b"minimum-date",
                &[leg("1000", true, i128::MAX), leg("3000", false, i128::MAX)],
                None,
                None,
            ),
            i32::MIN,
        )
        .0,
    );
    let mut expected = schedule(3, i32::MIN, i32::MAX, &["1000"], &[1]);
    let bucket = classification(1, "", None);
    expected.buckets.push(bucket.clone());
    expected.rows[0].activity = vec![i128::MAX];
    expected.rows[0].net_change = i128::MAX;
    expected.rows[0].closing = i128::MAX;
    expected
        .movements
        .push(movement(&records[2], 0, "1000", true, i128::MAX, &bucket));
    let (native, anchor, _) = source_bundle(&records, 3, i32::MAX, &rows(i128::MAX, 0), &[]);
    assert!(verify(&native, anchor, &expected).is_ok());

    let amount = i128::MAX / 2;
    let (records, expected) = offsetting(amount);
    let (native, anchor, _) = source_bundle(&records, 4, 20, &stock(amount, amount), &[]);
    let report = verify(&native, anchor, &expected)
        .unwrap()
        .roll_forward
        .unwrap();
    assert_eq!(report.rows[0].activity, [amount, -amount]);
    assert_eq!(report.rows[0].net_change, 0);
}

#[test]
fn genuine_gross_overflow_is_not_hidden_by_net_zero_activity() {
    let (records, expected) = offsetting(i128::MAX);
    // The claimed zero TB would fit, but its complete debit and credit totals
    // each exceed i128. Netting them before the stock fold would be unsound.
    let (native, anchor, _) = source_bundle(&records, 4, 20, &stock(0, 0), &[]);
    assert_eq!(
        verify(&native, anchor, &expected).unwrap_err().predicate,
        "exact_arithmetic"
    );
}

#[test]
fn outer_pin_registry_closure_and_full_native_recomputation_are_all_required() {
    let (records, expected) = offsetting(40);
    let (native, anchor, source_pin) = source_bundle(&records, 4, 20, &stock(40, 40), &[]);
    let (bundle, pin) = wrap(&native, &expected);
    assert_ne!(pin, source_pin);
    let actual = verify_report_with(&bundle, &[], None, None, Some(&pin), |_, _| {
        Ok(anchor.clone())
    })
    .unwrap();
    assert_eq!(actual.certificate_digest, pin);
    assert_eq!(
        actual.output_digest,
        hash_parts(b"fa:report-output:v1", &[&expected_bytes(&expected)])
    );
    assert!(verify_report_with(&bundle, &[], None, None, None, |_, _| Ok(anchor.clone())).is_err());
    assert!(
        verify_report_with(&bundle, &[], None, None, Some(&source_pin), |_, _| Ok(
            anchor.clone()
        ))
        .is_err()
    );
    let mut changed_registry = bundle.clone();
    *changed_registry.last_mut().unwrap() ^= 1;
    assert!(
        verify_report_with(&changed_registry, &[], None, None, Some(&pin), |_, _| Ok(
            anchor.clone()
        ))
        .is_err()
    );
    let mut downgraded = bundle;
    let major = 4 + REPORT_BUNDLE_FORMAT.len();
    downgraded[major..major + 2].copy_from_slice(&1u16.to_le_bytes());
    assert!(
        verify_report_with(&downgraded, &[], None, None, Some(&pin), |_, _| Ok(
            anchor.clone()
        ))
        .is_err()
    );
    let (wrong_source, _, _) = source_bundle(&records, 4, 20, &stock(39, 39), &[]);
    assert_eq!(
        verify(&wrong_source, anchor.clone(), &expected)
            .unwrap_err()
            .predicate,
        "report_recomputation"
    );
    let (wrong_cutoff, _, _) = source_bundle(&records, 4, 21, &stock(40, 40), &[]);
    assert_eq!(
        verify(&wrong_cutoff, anchor, &expected)
            .unwrap_err()
            .predicate,
        "supported_report"
    );
}

#[test]
fn empty_complete_scope_is_preserved_and_unknown_accounts_or_units_refuse() {
    let records = schema();
    let expected = schedule(2, -1, 20, &["1000", "3000"], &[0, 1]);
    let (native, anchor, _) = source_bundle(&records, 2, 20, &[], &[]);
    let actual = verify(&native, anchor.clone(), &expected)
        .unwrap()
        .roll_forward
        .unwrap();
    assert_eq!(actual.rows.len(), 4);
    assert!(
        actual
            .rows
            .iter()
            .all(|row| row.opening == 0 && row.closing == 0 && row.activity.is_empty())
    );
    let mut bad_account = expected.clone();
    bad_account.accounts[0].id ^= 1;
    assert_eq!(
        verify(&native, anchor.clone(), &bad_account)
            .unwrap_err()
            .predicate,
        "account_metadata"
    );
    let mut bad_unit = expected;
    bad_unit.units = vec![u32::MAX];
    assert_eq!(
        verify(&native, anchor, &bad_unit).unwrap_err().predicate,
        "registry_closure"
    );
}

#[test]
fn bounded_outer_decoder_refuses_noncanonical_scopes_digests_and_counts() {
    use crate::report::roll_forward::decode;
    for (accounts, units, label, from, through) in [
        (vec![], vec![1], "label", 0, 1),
        (vec![1, 1], vec![1], "label", 0, 1),
        (vec![2, 1], vec![1], "label", 0, 1),
        (vec![1], vec![], "label", 0, 1),
        (vec![1], vec![1, 1], "label", 0, 1),
        (vec![1], vec![1], " \n\t", 0, 1),
        (vec![1], vec![1], "label", 2, 1),
    ] {
        let (raw, _) = outer(&[], &accounts, &units, label, from, through, &[]);
        assert_eq!(
            decode(&raw).err().unwrap().predicate,
            "roll_forward_selection"
        );
    }
    let (mut raw, _) = outer(&[], &[1], &[1], "label", 0, 1, &[]);
    *raw.last_mut().unwrap() ^= 1;
    assert_eq!(decode(&raw).err().unwrap().predicate, "certificate_digest");
    let mut hostile = Writer::default();
    hostile
        .bytes(b"fa:roll-forward-certificate:v1")
        .bytes(&[])
        .u32(u32::MAX);
    assert!(decode(&hostile.buf).is_err());
    let (raw, _) = outer(&[], &[1], &[1], &"x".repeat(257), 0, 1, &[]);
    assert!(decode(&raw).is_err());
    let (raw, _) = outer(
        &[],
        &(0..1000).collect::<Vec<_>>(),
        &(0..1000).collect::<Vec<_>>(),
        "label",
        0,
        1,
        &[],
    );
    assert_eq!(
        decode(&raw).err().unwrap().predicate,
        "roll_forward_selection"
    );
}
