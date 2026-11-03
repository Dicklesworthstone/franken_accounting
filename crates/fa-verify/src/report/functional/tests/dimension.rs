//! Independent functional-dimension selectors, exact amount vectors and
//! resealed hostile bundles. None of these fixtures uses producer code.

use super::*;

fn value(dimension: &str, code: &str) -> u128 {
    let digest = framed_hash(
        b"fa:vid:dimension-value:v1",
        &[&BOOK, dimension.as_bytes(), code.as_bytes()],
    );
    u128::from_le_bytes(digest[..16].try_into().unwrap())
}

fn control(seq: u64, kind: u16, body: &[u8]) -> Record {
    let mut w = prefix(17, 0);
    w.count(0)
        .u8(1)
        .u8(1)
        .u16(kind)
        .bytes(body)
        .count(0)
        .u8(0)
        .bytes(format!("dimension-{seq}").as_bytes())
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

fn declaration(
    seq: u64,
    dimension: &str,
    code: &str,
    parent: Option<&str>,
    valid_from: Option<i32>,
) -> Record {
    let mut w = Writer::default();
    w.fixed(b"fa:dimension-value:v1")
        .bytes(dimension.as_bytes())
        .bytes(code.as_bytes())
        .bytes(code.as_bytes())
        .u8(u8::from(parent.is_some()));
    if let Some(parent) = parent {
        w.bytes(parent.as_bytes());
    }
    w.u8(u8::from(valid_from.is_some()));
    if let Some(day) = valid_from {
        w.i32(day);
    }
    w.u8(0);
    control(seq, 17, &w.buf)
}

fn close(seq: u64, code: &str, day: i32) -> Record {
    let mut w = Writer::default();
    w.fixed(b"fa:dimension-close:v1")
        .bytes(b"fund")
        .bytes(code.as_bytes())
        .i32(day);
    control(seq, 19, &w.buf)
}

/// Retain all monetary, entity and law bytes while adding one analytic tag
/// per leg. Recompute the entry and proposal hashes after every mutation.
fn tagged(record: &Record, dimension: u32, values: &[Option<u128>]) -> Record {
    let proposal = &record.bytes[..record.len];
    let mut r = Reader::new(proposal);
    r.fixed::<42>("header").unwrap();
    if r.present("document_date").unwrap() {
        r.i32("document_date").unwrap();
    }
    crate::envelope::skip_erasable(&mut r, "description").unwrap();
    if r.present("period").unwrap() {
        r.bytes(128, "calendar").unwrap();
        r.bytes(128, "period").unwrap();
    }
    assert_eq!(r.count(4096, 1, "legs").unwrap(), values.len());
    let mut w = Writer::default();
    w.fixed(&proposal[..proposal.len() - r.remaining()]);
    for value in values {
        let start = proposal.len() - r.remaining();
        r.fixed::<37>("leg").unwrap();
        if r.present("base").unwrap() {
            r.fixed::<20>("base").unwrap();
        }
        w.fixed(&proposal[start..proposal.len() - r.remaining()]);
        let count = r.count(64, 20, "dimensions").unwrap();
        let mut tags = BTreeMap::new();
        for _ in 0..count {
            tags.insert(r.u32("kind").unwrap(), r.u128("value").unwrap());
        }
        tags.remove(&dimension);
        if let Some(value) = value {
            tags.insert(dimension, *value);
        }
        w.count(tags.len());
        for (kind, value) in tags {
            w.u32(kind).u128(value);
        }
        let start = proposal.len() - r.remaining();
        assert!(!r.present("memo").unwrap());
        assert_eq!(r.count(0, 1, "applications").unwrap(), 0);
        w.fixed(&proposal[start..proposal.len() - r.remaining()]);
    }
    w.fixed(&proposal[proposal.len() - r.remaining()..]);
    finish(w, record.envelope.commit_seq)
}

fn declarations() -> Vec<Record> {
    let mut records = schema();
    records.push(declaration(3, "fund", "root", None, None));
    records.push(declaration(4, "fund", "child", Some("root"), None));
    records.push(declaration(5, "fund", "other", None, None));
    records
}

#[allow(clippy::too_many_arguments)]
fn replay_selected(
    records: &[Record],
    selected: Selection,
    known_at: u64,
    spec: &[u8],
    rates: &[RateFixture],
    bodies: &[(u64, &[u8])],
    dimension: &str,
    root: &str,
) -> Result<(VerifiedFunctionalTrialBalance, Vec<u8>), ReportError> {
    replay_registry_dimension_fixture(
        records,
        selected,
        known_at,
        spec,
        rates,
        bodies,
        &definitions(),
        Some(super::super::super::dimension::Selection {
            dimension: dimension.into(),
            value: root.into(),
        }),
    )
}

fn wrapper(dimension: &str, root: &str, included: &[&str], inner: &[u8]) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(DIMENSION_OUTPUT_FORMAT)
        .bytes(dimension.as_bytes())
        .bytes(root.as_bytes())
        .count(included.len());
    for value in included {
        w.bytes(value.as_bytes());
    }
    w.bytes(inner);
    w.buf
}

#[allow(clippy::too_many_arguments)]
fn pack_dimension(
    records: &[Record],
    selected: &Selection,
    known_at: u64,
    spec: &[u8],
    rates: &[RateFixture],
    output: &[u8],
    bodies: &[(u64, &[u8])],
    dimension: &str,
    root: &str,
) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
    let mut selector = Writer::default();
    selector.u8(11);
    selection(&mut selector, selected).unwrap();
    selector.bytes(dimension.as_bytes()).bytes(root.as_bytes());
    pack_profile_with_migrations(
        records,
        known_at,
        spec,
        rates,
        output,
        CertificateProfile {
            format: FUNCTIONAL_DIMENSION_CERTIFICATE_FORMAT,
            output_format: DIMENSION_OUTPUT_FORMAT,
            selector: &selector.buf,
        },
        &registries(),
        bodies,
    )
}

fn verify(
    bundle: &[u8],
    signed: &SignedCheckpoint,
    pin: Option<&[u8; 32]>,
) -> Result<crate::report::VerifiedReport, ReportError> {
    verify_report_with_inputs(
        bundle,
        &[],
        None,
        None,
        pin,
        None,
        |_, _| Ok(signed.clone()),
    )
}

fn one_sided_history() -> (Vec<Record>, RateFixture) {
    let mut records = declarations();
    let rate = rate_fixture(1, 3, 1, 10);
    records.push(intake(&rate, 6));
    records.push(tagged(
        &entry(
            7,
            1,
            10,
            b"residual-ordinal-two",
            &residual_legs(),
            Some((1, &rate, Some((1, 1)))),
            None,
            None,
        ),
        7,
        &[
            None,
            Some(value("fund", "other")),
            Some(value("fund", "child")),
        ],
    ));
    (records, rate)
}

/// A literal expected credit of one base minor unit, on the third original
/// leg. Both the output and its fold digest are encoded independently from
/// this hand-calculated fact; no replayed amount supplies the expected bytes.
fn one_sided_expected(
    records: &[Record],
    selected: &Selection,
    spec: &[u8],
) -> ([u8; 32], Vec<u8>) {
    let activity = matches!(selected, Selection::Activity(_));
    let through = match selected {
        Selection::AsOf(day) => Some(*day),
        Selection::Periods(_) => Some(30),
        Selection::Activity(_) => None,
        _ => panic!("trial balance selection"),
    };
    let cell = |w: &mut Writer, with_period: bool| {
        w.count(1).u128(id("3000")).u32(0);
        if with_period {
            w.bytes(b"P1");
        }
        w.u8(0).i128(0).i128(1).u64(1);
    };
    let record = &records[6];
    let mut fold = Writer::default();
    let inner_digest = if activity {
        let mut leg = Writer::default();
        leg.fixed(&[0; 32])
            .u64(7)
            .u128(handle(record).0)
            .u16(2)
            .u128(id("3000"))
            .u32(0)
            .u8(0)
            .u8(1)
            .i128(1);
        fold.bytes(b"P1")
            .u32(0)
            .u8(1)
            .u64(7)
            .fixed(&hash_parts(
                b"fa:register-functional-leg-contribution:v1",
                &[&leg.buf],
            ))
            .count(0);
        cell(&mut fold, true);
        fold.count(0);
        hash_parts(b"fa:register-functional-fold:v1", &[&fold.buf])
    } else {
        let mut source = Writer::default();
        source
            .u64(7)
            .u128(handle(record).0)
            .fixed(&record.envelope.record_digest)
            .u64(7)
            .u8(0)
            .u8(0);
        fold.bytes(spec)
            .i32(through.unwrap())
            .u32(0)
            .u64(1)
            .u8(1)
            .u64(7)
            .fixed(&hash_parts(
                b"fa:register-functional-stock-sources:v1",
                &[&source.buf],
            ));
        cell(&mut fold, false);
        fold.count(0);
        hash_parts(b"fa:register-functional-stock:v1", &[&fold.buf])
    };
    let mut ids = [value("fund", "root"), value("fund", "child")];
    ids.sort_unstable();
    let mut filter = Writer::default();
    filter.fixed(&inner_digest).u32(7).count(2);
    for id in ids {
        filter.u128(id);
    }
    let digest = hash_parts(b"fa:register-functional-dimension:v1", &[&filter.buf]);
    let mut inner = Writer::default();
    inner.fixed(OUTPUT_FORMAT).bytes(b"retained-base-amounts");
    match selected {
        Selection::AsOf(day) => {
            inner.u8(1).i32(*day);
        }
        Selection::Periods(_) | Selection::Activity(_) => {
            inner.u8(if activity { 2 } else { 0 }).count(1).bytes(b"P1");
        }
        _ => unreachable!(),
    }
    inner.u8(u8::from(through.is_some()));
    if let Some(day) = through {
        inner.i32(day);
    }
    inner.u32(0).u64(7).u8(1).u64(7).u64(1).fixed(&digest);
    cell(&mut inner, false);
    inner
        .count(0)
        .count(1)
        .u128(id("3000"))
        .u128(id("3000"))
        .bytes(b"3000")
        .bytes(b"Equity")
        .u8(3)
        .u8(1)
        .u8(1)
        .u8(1)
        .u8(0)
        .u64(1);
    (
        digest,
        wrapper("fund", "root", &["child", "root"], &inner.buf),
    )
}

#[test]
fn v13_stock_and_activity_match_independent_one_sided_bytes_and_original_ordinal() {
    let (records, rate) = one_sided_history();
    let spec = book(&[]);
    for selected in [
        Selection::AsOf(20),
        Selection::Periods(vec!["P1".into()]),
        Selection::Activity(vec!["P1".into()]),
    ] {
        let (digest, expected) = one_sided_expected(&records, &selected, &spec);
        let (report, output) = replay_selected(
            &records,
            selected.clone(),
            7,
            &spec,
            std::slice::from_ref(&rate),
            &[],
            "fund",
            "root",
        )
        .unwrap();
        assert_eq!(
            report.cells,
            [VerifiedFunctionalCell {
                account: id("3000"),
                unit_id: 0,
                entity: None,
                debits: 0,
                credits: 1,
                entry_count: 1,
            }]
        );
        assert_eq!((report.entries, report.watermark), (1, Some(7)));
        assert_eq!(report.fold_digest, digest);
        assert_eq!(output, expected);
        let (bundle, signed, pin) = pack_dimension(
            &records,
            &selected,
            7,
            &spec,
            std::slice::from_ref(&rate),
            &expected,
            &[],
            "fund",
            "root",
        );
        assert_eq!(
            verify(&bundle, &signed, None).unwrap_err().predicate,
            "report_input_authority"
        );
        let checked = verify(&bundle, &signed, Some(&pin)).unwrap();
        assert_eq!(checked.functional_trial_balance, Some(report));
        assert_eq!(checked.dimension.unwrap().values, ["child", "root"]);
        assert_eq!(checked.output, expected);
    }
}

fn entity_pair(entity: &'static str, native: i128, base: i128, base_native: bool) -> Vec<TestLeg> {
    pair(native, base)
        .into_iter()
        .map(|mut leg| {
            leg.entity = Some(entity);
            if base_native {
                leg.unit = 0;
                leg.base = None;
            }
            leg
        })
        .collect()
}

fn mixed_history() -> (Vec<Record>, RateFixture) {
    let mut records = declarations();
    let rate = rate_fixture(1, 3, 1, 10);
    records.push(intake(&rate, 6));
    for (seq, class, entity, native, base, base_native, debit, credit) in [
        (7, 1, "A", 9, 3, false, Some("child"), None),
        (8, 1, "B", 12, 4, false, Some("child"), Some("other")),
        (9, 1, "A", 5, 5, true, Some("root"), Some("root")),
        (10, 2, "B", 6, 2, false, Some("child"), None),
        (11, 1, "A", 30, 10, false, Some("other"), Some("other")),
        (12, 1, "A", 21, 7, false, None, None),
    ] {
        records.push(tagged(
            &entry(
                seq,
                class,
                10,
                &seq.to_le_bytes(),
                &entity_pair(entity, native, base, base_native),
                (!base_native).then_some((1, &rate, None)),
                None,
                None,
            ),
            7,
            &[
                debit.map(|code| value("fund", code)),
                credit.map(|code| value("fund", code)),
            ],
        ));
    }
    records.push(close(13, "child", 20));
    records.push(declaration(14, "fund", "future", Some("root"), Some(40)));
    records.push(entry(
        15,
        3,
        40,
        b"release",
        &[],
        None,
        None,
        Some(&records[9]),
    ));
    (records, rate)
}

#[test]
fn historical_descendants_preserve_entities_pending_releases_and_selected_watermarks() {
    let (records, rate) = mixed_history();
    let spec = book(&["A", "B"]);
    for selected in [Selection::AsOf(20), Selection::Activity(vec!["P1".into()])] {
        let (before, before_output) = replay_selected(
            &records,
            selected.clone(),
            14,
            &spec,
            std::slice::from_ref(&rate),
            &[],
            "fund",
            "root",
        )
        .unwrap();
        let actual: BTreeMap<_, _> = before
            .cells
            .iter()
            .map(|cell| {
                (
                    (cell.account, cell.entity.as_deref()),
                    (cell.debits, cell.credits, cell.entry_count),
                )
            })
            .collect();
        assert_eq!(
            actual,
            BTreeMap::from([
                ((id("1000"), Some("A")), (8, 0, 2)),
                ((id("1000"), Some("B")), (4, 0, 1)),
                ((id("3000"), Some("A")), (0, 5, 1)),
            ])
        );
        assert_eq!(
            before.pending,
            [VerifiedFunctionalCell {
                account: id("1000"),
                unit_id: 0,
                entity: Some("B".into()),
                debits: 2,
                credits: 0,
                entry_count: 1,
            }]
        );
        assert_eq!((before.entries, before.watermark), (3, Some(10)));
        let (after, output) = replay_selected(
            &records,
            selected.clone(),
            15,
            &spec,
            std::slice::from_ref(&rate),
            &[],
            "fund",
            "root",
        )
        .unwrap();
        assert_eq!(after.cells, before.cells);
        assert!(after.pending.is_empty());
        assert_eq!((after.entries, after.watermark), (3, Some(15)));
        assert_ne!(before.fold_digest, after.fold_digest);
        for (known_at, output) in [(14, before_output), (15, output)] {
            let (bundle, signed, pin) = pack_dimension(
                &records,
                &selected,
                known_at,
                &spec,
                std::slice::from_ref(&rate),
                &output,
                &[],
                "fund",
                "root",
            );
            assert_eq!(
                verify(&bundle, &signed, Some(&pin))
                    .unwrap()
                    .dimension
                    .unwrap()
                    .values,
                ["child", "future", "root"]
            );
        }
        let (empty, _) = replay_selected(
            &records,
            selected,
            15,
            &spec,
            std::slice::from_ref(&rate),
            &[],
            "fund",
            "future",
        )
        .unwrap();
        assert!(empty.cells.is_empty() && empty.pending.is_empty());
        assert_eq!((empty.entries, empty.watermark), (0, None));
    }
    let (early, _) = replay_selected(
        &records,
        Selection::AsOf(20),
        12,
        &spec,
        std::slice::from_ref(&rate),
        &[],
        "fund",
        "root",
    )
    .unwrap();
    let (later, _) = replay_selected(
        &records,
        Selection::AsOf(20),
        14,
        &spec,
        &[rate],
        &[],
        "fund",
        "root",
    )
    .unwrap();
    assert_eq!(early.cells, later.cells);
    assert_eq!(early.pending, later.pending);
    assert_ne!(
        early.fold_digest, later.fold_digest,
        "a newly declared descendant binds even without postings"
    );
}

#[test]
fn excluded_legs_cannot_hide_bad_rates_base_amounts_entities_or_undeclared_tags() {
    let (records, rate) = mixed_history();
    let spec = book(&["A", "B"]);
    let selected = Selection::AsOf(20);
    let (_, output) = replay_selected(
        &records,
        selected.clone(),
        15,
        &spec,
        std::slice::from_ref(&rate),
        &[],
        "fund",
        "root",
    )
    .unwrap();
    for mutant in 0..5 {
        let mut changed = records.clone();
        match mutant {
            0 => {
                // Both legs belong to the other fund: choosing root cannot
                // hide a balanced but incorrectly repriced foreign entry.
                changed[10] = tagged(
                    &entry(
                        11,
                        1,
                        10,
                        &11u64.to_le_bytes(),
                        &entity_pair("A", 30, 11, false),
                        Some((1, &rate, None)),
                        None,
                        None,
                    ),
                    7,
                    &[Some(value("fund", "other")); 2],
                );
            }
            1 => {
                let mut legs = entity_pair("A", 30, 10, false);
                legs[1].entity = Some("B");
                changed[10] = tagged(
                    &entry(
                        11,
                        1,
                        10,
                        &11u64.to_le_bytes(),
                        &legs,
                        Some((1, &rate, None)),
                        None,
                        None,
                    ),
                    7,
                    &[Some(value("fund", "other")); 2],
                );
            }
            2 => changed[10] = tagged(&changed[10], 7, &[Some(value("fund", "missing")); 2]),
            3 => {
                changed[3] = declaration(4, "fund", "child", Some("missing"), None);
            }
            _ => changed[10] = tagged(&changed[10], 10, &[Some(99); 2]),
        }
        assert!(
            replay_selected(
                &changed,
                Selection::AsOf(20),
                15,
                &spec,
                std::slice::from_ref(&rate),
                &[],
                "fund",
                "root",
            )
            .is_err(),
            "mutant {mutant}"
        );
        let (bundle, signed, pin) = pack_dimension(
            &changed,
            &selected,
            15,
            &spec,
            std::slice::from_ref(&rate),
            &output,
            &[],
            "fund",
            "root",
        );
        assert!(
            verify(&bundle, &signed, Some(&pin)).is_err(),
            "resealed mutant {mutant}"
        );
    }
    assert_eq!(
        replay_selected(
            &records,
            Selection::AsOf(20),
            15,
            &spec,
            &[],
            &[],
            "fund",
            "future",
        )
        .unwrap_err()
        .predicate,
        "functional_rates"
    );
    for (dimension, root) in [
        ("fund", "missing"),
        ("party", "root"),
        ("legal_entity", "A"),
    ] {
        assert!(
            replay_selected(
                &records,
                Selection::AsOf(20),
                15,
                &spec,
                std::slice::from_ref(&rate),
                &[],
                dimension,
                root,
            )
            .is_err()
        );
    }
}

#[test]
fn resealed_claimed_hierarchy_or_valuation_cannot_replace_authenticated_projection() {
    let (records, rate) = one_sided_history();
    let selected = Selection::AsOf(20);
    let spec = book(&[]);
    let (_, output) = one_sided_expected(&records, &selected, &spec);
    let mut r = Reader::new(&output);
    r.fixed::<{ DIMENSION_OUTPUT_FORMAT.len() }>("format")
        .unwrap();
    r.bytes(64, "dimension").unwrap();
    r.bytes(64, "root").unwrap();
    let count = r.count(3, 4, "values").unwrap();
    for _ in 0..count {
        r.bytes(64, "value").unwrap();
    }
    let inner = r.bytes(1 << 20, "inner").unwrap();
    let mut changed_inner = inner.to_vec();
    let mut amount = Reader::new(inner);
    amount
        .fixed::<{ OUTPUT_FORMAT.len() }>("inner format")
        .unwrap();
    amount.bytes(64, "valuation").unwrap();
    assert_eq!(amount.u8("selection").unwrap(), 1);
    amount.i32("selected date").unwrap();
    assert!(amount.present("through").unwrap());
    amount.i32("through").unwrap();
    amount.u32("base").unwrap();
    amount.u64("known at").unwrap();
    assert!(amount.present("watermark").unwrap());
    amount.u64("watermark").unwrap();
    amount.u64("entries").unwrap();
    amount.fixed::<32>("fold digest").unwrap();
    assert_eq!(amount.count(1, 1, "cells").unwrap(), 1);
    amount.u128("account").unwrap();
    amount.u32("unit").unwrap();
    assert!(!amount.present("entity").unwrap());
    assert_eq!(amount.i128("debits").unwrap(), 0);
    let credit_offset = inner.len() - amount.remaining();
    assert_eq!(amount.i128("credits").unwrap(), 1);
    changed_inner[credit_offset] ^= 1;
    for bad in [
        wrapper("fund", "root", &["root"], inner),
        wrapper("fund", "root", &["root", "child"], inner),
        wrapper("fund", "other", &["child", "root"], inner),
        wrapper("department", "root", &["child", "root"], inner),
        wrapper("fund", "root", &["child", "root"], &changed_inner),
    ] {
        let (bundle, signed, pin) = pack_dimension(
            &records,
            &selected,
            7,
            &spec,
            std::slice::from_ref(&rate),
            &bad,
            &[],
            "fund",
            "root",
        );
        assert_eq!(
            verify(&bundle, &signed, Some(&pin)).unwrap_err().predicate,
            "report_recomputation"
        );
    }
    let mut changed = records.clone();
    changed[3] = declaration(4, "fund", "child", None, None);
    let (bundle, signed, pin) = pack_dimension(
        &changed,
        &selected,
        7,
        &spec,
        &[rate],
        &output,
        &[],
        "fund",
        "root",
    );
    assert_eq!(
        verify(&bundle, &signed, Some(&pin)).unwrap_err().predicate,
        "report_recomputation"
    );
}

#[test]
fn functional_dimension_migrations_activate_only_at_the_original_finalize_frontier() {
    let mut records = declarations();
    let run = migration::run();
    let body = migration::body(0, false);
    records.push(migration::control(6, 0, run, &body));
    let native: Vec<_> = pair(42, 42)
        .into_iter()
        .map(|mut leg| {
            leg.unit = 0;
            leg.base = None;
            leg
        })
        .collect();
    records.push(tagged(
        &entry_with_migration(
            7,
            12,
            10,
            b"fund-migration",
            &native,
            None,
            None,
            None,
            Some(run),
        ),
        7,
        &[Some(value("fund", "child")), None],
    ));
    records.push(migration::control(8, 1, run, &body));
    let bodies = [(5, body.as_slice())];
    let spec = book(&[]);
    for selected in [Selection::AsOf(20), Selection::Activity(vec!["P1".into()])] {
        for known_at in [7, 8] {
            let (report, output) = replay_selected(
                &records,
                selected.clone(),
                known_at,
                &spec,
                &[],
                &bodies,
                "fund",
                "root",
            )
            .unwrap();
            assert_eq!(report.entries, u64::from(known_at == 8));
            assert_eq!(report.watermark, (known_at == 8).then_some(8));
            assert_eq!(
                report.cells.iter().map(|cell| cell.debits).sum::<i128>(),
                if known_at == 8 { 42 } else { 0 }
            );
            assert_eq!(
                report.cells.iter().map(|cell| cell.credits).sum::<i128>(),
                0
            );
            let (bundle, signed, pin) = pack_dimension(
                &records,
                &selected,
                known_at,
                &spec,
                &[],
                &output,
                &bodies,
                "fund",
                "root",
            );
            assert_eq!(
                verify(&bundle, &signed, Some(&pin))
                    .unwrap()
                    .functional_trial_balance,
                Some(report)
            );
        }
    }
}

#[test]
fn every_registered_analytic_dimension_uses_its_own_historical_namespace() {
    let spec = book(&[]);
    for (dimension, kind) in [
        ("cost_center", 2),
        ("department", 3),
        ("project", 4),
        ("product", 5),
        ("region", 6),
        ("fund", 7),
        ("grant", 8),
        ("segment", 9),
    ] {
        let mut records = schema();
        records.push(declaration(3, dimension, "root", None, None));
        records.push(declaration(4, dimension, "child", Some("root"), None));
        let native: Vec<_> = pair(42, 42)
            .into_iter()
            .map(|mut leg| {
                leg.unit = 0;
                leg.base = None;
                leg
            })
            .collect();
        records.push(tagged(
            &entry(5, 1, 10, b"base-native", &native, None, None, None),
            kind,
            &[Some(value(dimension, "child")), None],
        ));
        let selected = Selection::AsOf(20);
        let (report, output) = replay_selected(
            &records,
            selected.clone(),
            5,
            &spec,
            &[],
            &[],
            dimension,
            "root",
        )
        .unwrap();
        assert_eq!(
            report.cells,
            [VerifiedFunctionalCell {
                account: id("1000"),
                unit_id: 0,
                entity: None,
                debits: 42,
                credits: 0,
                entry_count: 1,
            }]
        );
        let (bundle, signed, pin) = pack_dimension(
            &records,
            &selected,
            5,
            &spec,
            &[],
            &output,
            &[],
            dimension,
            "root",
        );
        let checked = verify(&bundle, &signed, Some(&pin)).unwrap();
        assert_eq!(checked.dimension.unwrap().dimension, dimension);
        assert_eq!(checked.functional_trial_balance, Some(report));
    }
}

#[test]
fn v13_requires_its_exact_header_selector_output_family_and_input_count() {
    let (records, _) = one_sided_history();
    let (_, output) = one_sided_expected(&records, &Selection::AsOf(20), &book(&[]));
    let encoded = |format: &[u8], family: &[u8], selector: u8, inputs: usize| {
        let mut w = Writer::default();
        w.fixed(format)
            .bytes(b"fa-fold-over-prefix")
            .bytes(b"embedded-owner")
            .bytes(family)
            .fixed(&BOOK)
            .fixed(&[0; 16])
            .u64(7)
            .u8(selector)
            .u8(1)
            .i32(20)
            .bytes(b"fund")
            .bytes(b"root")
            .fixed(&[0; 32])
            .fixed(&[0; 32])
            .u64(7)
            .count(inputs);
        for _ in 0..inputs {
            w.bytes(b"opaque source witness");
        }
        w.bytes(&output)
            .fixed(&hash_parts(b"fa:report-output:v1", &[&output]))
            .u8(0);
        let digest = hash_parts(format, &[&w.buf]);
        w.fixed(&digest);
        w.buf
    };
    let good = encoded(
        FUNCTIONAL_DIMENSION_CERTIFICATE_FORMAT,
        DIMENSION_OUTPUT_FORMAT,
        11,
        9,
    );
    let cert = certificate(&good).unwrap();
    assert!(cert.functional);
    assert_eq!(cert.dimension.unwrap().dimension, "fund");
    for (format, family, selector, inputs) in [
        (
            FUNCTIONAL_DIMENSION_CERTIFICATE_FORMAT.as_slice(),
            DIMENSION_OUTPUT_FORMAT,
            8,
            9,
        ),
        (
            FUNCTIONAL_DIMENSION_CERTIFICATE_FORMAT.as_slice(),
            DIMENSION_OUTPUT_FORMAT,
            6,
            9,
        ),
        (
            FUNCTIONAL_DIMENSION_CERTIFICATE_FORMAT.as_slice(),
            DIMENSION_OUTPUT_FORMAT,
            11,
            8,
        ),
        (
            FUNCTIONAL_DIMENSION_CERTIFICATE_FORMAT.as_slice(),
            OUTPUT_FORMAT,
            11,
            9,
        ),
        (
            FUNCTIONAL_CERTIFICATE_FORMAT.as_slice(),
            DIMENSION_OUTPUT_FORMAT,
            11,
            9,
        ),
        (
            super::super::super::DIMENSION_CERTIFICATE_FORMAT.as_slice(),
            DIMENSION_OUTPUT_FORMAT,
            11,
            9,
        ),
    ] {
        assert!(certificate(&encoded(format, family, selector, inputs)).is_err());
    }
}
