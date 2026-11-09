//! Hand-encoded explicit FX terms, with quote/carrying/cash expectations that
//! do not call the native planner or its codec. Hostile records are resealed.

use super::*;

fn documents() -> Vec<(String, Vec<u8>)> {
    let mut docs = registries();
    docs[4].1 = registry::settlement_terms_fixture(&docs[4].1);
    docs
}

fn profile(docs: &[(String, Vec<u8>)]) -> registry::FunctionalRegistry {
    let inputs: Vec<_> = docs
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    registry::verify_functional(&inputs, &closure(docs)).unwrap()
}

fn replay(
    records: &[Record],
    rates: &[RateFixture],
    spec: &[u8],
) -> Result<(VerifiedFunctionalTrialBalance, Vec<u8>), ReportError> {
    replay_registry_fixture(
        records,
        Selection::AsOf(58),
        records
            .iter()
            .map(|record| record.envelope.commit_seq)
            .max()
            .unwrap(),
        spec,
        rates,
        &[],
        &profile(&documents()),
    )
}

fn verify(
    records: &[Record],
    rates: &[RateFixture],
    output: &[u8],
    docs: &[(String, Vec<u8>)],
) -> Result<crate::report::VerifiedReport, ReportError> {
    let (bundle, signed, pin) = pack_with_registries(
        records,
        &Selection::AsOf(58),
        records
            .iter()
            .map(|record| record.envelope.commit_seq)
            .max()
            .unwrap(),
        &book(&[]),
        rates,
        output,
        docs,
    );
    verify_report_with_inputs(&bundle, &[], None, None, Some(&pin), None, |_, _| {
        Ok(signed.clone())
    })
}

fn terms(components: &[(u16, Vec<(u16, u8)>)]) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"FA-FX-TERMS\0").u16(2).count(components.len());
    for (applying, differences) in components {
        w.u16(*applying).count(differences.len());
        for (ordinal, kind) in differences {
            w.u16(*ordinal).u8(*kind);
        }
    }
    w.buf
}

fn extensions(original: Record, minor: u16, extensions: &[(u16, &[u8])]) -> Record {
    let mut raw = original.bytes[..original.len].to_vec();
    raw[2..4].copy_from_slice(&minor.to_le_bytes());
    let mut w = Writer::default();
    w.fixed(&raw).count(extensions.len());
    for (tag, body) in extensions {
        w.u16(*tag).bytes(body);
    }
    finish(w, original.envelope.commit_seq)
}

fn marked(
    seq: u64,
    day: i32,
    key: &[u8],
    legs: &[AppliedLeg],
    rate: &RateFixture,
    body: &[u8],
) -> Record {
    extensions(payment(seq, day, key, legs, rate), 10, &[(42, body)])
}

fn source_history(
    native: i128,
    historical: i128,
    spot: (u128, u128),
    quote: (u128, u128),
    debit: bool,
) -> (Vec<Record>, Vec<RateFixture>, Record) {
    let (mut records, rates, mut source) = history(native, historical, spot, quote);
    if !debit {
        let mut legs = pair(native, historical);
        legs[0].code = "2000";
        legs[0].debit = false;
        legs[1].code = "5000";
        legs[1].debit = true;
        source = entry(
            4,
            1,
            10,
            b"payable",
            &legs,
            Some((1, &rates[0], None)),
            None,
            None,
        );
        records[3] = source.clone();
    }
    (records, rates, source)
}

fn zero_carrying_history(
    debit: bool,
    quote: (u128, u128),
    prior_cash: i128,
) -> (Vec<Record>, Vec<RateFixture>, Record) {
    // A direct SpotClose source must have positive functional value. Start
    // with 4 foreign units carried at 2, then apply 3: HalfEven(2 * 3 / 4)
    // relieves 2 and leaves one native unit with exactly zero carrying value.
    let (mut records, rates, source) = source_history(4, 2, (1, 2), quote, debit);
    let prior = component(
        &source,
        0,
        if debit { "1100" } else { "2000" },
        debit,
        3,
        2,
        prior_cash,
    );
    records.push(payment(6, 20, b"prior-rounded-relief", &prior, &rates[1]));
    (records, rates, source)
}

#[allow(clippy::too_many_arguments)]
fn explicit_component(
    source: &Record,
    debit: bool,
    native: i128,
    historical: i128,
    quote: i128,
    cash: i128,
    differences: &[(u8, &'static str, i128)],
) -> (Vec<AppliedLeg>, Vec<(u16, u8)>) {
    let applying = !debit;
    let mut legs = vec![
        leg(
            if debit { "1100" } else { "2000" },
            applying,
            1,
            native,
            historical,
        ),
        leg("1900", !applying, 1, native, historical),
        leg("1000", !applying, 0, cash, cash),
        leg("1900", applying, 0, cash, cash),
    ];
    let realized = quote - historical;
    if realized != 0 {
        let side = if realized > 0 { applying } else { !applying };
        legs.push(leg("7000", side, 0, realized.abs(), realized.abs()));
        legs.push(leg("1900", !side, 0, realized.abs(), realized.abs()));
    }
    let mut declared = Vec::new();
    for &(kind, account, amount) in differences {
        let side = if kind == 4 { true } else { debit };
        declared.push((legs.len() as u16, kind));
        legs.push(leg(account, side, 0, amount, amount));
        legs.push(leg("1900", !side, 0, amount, amount));
    }
    let (identity, digest) = handle(source);
    legs[0].applications.push(Application {
        identity,
        digest,
        ordinal: 0,
        unit: 1,
        amount: native,
    });
    (legs, declared)
}

#[test]
fn explicit_fx_terms_separate_actual_cash_all_three_differences_and_quote_gain_or_loss() {
    for debit in [true, false] {
        for (native, historical, spot, quote, quoted) in [
            (100, 110, (11, 10), (6, 5), 120),
            (100, 130, (13, 10), (6, 5), 120),
            (100, 120, (6, 5), (6, 5), 120),
            (1, 0, (1, 2), (10, 1), 10),
        ] {
            let (mut records, rates, source) = if historical == 0 {
                zero_carrying_history(debit, quote, 30)
            } else {
                source_history(native, historical, spot, quote, debit)
            };
            let (source_carrying, prior_cash, prior_realized) = if historical == 0 {
                // The preceding 3-unit application was quoted at 30 and
                // relieved all 2 functional units of the original source.
                (2, 30, 28)
            } else {
                (historical, 0, 0)
            };
            // A 5-unit discount, 1-unit writeoff and 2-unit charge: receipt
            // cash is Q-8, whereas payment cash is Q-5-1+2 = Q-4.
            let cash = quoted - if debit { 8 } else { 4 };
            let (legs, differences) = explicit_component(
                &source,
                debit,
                native,
                historical,
                quoted,
                cash,
                &[(1, "4000", 5), (3, "5000", 1), (4, "5000", 2)],
            );
            let body = terms(&[(0, differences)]);
            let seq = records.last().unwrap().envelope.commit_seq + 1;
            records.push(marked(seq, 20, b"net-cash", &legs, &rates[1], &body));
            let (report, output) = replay(&records, &rates, &book(&[])).unwrap();
            let control = if debit { "1100" } else { "2000" };
            assert_eq!(totals(&report, control), (source_carrying, source_carrying));
            assert_eq!(
                totals(&report, "1000"),
                if debit {
                    (prior_cash + cash, 0)
                } else {
                    (0, prior_cash + cash)
                },
            );
            let realized = prior_realized + quoted - historical;
            let realized_debit = if realized > 0 { !debit } else { debit };
            assert_eq!(
                totals(&report, "7000"),
                if realized_debit {
                    (realized.abs(), 0)
                } else {
                    (0, realized.abs())
                },
            );
            let (dr, cr) = totals(&report, "1900");
            assert_eq!(dr, cr, "complete paired conversion account must clear");
            assert_eq!(
                verify(&records, &rates, &output, &documents())
                    .unwrap()
                    .functional_trial_balance,
                Some(report),
            );
        }
    }
}

#[test]
fn a_direct_spot_source_cannot_create_zero_functional_carrying() {
    for debit in [true, false] {
        let (records, rates, _) = source_history(1, 0, (1, 2), (10, 1), debit);
        assert_eq!(
            replay(&records[..4], &rates[..1], &book(&[]))
                .unwrap_err()
                .predicate,
            "functional_valuation",
            "zero relief must come from the preceding carrying history, not a zero-valued direct source",
        );
    }
}

#[test]
fn explicit_terms_partial_remainder_undo_and_reapplication_preserve_historical_relief() {
    let (mut records, rates, source) = history(10, 15, (3, 2), (2, 1));
    let mut last = None;
    for (seq, native, historical, quote) in [(6, 3, 4, 6), (7, 3, 5, 6), (8, 4, 6, 8)] {
        let (legs, differences) = explicit_component(
            &source,
            true,
            native,
            historical,
            quote,
            quote - 1,
            &[(4, "5000", 1)],
        );
        let body = terms(&[(0, differences)]);
        let record = marked(seq, 20, &seq.to_le_bytes(), &legs, &rates[1], &body);
        records.push(record.clone());
        last = Some((record, legs, body));
    }
    let (report, _) = replay(&records, &rates, &book(&[])).unwrap();
    assert_eq!(totals(&report, "1100"), (15, 15));
    assert_eq!(totals(&report, "1000"), (17, 0));
    assert_eq!(totals(&report, "7000"), (0, 5));
    let (target, legs, body) = last.unwrap();
    let original_undo = application_entry(
        9,
        4,
        20,
        b"undo-net-cash",
        &swapped(&legs),
        (4, &rates[1], None),
        Some(&target),
    );
    records.push(extensions(original_undo.clone(), 10, &[(42, &body)]));
    let (undone, _) = replay(&records, &rates, &book(&[])).unwrap();
    assert_eq!(totals(&undone, "1100"), (21, 15));
    *records.last_mut().unwrap() = original_undo;
    assert_eq!(
        replay(&records, &rates, &book(&[])).unwrap_err().predicate,
        "functional_reversal",
    );
    *records.last_mut().unwrap() = extensions(
        application_entry(
            9,
            4,
            20,
            b"undo-net-cash",
            &swapped(&legs),
            (4, &rates[1], None),
            Some(&target),
        ),
        10,
        &[(42, &body)],
    );
    records.push(marked(10, 20, b"reapply", &legs, &rates[1], &body));
    let (restored, _) = replay(&records, &rates, &book(&[])).unwrap();
    let (dr, cr) = totals(&restored, "1100");
    assert_eq!(dr, cr);
    let (dr, cr) = totals(&restored, "1000");
    assert_eq!(dr - cr, 17);
}

#[test]
fn sparse_terms_preserve_unmarked_legacy_components_on_either_side() {
    for marked_first in [true, false] {
        let (mut records, rates, source) = history(100, 110, (11, 10), (6, 5));
        let second = invoice(6, b"second-item", 50, 55, &rates[0]);
        records.push(second.clone());
        let (
            marked_source,
            native,
            historical,
            quote,
            legacy_source,
            legacy_native,
            legacy_historical,
            legacy_quote,
        ) = if marked_first {
            (&source, 100, 110, 120, &second, 50, 55, 60)
        } else {
            (&second, 50, 55, 60, &source, 100, 110, 120)
        };
        let (explicit, mut differences) = explicit_component(
            marked_source,
            true,
            native,
            historical,
            quote,
            quote - 2,
            &[(4, "5000", 2)],
        );
        let legacy = component(
            legacy_source,
            0,
            "1100",
            true,
            legacy_native,
            legacy_historical,
            legacy_quote,
        );
        let applying = if marked_first { 0 } else { legacy.len() as u16 };
        for (ordinal, _) in &mut differences {
            *ordinal += applying;
        }
        let mut legs = if marked_first {
            explicit.clone()
        } else {
            legacy.clone()
        };
        legs.extend(if marked_first { legacy } else { explicit });
        let body = terms(&[(applying, differences)]);
        records.push(marked(7, 20, b"mixed-profiles", &legs, &rates[1], &body));
        let (report, _) = replay(&records, &rates, &book(&[])).unwrap();
        assert_eq!(totals(&report, "1100"), (165, 165));
        assert_eq!(totals(&report, "1000"), (178, 0));
        assert_eq!(totals(&report, "7000"), (0, 15));
    }
}

#[test]
fn balanced_explicit_pairs_cannot_replace_quote_math_relief_or_source_identity() {
    let (mut records, rates, source) = source_history(100, 110, (11, 10), (6, 5), false);
    let (legs, differences) =
        explicit_component(&source, false, 100, 110, 120, 122, &[(4, "5000", 2)]);
    let body = terms(&[(0, differences)]);
    let honest = marked(6, 20, b"hostile-net-cash", &legs, &rates[1], &body);
    records.push(honest);
    let (_, output) = replay(&records, &rates, &book(&[])).unwrap();
    for pair in [0, 2, 4, 6] {
        let mut changed = legs.clone();
        for leg in &mut changed[pair..pair + 2] {
            if pair != 0 {
                leg.leg.native += 1;
            }
            *leg.leg.base.as_mut().unwrap() += 1;
        }
        *records.last_mut().unwrap() =
            marked(6, 20, b"hostile-net-cash", &changed, &rates[1], &body);
        assert_eq!(
            verify(&records, &rates, &output, &documents())
                .unwrap_err()
                .predicate,
            "functional_carrying",
            "balanced pair {pair} is not independent evidence of its amount",
        );
    }
    for kind in 0..3 {
        let mut changed = legs.clone();
        match kind {
            0 => changed[0].applications[0].digest[0] ^= 1,
            1 => changed[6].leg.code = "1000",
            _ => changed[7].leg.code = "7000",
        }
        *records.last_mut().unwrap() =
            marked(6, 20, b"hostile-net-cash", &changed, &rates[1], &body);
        assert_eq!(
            replay(&records, &rates, &book(&[])).unwrap_err().predicate,
            "functional_carrying",
        );
    }
    // A positive bank payment cannot turn a quote rounded to zero into an
    // eligible foreign settlement, even when cash and the charge cancel.
    let (mut records, rates, source) = zero_carrying_history(false, (1, 2), 2);
    let (legs, differences) = explicit_component(&source, false, 1, 0, 0, 2, &[(4, "5000", 2)]);
    records.push(marked(
        7,
        20,
        b"zero-gross-quote",
        &legs,
        &rates[1],
        &terms(&[(0, differences)]),
    ));
    assert_eq!(
        replay(&records, &rates, &book(&[])).unwrap_err().predicate,
        "functional_carrying",
    );
}

#[test]
fn explicit_terms_bind_full_source_dimensions_even_when_each_entity_balances() {
    let (mut records, rates, _) = history(100, 110, (11, 10), (6, 5));
    let mut source_legs = pair(100, 110);
    source_legs[0].code = "1100";
    source_legs[1].code = "4000";
    for leg in &mut source_legs {
        leg.entity = Some("alpha");
    }
    let source = entry(
        4,
        1,
        10,
        b"invoice",
        &source_legs,
        Some((1, &rates[0], None)),
        None,
        None,
    );
    records[3] = source.clone();
    let (mut legs, differences) =
        explicit_component(&source, true, 100, 110, 120, 118, &[(4, "5000", 2)]);
    for leg in &mut legs {
        leg.leg.entity = Some("alpha");
    }
    let body = terms(&[(0, differences)]);
    records.push(marked(6, 20, b"dimensioned-net", &legs, &rates[1], &body));
    let spec = book(&["alpha", "beta"]);
    assert!(replay(&records, &rates, &spec).is_ok());
    for leg in &mut legs[6..8] {
        leg.leg.entity = Some("beta");
    }
    *records.last_mut().unwrap() = marked(6, 20, b"dimensioned-net", &legs, &rates[1], &body);
    assert_eq!(
        replay(&records, &rates, &spec).unwrap_err().predicate,
        "functional_carrying",
    );
}

#[test]
fn explicit_terms_refuse_missing_unknown_reordered_and_legacy_profile_declarations() {
    let (mut records, rates, source) = history(100, 110, (11, 10), (6, 5));
    let (legs, differences) = explicit_component(
        &source,
        true,
        100,
        110,
        120,
        117,
        &[(1, "4000", 1), (4, "5000", 2)],
    );
    let body = terms(&[(0, differences.clone())]);
    let original = payment(6, 20, b"bad-terms", &legs, &rates[1]);
    records.push(extensions(original.clone(), 10, &[(42, &body)]));
    let (_, output) = replay(&records, &rates, &book(&[])).unwrap();
    assert_eq!(
        verify(&records, &rates, &output, &registries())
            .unwrap_err()
            .predicate,
        "functional_carrying",
    );

    let mut bad_version = body.clone();
    bad_version[12..14].copy_from_slice(&3u16.to_le_bytes());
    let mut unknown_kind = body.clone();
    unknown_kind[26] = 2;
    let mut backwards = differences.clone();
    backwards.reverse();
    let mut trailing = body.clone();
    trailing.push(0);
    let mut oversized = body.clone();
    oversized[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
    for malformed in [
        bad_version,
        unknown_kind,
        terms(&[(0, backwards)]),
        terms(&[(0, differences.clone()), (0, differences.clone())]),
        terms(&[(2, differences)]),
        terms(&[(0, Vec::new())]),
        terms(&[]),
        trailing,
        oversized,
    ] {
        *records.last_mut().unwrap() = extensions(original.clone(), 10, &[(42, &malformed)]);
        assert!(verify(&records, &rates, &output, &documents()).is_err());
    }
    for malformed in [
        original.clone(),
        extensions(original.clone(), 9, &[(42, &body)]),
        extensions(original.clone(), 10, &[(43, &body)]),
        extensions(original.clone(), 10, &[(42, &body), (42, &body)]),
        extensions(original.clone(), 10, &[(42, &body), (41, &[])]),
        extensions(original, 10, &[(41, &[]), (42, &body)]),
    ] {
        *records.last_mut().unwrap() = malformed;
        assert!(verify(&records, &rates, &output, &documents()).is_err());
    }
}

#[test]
fn resealed_explicit_terms_registry_cannot_redefine_pair_layout_or_economic_equations() {
    let (mut records, rates, source) = history(100, 110, (11, 10), (6, 5));
    let (legs, differences) =
        explicit_component(&source, true, 100, 110, 120, 118, &[(4, "5000", 2)]);
    let body = terms(&[(0, differences)]);
    records.push(marked(6, 20, b"retained-profile", &legs, &rates[1], &body));
    let (_, output) = replay(&records, &rates, &book(&[])).unwrap();
    for marker in [
        b"cash_fx_differences_paired".as_slice(),
        b"quote=cash+discount+writeoff+bank_charge".as_slice(),
        b"quote=cash+discount+writeoff-bank_charge".as_slice(),
    ] {
        let mut docs = documents();
        let at = docs[4]
            .1
            .windows(marker.len())
            .position(|bytes| bytes == marker)
            .unwrap();
        docs[4].1[at] ^= 1;
        assert_eq!(
            verify(&records, &rates, &output, &docs)
                .unwrap_err()
                .predicate,
            "registry_closure",
        );
    }
}
