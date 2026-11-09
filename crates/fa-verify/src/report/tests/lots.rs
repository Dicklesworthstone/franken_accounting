//! Independently encoded complete-prefix fixtures and hand-calculated lot
//! schedules. No production crate, stored applied mirror or lot engine is used.
use super::*;
use crate::report::{VerifiedLot, VerifiedLotAmount, VerifiedLotRelief, VerifiedLots};

const BASE: u32 = 1;
const QUANTITY: u32 = 10;

fn dated((mut record, identity): (Record, u128), day: i32) -> (Record, u128) {
    record.bytes[38..42].copy_from_slice(&day.to_le_bytes());
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&record.bytes[..record.len]]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    record.bytes[record.len..record.len + 32].copy_from_slice(&proposal);
    record.bytes[record.len + 32..].copy_from_slice(&digest);
    record.envelope =
        envelope_of_entry(&record.bytes, record.len, record.envelope.commit_seq, 0).unwrap();
    (record, identity)
}

fn chart() -> Vec<Record> {
    let mut body = Writer::default();
    body.count(2);
    for (code, name, kind, normal) in [("1000", "Inventory", 1, 0), ("3000", "Offset", 3, 1)] {
        body.bytes(code.as_bytes())
            .bytes(name.as_bytes())
            .u8(kind)
            .u8(normal)
            .u8(1)
            .fixed(&(-2i64).to_le_bytes())
            .u8(0);
    }
    vec![
        record(17, 1, 0, b"lots-chart", 0, Some((1, &body.buf)), None, None),
        schema().pop().unwrap(),
    ]
}

fn quantity(code: &'static str, debit: bool, amount: i128) -> InputLeg {
    let mut result = leg(code, debit, amount);
    result.unit = QUANTITY;
    result
}

fn acquisition(amount: i128, cost: i128) -> Vec<InputLeg> {
    vec![
        quantity("1000", true, amount),
        quantity("3000", false, amount),
        leg("1000", true, cost),
        leg("3000", false, cost),
    ]
}

fn target(record: &Record, identity: u128, ordinal: u16, unit: u32, amount: i128) -> SettlementRef {
    let mut result = application(record, identity, ordinal, amount);
    result.unit = unit;
    result
}

struct Fixture {
    records: Vec<Record>,
    first: u128,
    second: u128,
    dispose_first: u128,
    dispose_second: u128,
}

fn fixture() -> Fixture {
    let mut records = chart();
    let (first, first_id) = dated(
        posting(1, 3, b"lots-first", &acquisition(10, 100), None, None),
        10,
    );
    let (second, second_id) = dated(
        posting(1, 4, b"lots-second", &acquisition(10, 20), None, None),
        20,
    );
    let mut first_sale = vec![
        quantity("1000", false, 10),
        quantity("3000", true, 10),
        leg("1000", false, 60),
        leg("3000", true, 60),
    ];
    first_sale[0]
        .settles
        .push(target(&first, first_id, 0, QUANTITY, 10));
    first_sale[2]
        .settles
        .push(target(&first, first_id, 2, BASE, 60));
    let (sale, sale_id) = dated(
        posting(1, 5, b"lots-sale-first", &first_sale, None, None),
        30,
    );
    let mut second_sale = vec![
        quantity("1000", false, 10),
        quantity("3000", true, 10),
        leg("1000", false, 60),
        leg("3000", true, 60),
    ];
    second_sale[0]
        .settles
        .push(target(&second, second_id, 0, QUANTITY, 10));
    second_sale[2]
        .settles
        .push(target(&first, first_id, 2, BASE, 40));
    second_sale[2]
        .settles
        .push(target(&second, second_id, 2, BASE, 20));
    let (last_sale, last_id) = dated(
        posting(1, 6, b"lots-sale-second", &second_sale, None, None),
        40,
    );
    let (undo_last, _) = dated(
        reverse(&last_sale, last_id, 7, b"lots-undo-second", &second_sale),
        50,
    );
    let (undo_first, _) = dated(
        reverse(&sale, sale_id, 8, b"lots-undo-first", &first_sale),
        60,
    );
    records.extend([first, second, sale, last_sale, undo_last, undo_first]);
    Fixture {
        records,
        first: first_id,
        second: second_id,
        dispose_first: sale_id,
        dispose_second: last_id,
    }
}

fn account() -> VerifiedOpenItemAccount {
    let mut row = displayed("1000");
    row.name = "Inventory".into();
    row.unit_policy = OpenItemUnitPolicy::AnyUnit;
    row
}

fn source(items: Vec<VerifiedOpenItem>) -> VerifiedOpenItems {
    let row = account();
    let mut result = VerifiedOpenItems {
        account_filter: Some(row.account),
        accounts: BTreeMap::from([(row.account, row)]),
        items,
    };
    result
        .items
        .sort_by_key(|item| (item.account, item.recorded_at, item.entry, item.ordinal));
    result
}

fn selected_frontier(known_at: u64, cutoff: Option<i32>) -> u64 {
    let effective = match cutoff {
        None | Some(60..) => 8,
        Some(50..=59) => 7,
        Some(40..=49) => 6,
        Some(30..=39) => 5,
        Some(20..=29) => 4,
        Some(10..=19) => 3,
        Some(..=9) => 2,
    };
    known_at.min(effective)
}

fn history(
    entry: u128,
    ordinal: u16,
    amount: i128,
    recorded_at: u64,
    live: bool,
) -> VerifiedApplication {
    VerifiedApplication {
        entry,
        ordinal,
        amount,
        recorded_at,
        live,
    }
}

fn source_at(fixture: &Fixture, at: u64) -> VerifiedOpenItems {
    let first_live = (5..8).contains(&at);
    let second_live = at == 6;
    let mut items = Vec::new();
    if at >= 3 {
        let q_applied = if first_live { 10 } else { 0 };
        let c_applied = if first_live { 60 } else { 0 } + if second_live { 40 } else { 0 };
        let q_history = if at >= 5 {
            vec![history(fixture.dispose_first, 0, 10, 5, first_live)]
        } else {
            vec![]
        };
        let mut c_history = if at >= 5 {
            vec![history(fixture.dispose_first, 2, 60, 5, first_live)]
        } else {
            vec![]
        };
        if at >= 6 {
            c_history.push(history(fixture.dispose_second, 2, 40, 6, second_live));
        }
        let mut q = item(
            fixture.first,
            0,
            "1000",
            true,
            3,
            10,
            q_applied,
            0,
            10 - q_applied,
            q_history,
        );
        q.unit_id = QUANTITY;
        items.push(q);
        items.push(item(
            fixture.first,
            2,
            "1000",
            true,
            3,
            100,
            c_applied,
            0,
            100 - c_applied,
            c_history,
        ));
    }
    if at >= 4 {
        let q_applied = if second_live { 10 } else { 0 };
        let c_applied = if second_live { 20 } else { 0 };
        let q_history = if at >= 6 {
            vec![history(fixture.dispose_second, 0, 10, 6, second_live)]
        } else {
            vec![]
        };
        let c_history = if at >= 6 {
            vec![history(fixture.dispose_second, 2, 20, 6, second_live)]
        } else {
            vec![]
        };
        let mut q = item(
            fixture.second,
            0,
            "1000",
            true,
            4,
            10,
            q_applied,
            0,
            10 - q_applied,
            q_history,
        );
        q.unit_id = QUANTITY;
        q.effective_date = 20;
        items.push(q);
        let mut c = item(
            fixture.second,
            2,
            "1000",
            true,
            4,
            20,
            c_applied,
            0,
            20 - c_applied,
            c_history,
        );
        c.effective_date = 20;
        items.push(c);
    }
    for (id, live, seq, day) in [
        (fixture.dispose_first, first_live, 5, 30),
        (fixture.dispose_second, second_live, 6, 40),
    ] {
        if live {
            let mut q = item(id, 0, "1000", false, seq, 10, 0, 10, 0, vec![]);
            q.unit_id = QUANTITY;
            q.effective_date = day;
            let mut c = item(id, 2, "1000", false, seq, 60, 0, 60, 0, vec![]);
            c.effective_date = day;
            items.extend([q, c]);
        }
    }
    source(items)
}

fn amount(unit: u32, mantissa: i128) -> VerifiedLotAmount {
    VerifiedLotAmount { unit, mantissa }
}

fn expected(fixture: &Fixture, known_at: u64, cutoff: Option<i32>) -> VerifiedLots {
    let at = selected_frontier(known_at, cutoff);
    let first_live = (5..8).contains(&at);
    let second_live = at == 6;
    let mut lots = Vec::new();
    for (id, index, seq, day, original_cost, q_applied, c_applied) in [
        (
            fixture.first,
            2,
            3,
            10,
            100,
            if first_live { 10 } else { 0 },
            if first_live { 60 } else { 0 } + if second_live { 40 } else { 0 },
        ),
        (
            fixture.second,
            3,
            4,
            20,
            20,
            if second_live { 10 } else { 0 },
            if second_live { 20 } else { 0 },
        ),
    ] {
        if seq > at {
            continue;
        }
        let mut relieves = Vec::new();
        if seq == 3 && at >= 5 {
            relieves.push(VerifiedLotRelief {
                disposal_entry: fixture.dispose_first,
                qty_ordinal: Some(0),
                cost_ordinal: Some(2),
                quantity: amount(QUANTITY, 10),
                cost: amount(BASE, 60),
                recorded_at: 5,
                live: first_live,
            });
        }
        if at >= 6 {
            relieves.push(VerifiedLotRelief {
                disposal_entry: fixture.dispose_second,
                qty_ordinal: if seq == 3 { None } else { Some(0) },
                cost_ordinal: Some(2),
                quantity: amount(QUANTITY, if seq == 3 { 0 } else { 10 }),
                cost: amount(BASE, if seq == 3 { 40 } else { 20 }),
                recorded_at: 6,
                live: second_live,
            });
        }
        lots.push(VerifiedLot {
            entry: id,
            entry_digest: fixture.records[index].envelope.record_digest,
            qty_ordinal: 0,
            cost_ordinal: 2,
            account: account_id("1000"),
            dimensions: Vec::new(),
            debit: true,
            effective_date: day,
            recorded_at: seq,
            original_quantity: amount(QUANTITY, 10),
            relieved_quantity: amount(QUANTITY, q_applied),
            open_quantity: amount(QUANTITY, 10 - q_applied),
            original_cost: amount(BASE, original_cost),
            relieved_cost: amount(BASE, c_applied),
            open_cost: amount(BASE, original_cost - c_applied),
            relieves,
        });
    }
    VerifiedLots {
        book_id: BOOK,
        known_at,
        effective_through: cutoff,
        account: account_id("1000"),
        account_code: "1000".into(),
        account_name: "Inventory".into(),
        base_unit: BASE,
        dimensioned: false,
        source_certificate_digest: [0; 32],
        lots,
    }
}

fn output_bytes(report: &VerifiedLots) -> Vec<u8> {
    // This fixture encoder deliberately does not call the replay encoder.
    let mut out = Writer::default();
    out.bytes(if report.dimensioned {
        b"fa:lots:v2"
    } else {
        b"fa:lots:v1"
    })
    .fixed(&report.book_id)
    .u64(report.known_at)
    .u8(u8::from(report.effective_through.is_some()));
    if let Some(cutoff) = report.effective_through {
        out.i32(cutoff);
    }
    out.u128(report.account)
        .bytes(report.account_code.as_bytes())
        .bytes(report.account_name.as_bytes())
        .u32(report.base_unit)
        .count(report.lots.len());
    for lot in &report.lots {
        out.u128(lot.entry)
            .fixed(&lot.entry_digest)
            .u16(lot.qty_ordinal)
            .u16(lot.cost_ordinal)
            .u128(lot.account);
        if report.dimensioned {
            out.count(lot.dimensions.len());
            for (kind, value) in &lot.dimensions {
                out.u32(*kind).u128(*value);
            }
        }
        out.u8(u8::from(!lot.debit))
            .i32(lot.effective_date)
            .u64(lot.recorded_at);
        for value in [
            lot.original_quantity,
            lot.relieved_quantity,
            lot.open_quantity,
            lot.original_cost,
            lot.relieved_cost,
            lot.open_cost,
        ] {
            out.u32(value.unit).i128(value.mantissa);
        }
        out.count(lot.relieves.len());
        for edge in &lot.relieves {
            out.u128(edge.disposal_entry)
                .u8(u8::from(edge.qty_ordinal.is_some()));
            if let Some(ordinal) = edge.qty_ordinal {
                out.u16(ordinal);
            }
            out.u8(u8::from(edge.cost_ordinal.is_some()));
            if let Some(ordinal) = edge.cost_ordinal {
                out.u16(ordinal);
            }
            out.u32(edge.quantity.unit)
                .i128(edge.quantity.mantissa)
                .u32(edge.cost.unit)
                .i128(edge.cost.mantissa)
                .u64(edge.recorded_at)
                .u8(u8::from(edge.live));
        }
    }
    out.buf
}

fn wrap(native: &[u8], base_unit: u32, cutoff: Option<i32>, output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let dimensioned = Reader::new(output).bytes(64, "output format").unwrap() == b"fa:lots:v2";
    wrap_version(native, base_unit, cutoff, output, dimensioned)
}

fn wrap_version(
    native: &[u8],
    base_unit: u32,
    cutoff: Option<i32>,
    output: &[u8],
    dimensioned: bool,
) -> (Vec<u8>, [u8; 32]) {
    let mut r = Reader::new(native);
    assert_eq!(r.bytes(64, "format").unwrap(), REPORT_BUNDLE_FORMAT);
    assert_eq!(r.u16("major").unwrap(), 2);
    assert_eq!(r.u16("minor").unwrap(), 0);
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "source").unwrap();
    let remainder = &native[native.len() - r.remaining()..];
    let mut outer = Writer::default();
    outer
        .bytes(if dimensioned {
            b"fa:lots-certificate:v2"
        } else {
            b"fa:lots-certificate:v1"
        })
        .u128(PRINCIPAL)
        .fixed(&[7; 32])
        .bytes(source)
        .u32(base_unit)
        .u8(u8::from(cutoff.is_some()));
    if let Some(day) = cutoff {
        outer.i32(day);
    }
    outer.bytes(output);
    let digest = hash_parts(
        if dimensioned {
            b"fa:lots-certificate-digest:v2"
        } else {
            b"fa:lots-certificate-digest:v1"
        },
        &[&(outer.buf.len() as u32).to_le_bytes(), &outer.buf],
    );
    outer.fixed(&digest);
    let mut bundle = Writer::default();
    bundle
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(&outer.buf)
        .fixed(remainder);
    (bundle.buf, digest)
}

fn verify_lots(
    fixture: &Fixture,
    known_at: u64,
    cutoff: Option<i32>,
    expected: &VerifiedLots,
) -> Result<VerifiedReport, ReportError> {
    let (native, anchor, _) = pack(&fixture.records, known_at, &source_at(fixture, known_at));
    let (bundle, pin) = wrap(&native, BASE, cutoff, &output_bytes(expected));
    verify_report_with_lots_input(
        &bundle,
        &[],
        None,
        None,
        Some(&pin),
        None,
        Some(BASE),
        |_, _| Ok(anchor),
    )
}

#[test]
fn portable_lots_reconstruct_pooled_cost_only_layers_and_exact_reversal_history() {
    let fixture = fixture();
    for (known_at, expected_costs, expected_quantities) in [
        (4, [100, 20], [10, 10]),
        (5, [40, 20], [0, 10]),
        (6, [0, 0], [0, 0]),
        (7, [40, 20], [0, 10]),
        (8, [100, 20], [10, 10]),
    ] {
        let expected = expected(&fixture, known_at, None);
        let verified = verify_lots(&fixture, known_at, None, &expected).unwrap();
        let actual = verified.lots.as_ref().unwrap();
        assert_eq!(actual.lots, expected.lots, "known_at={known_at}");
        assert_eq!(
            actual
                .lots
                .iter()
                .map(|lot| lot.open_cost.mantissa)
                .collect::<Vec<_>>(),
            expected_costs
        );
        assert_eq!(
            actual
                .lots
                .iter()
                .map(|lot| lot.open_quantity.mantissa)
                .collect::<Vec<_>>(),
            expected_quantities
        );
        assert_eq!(verified.output, output_bytes(&expected));
        assert!(verified.open_items.is_none());
        if known_at >= 6 {
            let edge = actual.lots[0].relieves.last().unwrap();
            assert_eq!(
                (edge.qty_ordinal, edge.quantity.mantissa, edge.cost.mantissa),
                (None, 0, 40)
            );
            assert_eq!(edge.live, known_at == 6);
        }
    }
}

#[test]
fn portable_lot_cutoffs_reselect_before_application_netting_and_keep_empty_account_metadata() {
    let fixture = fixture();
    for cutoff in [0, 15, 25, 35, 45, 55, 65] {
        let expected = expected(&fixture, 8, Some(cutoff));
        let verified = verify_lots(&fixture, 8, Some(cutoff), &expected).unwrap();
        let actual = verified.lots.unwrap();
        assert_eq!(actual.lots, expected.lots, "cutoff={cutoff}");
        assert_eq!(actual.account_code, "1000");
        assert_eq!(actual.base_unit, BASE);
        if cutoff == 0 {
            assert!(actual.lots.is_empty());
        }
    }
    let empty = expected(&fixture, 2, None);
    assert!(
        verify_lots(&fixture, 2, None, &empty)
            .unwrap()
            .lots
            .unwrap()
            .lots
            .is_empty()
    );
}

#[test]
fn resealed_lot_row_amount_digest_ordinal_and_relief_omissions_fail_recomputation() {
    let fixture = fixture();
    let original = expected(&fixture, 7, None);
    type Mutation = fn(&mut VerifiedLots);
    let mutations: [(&str, Mutation); 10] = [
        ("missing layer", |report| {
            report.lots.pop();
        }),
        ("missing relief", |report| {
            report.lots[0].relieves.pop();
        }),
        ("cost changed", |report| {
            report.lots[0].open_cost.mantissa += 1;
        }),
        ("quantity changed", |report| {
            report.lots[1].open_quantity.mantissa += 1;
        }),
        ("digest changed", |report| {
            report.lots[0].entry_digest[0] ^= 1;
        }),
        ("ordinal changed", |report| {
            report.lots[0].cost_ordinal += 1;
        }),
        ("undone made live", |report| {
            report.lots[0].relieves[1].live = true;
        }),
        ("wrong account", |report| {
            report.account += 1;
        }),
        ("wrong prefix", |report| {
            report.known_at -= 1;
        }),
        ("wrong cutoff", |report| {
            report.effective_through = Some(20);
        }),
    ];
    for (name, mutate) in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert_eq!(
            verify_lots(&fixture, 7, None, &changed)
                .expect_err(name)
                .predicate,
            "lots_recomputation",
            "{name}"
        );
    }
}

#[test]
fn lot_base_unit_must_be_recipient_selected_and_cannot_be_supplied_to_another_family() {
    let fixture = fixture();
    let (native, anchor, native_pin) = pack(&fixture.records, 5, &source_at(&fixture, 5));
    let (bundle, pin) = wrap(
        &native,
        BASE,
        None,
        &output_bytes(&expected(&fixture, 5, None)),
    );
    let without = verify_report_with(&bundle, &[], None, None, Some(&pin), |_, _| {
        Ok(anchor.clone())
    })
    .unwrap_err();
    assert_eq!(without.predicate, "lots_base_unit");
    let wrong = verify_report_with_lots_input(
        &bundle,
        &[],
        None,
        None,
        Some(&pin),
        None,
        Some(0),
        |_, _| Ok(anchor.clone()),
    )
    .unwrap_err();
    assert_eq!(wrong.predicate, "lots_base_unit");
    let misplaced = verify_report_with_lots_input(
        &native,
        &[],
        None,
        None,
        Some(&native_pin),
        None,
        Some(BASE),
        |_, _| Ok(anchor.clone()),
    )
    .unwrap_err();
    assert_eq!(misplaced.predicate, "lots_base_unit");
    let no_trust =
        verify_report_with_lots_input(&bundle, &[], None, None, None, None, Some(BASE), |_, _| {
            Ok(anchor)
        })
        .unwrap_err();
    assert_eq!(no_trust.predicate, "report_input_authority");
}

#[test]
fn lot_certificate_rejects_trailing_bytes_and_a_false_outer_commitment() {
    let fixture = fixture();
    let (native, _, _) = pack(&fixture.records, 5, &source_at(&fixture, 5));
    let (bundle, _) = wrap(
        &native,
        BASE,
        None,
        &output_bytes(&expected(&fixture, 5, None)),
    );
    let mut reader = Reader::new(&bundle);
    reader.bytes(64, "format").unwrap();
    reader.u16("major").unwrap();
    reader.u16("minor").unwrap();
    let original = reader
        .bytes(MAX_REPORT_BUNDLE_BYTES, "certificate")
        .unwrap();
    let mut bytes = original.to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        crate::report::lots::decode(&bytes).err().unwrap().predicate,
        "certificate_digest"
    );
    bytes = original.to_vec();
    bytes.push(0);
    assert_eq!(
        crate::report::lots::decode(&bytes).err().unwrap().predicate,
        "canonical_encoding"
    );
    for length in [0, 3, 4, 20, original.len() - 1] {
        assert!(crate::report::lots::decode(&original[..length]).is_err());
    }
}

fn empty(known_at: u64, cutoff: Option<i32>) -> VerifiedLots {
    VerifiedLots {
        book_id: BOOK,
        known_at,
        effective_through: cutoff,
        account: account_id("1000"),
        account_code: "1000".into(),
        account_name: "Inventory".into(),
        base_unit: BASE,
        dimensioned: false,
        source_certificate_digest: [0; 32],
        lots: vec![],
    }
}

fn custom(
    records: &[Record],
    native_output: &VerifiedOpenItems,
    expected: &VerifiedLots,
    base: u32,
) -> Result<VerifiedReport, ReportError> {
    let (native, anchor, _) = pack(records, expected.known_at, native_output);
    let (bundle, pin) = wrap(
        &native,
        base,
        expected.effective_through,
        &output_bytes(expected),
    );
    verify_report_with_lots_input(
        &bundle,
        &[],
        None,
        None,
        Some(&pin),
        None,
        Some(base),
        |_, _| Ok(anchor),
    )
}

#[test]
fn bare_cost_acquisitions_and_partly_applied_credits_cannot_disappear_from_certified_lots() {
    let mut records = chart();
    let (cost, cost_id) = posting(
        1,
        3,
        b"bare-cost",
        &[leg("1000", true, 100), leg("3000", false, 100)],
        None,
        None,
    );
    records.push(cost);
    let native = source(vec![item(
        cost_id,
        0,
        "1000",
        true,
        3,
        100,
        0,
        0,
        100,
        vec![],
    )]);
    assert_eq!(
        custom(&records, &native, &empty(3, None), BASE)
            .unwrap_err()
            .predicate,
        "lots_profile"
    );

    let mut records = chart();
    let (purchase, purchase_id) = posting(
        1,
        3,
        b"partial-credit-purchase",
        &acquisition(10, 100),
        None,
        None,
    );
    let mut disposal = vec![leg("1000", false, 50), leg("3000", true, 50)];
    disposal[0]
        .settles
        .push(target(&purchase, purchase_id, 2, BASE, 40));
    let (credit, credit_id) = posting(1, 4, b"partial-credit", &disposal, None, None);
    records.extend([purchase, credit]);
    let mut q = item(purchase_id, 0, "1000", true, 3, 10, 0, 0, 10, vec![]);
    q.unit_id = QUANTITY;
    let native = source(vec![
        q,
        item(
            purchase_id,
            2,
            "1000",
            true,
            3,
            100,
            40,
            0,
            60,
            vec![history(credit_id, 0, 40, 4, true)],
        ),
        item(credit_id, 0, "1000", false, 4, 50, 0, 40, 10, vec![]),
    ]);
    assert_eq!(
        custom(&records, &native, &empty(4, None), BASE)
            .unwrap_err()
            .predicate,
        "lots_profile"
    );
}

#[test]
fn unpaired_dimension_history_and_ineligible_units_are_refused_even_before_effective_cutoff() {
    for (unit, dimensions) in [(2, false), (11, false), (QUANTITY, true)] {
        let mut records = chart();
        let mut legs = acquisition(10, 100);
        legs[0].unit = unit;
        legs[1].unit = unit;
        if dimensions {
            legs[0].dimensions.push((1, 999));
        }
        let (purchase, id) = dated(posting(1, 3, b"profile-purchase", &legs, None, None), 50);
        records.push(purchase);
        let mut q = item(id, 0, "1000", true, 3, 10, 0, 0, 10, vec![]);
        q.unit_id = unit;
        q.effective_date = 50;
        let mut c = item(id, 2, "1000", true, 3, 100, 0, 0, 100, vec![]);
        c.effective_date = 50;
        let native = source(vec![q, c]);
        let error = custom(&records, &native, &empty(3, Some(0)), BASE).unwrap_err();
        assert_eq!(
            error.predicate, "lots_profile",
            "unit={unit} dimensions={dimensions}: {error}"
        );
    }
}

#[test]
fn a_quantity_unit_cannot_be_declared_the_cost_base_even_with_a_recipient_pin() {
    let fixture = fixture();
    let (native, anchor, _) = pack(&fixture.records, 5, &source_at(&fixture, 5));
    let (bundle, pin) = wrap(
        &native,
        QUANTITY,
        None,
        &output_bytes(&expected(&fixture, 5, None)),
    );
    let error = verify_report_with_lots_input(
        &bundle,
        &[],
        None,
        None,
        Some(&pin),
        None,
        Some(QUANTITY),
        |_, _| Ok(anchor),
    )
    .unwrap_err();
    assert_eq!(error.predicate, "lots_profile");
}

#[test]
fn dimensions_on_another_account_do_not_narrow_the_selected_native_lot_profile() {
    let mut records = chart();
    let mut legs = acquisition(10, 100);
    legs[1].dimensions.push((1, 999));
    let (purchase, id) = posting(1, 3, b"other-account-dimensions", &legs, None, None);
    let digest = purchase.envelope.record_digest;
    records.push(purchase);
    let mut q = item(id, 0, "1000", true, 3, 10, 0, 0, 10, vec![]);
    q.unit_id = QUANTITY;
    let native = source(vec![
        q,
        item(id, 2, "1000", true, 3, 100, 0, 0, 100, vec![]),
    ]);
    let mut expected = empty(3, None);
    expected.lots.push(VerifiedLot {
        entry: id,
        entry_digest: digest,
        qty_ordinal: 0,
        cost_ordinal: 2,
        account: account_id("1000"),
        dimensions: Vec::new(),
        debit: true,
        effective_date: 10,
        recorded_at: 3,
        original_quantity: amount(QUANTITY, 10),
        relieved_quantity: amount(QUANTITY, 0),
        open_quantity: amount(QUANTITY, 10),
        original_cost: amount(BASE, 100),
        relieved_cost: amount(BASE, 0),
        open_cost: amount(BASE, 100),
        relieves: vec![],
    });
    assert_eq!(
        custom(&records, &native, &expected, BASE)
            .unwrap()
            .lots
            .unwrap()
            .lots,
        expected.lots
    );
}

const PARTITION_A: &[(u32, u128)] = &[(2, 101), (4, 401)];
const PARTITION_B: &[(u32, u128)] = &[(2, 101), (4, 402)];

struct PartitionFixture {
    records: Vec<Record>,
    acquisition: u128,
    disposal: u128,
}

fn partition_fixture() -> PartitionFixture {
    let mut records = chart();
    let mut legs = Vec::new();
    // Cost ordinals deliberately interleave the two partitions. A partial
    // cost-center match would wrongly pair quantity ordinal 0 with cost 6.
    for (unit, value, dimensions) in [
        (QUANTITY, 2, PARTITION_A),
        (QUANTITY, 3, PARTITION_B),
        (QUANTITY, 4, PARTITION_A),
        (BASE, 900, PARTITION_B),
        (BASE, 100, PARTITION_A),
        (BASE, 400, PARTITION_A),
    ] {
        for (code, debit) in [("1000", true), ("3000", false)] {
            let mut value_leg = leg(code, debit, value);
            value_leg.unit = unit;
            value_leg.dimensions = dimensions.to_vec();
            legs.push(value_leg);
        }
    }
    let (purchase, acquisition) = posting(1, 3, b"partition-purchase", &legs, None, None);
    let mut disposal_legs = vec![
        quantity("1000", false, 2),
        quantity("3000", true, 2),
        leg("1000", false, 100),
        leg("3000", true, 100),
    ];
    for leg in &mut disposal_legs {
        leg.dimensions = PARTITION_A.to_vec();
    }
    disposal_legs[0]
        .settles
        .push(target(&purchase, acquisition, 0, QUANTITY, 2));
    disposal_legs[2]
        .settles
        .push(target(&purchase, acquisition, 8, BASE, 100));
    let (sale, disposal) = dated(
        posting(1, 4, b"partition-sale", &disposal_legs, None, None),
        20,
    );
    let (undo, _) = dated(
        reverse(&sale, disposal, 5, b"partition-undo", &disposal_legs),
        30,
    );
    records.extend([purchase, sale, undo]);
    PartitionFixture {
        records,
        acquisition,
        disposal,
    }
}

fn partition_source(fixture: &PartitionFixture, known_at: u64) -> VerifiedOpenItems {
    let mut items = Vec::new();
    if known_at >= 3 {
        for (ordinal, unit, original, disposal_ordinal) in [
            (0, QUANTITY, 2, Some(0)),
            (2, QUANTITY, 3, None),
            (4, QUANTITY, 4, None),
            (6, BASE, 900, None),
            (8, BASE, 100, Some(2)),
            (10, BASE, 400, None),
        ] {
            let applied = if known_at == 4 && disposal_ordinal.is_some() {
                original
            } else {
                0
            };
            let applications = match (known_at >= 4, disposal_ordinal) {
                (true, Some(ordinal)) => {
                    vec![history(
                        fixture.disposal,
                        ordinal,
                        original,
                        4,
                        known_at == 4,
                    )]
                }
                _ => Vec::new(),
            };
            let mut value = item(
                fixture.acquisition,
                ordinal,
                "1000",
                true,
                3,
                original,
                applied,
                0,
                original - applied,
                applications,
            );
            value.unit_id = unit;
            items.push(value);
        }
    }
    if known_at == 4 {
        for (ordinal, unit, original) in [(0, QUANTITY, 2), (2, BASE, 100)] {
            let mut value = item(
                fixture.disposal,
                ordinal,
                "1000",
                false,
                4,
                original,
                0,
                original,
                0,
                vec![],
            );
            value.unit_id = unit;
            value.effective_date = 20;
            items.push(value);
        }
    }
    source(items)
}

fn partition_expected(
    fixture: &PartitionFixture,
    known_at: u64,
    cutoff: Option<i32>,
) -> VerifiedLots {
    let mut report = empty(known_at, cutoff);
    report.dimensioned = known_at >= 3;
    let effective = match cutoff {
        None | Some(30..) => 5,
        Some(20..=29) => 4,
        Some(10..=19) => 3,
        Some(..=9) => 2,
    };
    let selected = known_at.min(effective);
    if selected < 3 {
        return report;
    }
    for (qty_ordinal, cost_ordinal, quantity, cost, dimensions) in [
        (0, 8, 2, 100, PARTITION_A),
        (2, 6, 3, 900, PARTITION_B),
        (4, 10, 4, 400, PARTITION_A),
    ] {
        let applied = qty_ordinal == 0 && selected == 4;
        report.lots.push(VerifiedLot {
            entry: fixture.acquisition,
            entry_digest: fixture.records[2].envelope.record_digest,
            qty_ordinal,
            cost_ordinal,
            account: account_id("1000"),
            dimensions: dimensions.to_vec(),
            debit: true,
            effective_date: 10,
            recorded_at: 3,
            original_quantity: amount(QUANTITY, quantity),
            relieved_quantity: amount(QUANTITY, if applied { quantity } else { 0 }),
            open_quantity: amount(QUANTITY, if applied { 0 } else { quantity }),
            original_cost: amount(BASE, cost),
            relieved_cost: amount(BASE, if applied { cost } else { 0 }),
            open_cost: amount(BASE, if applied { 0 } else { cost }),
            relieves: if qty_ordinal == 0 && selected >= 4 {
                vec![VerifiedLotRelief {
                    disposal_entry: fixture.disposal,
                    qty_ordinal: Some(0),
                    cost_ordinal: Some(2),
                    quantity: amount(QUANTITY, 2),
                    cost: amount(BASE, 100),
                    recorded_at: 4,
                    live: applied,
                }]
            } else {
                Vec::new()
            },
        });
    }
    report
}

#[test]
fn dimensioned_lots_pair_exact_full_sets_and_restore_reliefs_before_cutoff() {
    let fixture = partition_fixture();
    for known_at in 2..=5 {
        for cutoff in [None, Some(0), Some(15), Some(25), Some(35)] {
            let expected = partition_expected(&fixture, known_at, cutoff);
            let verified = custom(
                &fixture.records,
                &partition_source(&fixture, known_at),
                &expected,
                BASE,
            )
            .unwrap_or_else(|error| panic!("known_at={known_at} cutoff={cutoff:?}: {error}"));
            assert_eq!(verified.output, output_bytes(&expected));
            let actual = verified.lots.unwrap();
            assert_eq!(actual.dimensioned, known_at >= 3);
            assert_eq!(actual.lots, expected.lots);
            if known_at >= 3 && cutoff == Some(0) {
                assert!(actual.lots.is_empty());
                assert!(actual.dimensioned, "empty cutoff retains the v2 scope");
            }
        }
    }
}

#[test]
fn resealed_dimension_sets_and_pairing_cannot_reassign_lot_costs() {
    let fixture = partition_fixture();
    let expected = partition_expected(&fixture, 5, None);
    type Mutation = fn(&mut VerifiedLots);
    let changes: [(&str, Mutation); 7] = [
        ("missing dimension", |value| {
            value.lots[0].dimensions.pop();
        }),
        ("other project", |value| {
            value.lots[0].dimensions[1].1 = PARTITION_B[1].1;
        }),
        ("erased partition", |value| {
            value.lots[0].dimensions.clear();
        }),
        ("noncanonical order", |value| {
            value.lots[0].dimensions.reverse();
        }),
        ("other partition cost", |value| {
            value.lots[0].cost_ordinal = 6;
            value.lots[0].original_cost.mantissa = 900;
            value.lots[0].open_cost.mantissa = 900;
        }),
        ("missing paired layer", |value| {
            value.lots.pop();
        }),
        ("restoration erased", |value| {
            value.lots[0].relieves[0].live = true;
        }),
    ];
    for (name, mutate) in changes {
        let mut forged = expected.clone();
        mutate(&mut forged);
        assert_eq!(
            custom(
                &fixture.records,
                &partition_source(&fixture, 5),
                &forged,
                BASE
            )
            .expect_err(name)
            .predicate,
            "lots_recomputation",
            "{name}"
        );
    }
    for (known_at, dimensioned) in [(2, true), (5, false)] {
        let mut wrong_version = partition_expected(&fixture, known_at, Some(0));
        wrong_version.dimensioned = dimensioned;
        assert_eq!(
            custom(
                &fixture.records,
                &partition_source(&fixture, known_at),
                &wrong_version,
                BASE,
            )
            .unwrap_err()
            .predicate,
            "lots_profile",
            "version is derived from history even when no output row survives"
        );
    }
}

#[test]
fn dimensioned_lot_application_cannot_consume_another_complete_partition() {
    let fixture = partition_fixture();
    let purchase = &fixture.records[2];
    let mut legs = vec![
        quantity("1000", false, 2),
        quantity("3000", true, 2),
        leg("1000", false, 100),
        leg("3000", true, 100),
    ];
    for leg in &mut legs {
        leg.dimensions = PARTITION_B.to_vec();
    }
    legs[0]
        .settles
        .push(target(purchase, fixture.acquisition, 0, QUANTITY, 2));
    legs[2]
        .settles
        .push(target(purchase, fixture.acquisition, 8, BASE, 100));
    let (forged, _) = posting(1, 4, b"cross-partition-disposal", &legs, None, None);
    let mut records = fixture.records;
    records.truncate(3);
    records.push(forged);
    let mut expected = empty(4, Some(0));
    expected.dimensioned = true;
    assert_eq!(
        custom(&records, &source(vec![]), &expected, BASE)
            .unwrap_err()
            .predicate,
        "application_target",
        "a repaired prefix and an empty cutoff cannot conceal cross-partition relief"
    );
}
