//! Literal invoice/collection/depreciation/debt/capex workpapers. The fixture
//! wire encoders and expected earnings are independent of the verifier folds.
use super::*;

type Adjustment = ([u8; 32], u32, u8, u8, String);
type Contribution = ([u8; 32], u32, u128, u32, i128);

const CHART: &[(&str, &str, u8)] = &[
    ("1000", "Cash", 1),
    ("1200", "Receivables", 1),
    ("2000", "Debt", 2),
    ("3000", "Equity", 3),
    ("4000", "Revenue", 4),
    ("5000", "Equipment", 1),
    ("7000", "Expense", 5),
];

struct Inputs {
    f: Fixture,
    detail: VerifiedRollForward,
    adjustments: Vec<Adjustment>,
    contributions: Vec<Contribution>,
    cash_units: Vec<Unit>,
    unit: [i128; 13],
}

fn input(kind: u8, closing: u8) -> Inputs {
    let mut records = schema();
    records[0] = record(
        17,
        1,
        0,
        b"indirect-chart",
        0,
        Some((1, &chart_body_with_unit_policy(CHART, -1))),
        None,
        None,
    );
    let mut inputs = vec![
        (
            3u64,
            5,
            1,
            vec![leg("1200", true, 300), leg("4000", false, 300)],
        ),
        (
            4,
            10,
            1,
            vec![leg("1000", true, 200), leg("1200", false, 200)],
        ),
        (
            5,
            15,
            1,
            vec![leg("7000", true, 30), leg("5000", false, 30)],
        ),
        (
            6,
            20,
            1,
            vec![
                leg("2000", true, 50),
                leg("7000", true, 10),
                leg("1000", false, 60),
            ],
        ),
        (
            7,
            25,
            1,
            vec![leg("5000", true, 80), leg("1000", false, 80)],
        ),
    ];
    if closing > 0 {
        inputs.push((
            8,
            30,
            8,
            vec![
                leg("4000", true, 300),
                leg("7000", false, 40),
                leg("3000", false, 260),
            ],
        ));
    }
    if closing > 1 {
        inputs.push((
            9,
            30,
            4,
            vec![
                leg("4000", false, 300),
                leg("7000", true, 40),
                leg("3000", true, 260),
            ],
        ));
    }
    let known_at = inputs.last().unwrap().0;
    let mut target = None;
    for (seq, day, class, legs) in &inputs {
        let reversed = if *class == 4 {
            target.map(|(id, digest)| (id, digest, 1))
        } else {
            None
        };
        let (entry, id) = dated(
            posting(*class, *seq, &seq.to_le_bytes(), legs, reversed, None),
            *day,
        );
        if *class == 8 {
            target = Some((id, entry.envelope.record_digest));
        }
        records.push(entry);
    }
    // The signed checkpoint covers a later backdated sale. Historical earnings
    // and both ledgers must still use the earlier requested prefix.
    records.push(
        dated(
            posting(
                1,
                known_at + 1,
                b"later-backdated",
                &[leg("1000", true, 99), leg("4000", false, 99)],
                None,
                None,
            ),
            12,
        )
        .0,
    );
    let mut gross: BTreeMap<&str, [i128; 2]> = BTreeMap::new();
    for (_, _, _, legs) in &inputs {
        for leg in legs {
            gross.entry(leg.code).or_default()[usize::from(!leg.debit)] += leg.amount;
        }
    }
    let rows: Vec<_> = gross
        .iter()
        .map(|(&code, amount)| {
            let (_, name, typ) = CHART.iter().find(|a| a.0 == code).unwrap();
            ReportRow {
                account: account_id(code),
                code: code.into(),
                name: (*name).into(),
                account_type: *typ,
                unit: 1,
                debits: amount[0],
                credits: amount[1],
                debits_pending: 0,
                credits_pending: 0,
            }
        })
        .collect();
    let (native, anchor, digest) = source_bundle(&records, known_at, 30, &rows, &[]);
    let lead = |cash: bool| {
        let accounts: Vec<_> = CHART
            .iter()
            .filter(|a| (a.0 == "1000") == cash)
            .map(|(code, name, typ)| RollForwardAccount {
                id: account_id(code),
                code: (*code).into(),
                name: (*name).into(),
                account_type: *typ,
                is_leaf: true,
            })
            .collect();
        let mut movements = Vec::new();
        let mut buckets = BTreeSet::new();
        for (entry, (_, _, class, legs)) in records[2..].iter().zip(&inputs) {
            let bucket = classification(
                *class,
                if *class == 4 { "supersession:1" } else { "" },
                None,
            );
            for (index, leg) in legs
                .iter()
                .enumerate()
                .filter(|(_, leg)| (leg.code == "1000") == cash)
            {
                buckets.insert(bucket.clone());
                movements.push(movement(
                    entry,
                    index as u32,
                    leg.code,
                    leg.debit,
                    leg.amount,
                    &bucket,
                ));
            }
        }
        let buckets: Vec<_> = buckets.into_iter().collect();
        let mut rows = Vec::new();
        for account in &accounts {
            for unit_id in [0, 1] {
                let activity: Vec<i128> = buckets
                    .iter()
                    .map(|bucket| {
                        movements
                            .iter()
                            .filter(|m| {
                                m.account_id == account.id
                                    && m.unit_id == unit_id
                                    && &m.bucket == bucket
                            })
                            .map(|m| m.debits - m.credits)
                            .sum()
                    })
                    .collect();
                let net_change = activity.iter().sum();
                rows.push(RollForwardRow {
                    account_id: account.id,
                    unit_id,
                    opening: 0,
                    activity,
                    net_change,
                    closing: net_change,
                });
            }
        }
        VerifiedRollForward {
            book_id: BOOK,
            known_at,
            label: "March cash workpaper".into(),
            effective_from: 0,
            effective_through: 30,
            source_certificate_digest: digest,
            accounts,
            units: vec![0, 1],
            buckets,
            rows,
            movements,
        }
    };
    let roll = lead(true);
    let detail = lead(false);
    let mut assignments: Vec<_> = roll
        .movements
        .iter()
        .map(|m| {
            (
                m.entry_digest,
                m.leg_index,
                match m.recorded_seq {
                    4 => 0,
                    6 => 2,
                    7 => 1,
                    _ => unreachable!(),
                },
            )
        })
        .collect();
    assignments.sort_unstable();
    let definition = Definition {
        name: "Cash classifications".into(),
        accounts: vec![account_id("1000")],
        assignments,
    };
    let mut rules = vec![
        (account_id("1200"), 0),
        (account_id("2000"), 2),
        (account_id("5000"), 1),
        (account_id("7000"), 0),
    ];
    rules.sort_unstable();
    let override_leg = definition
        .assignments
        .iter()
        .find(|a| a.0 == records[5].envelope.record_digest)
        .unwrap();
    let policy = Policy {
        name: definition.name.clone(),
        accounts: definition.accounts.clone(),
        rules,
        overrides: vec![*override_leg],
    };
    let decisions = definition
        .assignments
        .iter()
        .map(|&(d, i, a)| (d, i, a, u8::from(d == override_leg.0)))
        .collect();
    let mut adjustments = vec![
        (
            records[2].envelope.record_digest,
            0,
            1,
            1,
            "Increase in receivables".into(),
        ),
        (
            records[3].envelope.record_digest,
            1,
            1,
            1,
            "Collections reduce receivables".into(),
        ),
        (
            records[4].envelope.record_digest,
            0,
            0,
            0,
            "Non-cash depreciation expense".into(),
        ),
    ];
    if kind != 2 {
        adjustments.push((
            records[5].envelope.record_digest,
            1,
            2,
            0,
            "Interest classified in financing".into(),
        ));
    }
    adjustments.sort_by_key(|a| (a.0, a.1));
    let contributions = adjustments
        .iter()
        .map(|a| {
            let m = detail
                .movements
                .iter()
                .find(|m| m.entry_digest == a.0 && m.leg_index == a.1)
                .unwrap();
            let amount = if a.3 == 0 {
                m.debits - m.credits
            } else {
                m.credits - m.debits
            };
            (a.0, a.1, m.account_id, m.unit_id, amount)
        })
        .collect();
    let (operating, financing, non_operating) = if kind == 2 {
        (190, -50, 0)
    } else {
        (200, -60, 10)
    };
    let cash_units = vec![
        (0, 0, [[0; 3]; 4], 0, 0),
        (
            1,
            0,
            [
                [200, 200 - operating, operating],
                [0, 80, -80],
                [0, -financing, financing],
                [0; 3],
            ],
            60,
            60,
        ),
    ];
    Inputs {
        f: Fixture {
            native,
            anchor,
            roll,
            definition,
            policy,
            decisions,
        },
        detail,
        adjustments,
        contributions,
        cash_units,
        unit: [
            260,
            30,
            -100,
            non_operating,
            operating,
            operating,
            0,
            0,
            -80,
            financing,
            0,
            60,
            60,
        ],
    }
}

fn income_bytes(inputs: &Inputs) -> Vec<u8> {
    let text: Vec<_> = include_str!("income-statement.hex")
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let definition: Vec<_> = text
        .as_chunks::<2>()
        .0
        .iter()
        .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
        .collect();
    let digest = hash_parts(
        b"fa:statement-definition:v1",
        &[&(definition.len() as u32).to_le_bytes(), &definition],
    );
    let mut w = Writer::default();
    w.fixed(b"FA-STATEMENT\0")
        .u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(inputs.f.roll.known_at)
        .bytes(b"income-statement")
        .u32(1)
        .fixed(&digest)
        .bytes(&definition)
        .count(1)
        .bytes(b"current")
        .count(1)
        .bytes(b"P1")
        .u8(1)
        .i32(0)
        .i32(30)
        .count(39);
    for (code, label, amount) in [
        ("revenue", "Revenue", 300),
        ("expense", "Expenses", 40),
        ("net_income", "Net income", 260),
    ] {
        // The four authenticated registry documents declare thirteen units.
        // Income retains all of them, even though cash selects only 0 and 1.
        for unit in 0..13 {
            w.bytes(code.as_bytes())
                .bytes(label.as_bytes())
                .u32(unit)
                .count(1)
                .i128(if unit == 1 { amount } else { 0 });
        }
    }
    w.count(2);
    for (code, name, typ, line) in [
        ("4000", "Revenue", 4, "revenue"),
        ("7000", "Expense", 5, "expense"),
    ] {
        w.u128(account_id(code))
            .bytes(code.as_bytes())
            .bytes(name.as_bytes())
            .u8(typ)
            .u8(1)
            .bytes(line.as_bytes());
    }
    w.buf
}

fn write_adjustments(w: &mut Writer, name: &str, adjustments: &[Adjustment]) {
    w.bytes(name.as_bytes()).count(adjustments.len());
    for (digest, leg, category, sign, reason) in adjustments {
        w.fixed(digest)
            .u32(*leg)
            .u8(*category)
            .u8(*sign)
            .bytes(reason.as_bytes());
    }
}

fn source(inputs: &Inputs, kind: u8) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    if kind == 0 {
        let (bundle, pin, output, _) = direct(&inputs.f, &inputs.f.definition, &inputs.cash_units);
        return (bundle, output, pin);
    }
    if kind == 1 {
        let (bundle, pin, output, _) = policy_bundle(
            &inputs.f,
            &inputs.f.definition,
            &inputs.f.policy,
            &inputs.f.decisions,
            &inputs.cash_units,
        );
        return (bundle, output, pin);
    }
    let (roll_bundle, _) = wrap(&inputs.f.native, &inputs.f.roll);
    let mut definition = Writer::default();
    definition
        .bytes(b"fa:cash-flow-split-definition:v1")
        .bytes(b"Cash classifications")
        .count(1)
        .u128(account_id("1000"))
        .count(inputs.f.definition.assignments.len());
    for (digest, index, activity) in &inputs.f.definition.assignments {
        let m = inputs
            .f
            .roll
            .movements
            .iter()
            .find(|m| &m.entry_digest == digest && m.leg_index == *index)
            .unwrap();
        definition
            .fixed(digest)
            .u32(*index)
            .bytes(b"Original cash documentation");
        if *activity == 2 {
            definition.count(2).u8(0).i128(10).u8(2).i128(50);
        } else {
            definition
                .count(1)
                .u8(*activity)
                .i128(m.debits.max(m.credits));
        }
    }
    let mut output = Writer::default();
    output
        .bytes(b"fa:cash-flow-split:v1")
        .bytes(&ledger_bytes(&inputs.f.roll))
        .bytes(&definition.buf)
        .count(inputs.cash_units.len());
    for (unit, opening, sections, change, closing) in &inputs.cash_units {
        output.u32(*unit).i128(*opening);
        for section in sections {
            for amount in section {
                output.i128(*amount);
            }
        }
        output.i128(*change).i128(*closing);
    }
    let mut outer = Writer::default();
    outer
        .bytes(b"fa:cash-flow-split-certificate:v1")
        .bytes(certificate(&roll_bundle))
        .bytes(&definition.buf)
        .bytes(&output.buf);
    let (outer, pin) = sealed(outer, b"fa:cash-flow-split-certificate-digest:v1");
    (replace_certificate(&roll_bundle, &outer), output.buf, pin)
}

fn indirect_output(
    inputs: &Inputs,
    kind: u8,
    cash: &[u8],
    income: &[u8],
    detail: &[u8],
    adjustments: &[Adjustment],
) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(if kind == 0 {
        b"fa:indirect-cash-flow:v1"
    } else {
        b"fa:indirect-cash-flow:v2"
    });
    if kind != 0 {
        w.u8(kind);
    }
    w.bytes(cash).bytes(income).u8(1).bytes(detail);
    write_adjustments(&mut w, "Earnings to operating cash", adjustments);
    w.count(inputs.contributions.len());
    for (digest, leg, account, unit, amount) in &inputs.contributions {
        w.fixed(digest)
            .u32(*leg)
            .u128(*account)
            .u32(*unit)
            .i128(*amount);
    }
    w.count(2);
    for unit in [0, 1] {
        w.u32(unit);
        for amount in inputs.unit {
            w.i128(if unit == 0 { 0 } else { amount });
        }
    }
    w.buf
}

fn indirect_certificate(
    kind: u8,
    source: &[u8],
    periods: &[&str],
    adjustments: &[Adjustment],
    output: &[u8],
) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    w.bytes(if kind == 0 {
        b"fa:indirect-cash-flow-certificate:v1"
    } else {
        b"fa:indirect-cash-flow-certificate:v2"
    });
    if kind != 0 {
        w.u8(kind);
    }
    w.bytes(source).count(periods.len());
    for period in periods {
        w.bytes(period.as_bytes());
    }
    write_adjustments(&mut w, "Earnings to operating cash", adjustments);
    w.bytes(output);
    sealed(
        w,
        if kind == 0 {
            b"fa:indirect-cash-flow-certificate-digest:v1"
        } else {
            b"fa:indirect-cash-flow-certificate-digest:v2"
        },
    )
}

fn artifact(inputs: &Inputs, kind: u8) -> (Vec<u8>, [u8; 32], Vec<u8>, [u8; 32]) {
    let (base, cash, source_pin) = source(inputs, kind);
    let output = indirect_output(
        inputs,
        kind,
        &cash,
        &income_bytes(inputs),
        &ledger_bytes(&inputs.detail),
        &inputs.adjustments,
    );
    let (outer, pin) = indirect_certificate(
        kind,
        certificate(&base),
        &["P1"],
        &inputs.adjustments,
        &output,
    );
    (replace_certificate(&base, &outer), pin, output, source_pin)
}

#[test]
fn indirect_explicit_policy_and_split_recompute_income_adjustments_and_complete_detail() {
    for kind in 0..3 {
        for closing in 0..3 {
            let inputs = input(kind, closing);
            let (bundle, pin, output, source_pin) = artifact(&inputs, kind);
            let actual = check(&inputs.f, &bundle, &pin)
                .unwrap_or_else(|error| panic!("kind={kind}, closing={closing}: {error:?}"));
            assert_eq!(actual.output, output, "kind={kind} closing={closing}");
            assert_eq!(actual.certificate_digest, pin);
            assert_eq!(actual.known_at, inputs.f.roll.known_at);
            assert!(actual.cash_flow.is_none());
            assert!(actual.split_cash_flow.is_none());
            let report = actual.indirect_cash_flow.unwrap();
            assert_eq!(report.source_certificate_digest, source_pin);
            assert_eq!(
                report
                    .income
                    .lines
                    .iter()
                    .find(|l| l.code == "net_income" && l.unit == 1)
                    .unwrap()
                    .amounts,
                [260]
            );
            assert_eq!(report.non_cash_source.as_ref().unwrap().accounts.len(), 6);
            assert_eq!(report.non_cash_source.as_ref().unwrap().cells.len(), 12);
            assert_eq!(report.contributions.len(), if kind == 2 { 3 } else { 4 });
            assert_eq!(
                (
                    report.units[1].net_income,
                    report.units[1].non_cash,
                    report.units[1].working_capital
                ),
                (260, 30, -100)
            );
            assert_eq!(
                (report.units[1].operating, report.units[1].direct_operating),
                if kind == 2 { (190, 190) } else { (200, 200) }
            );
            assert_eq!(
                (
                    report.units[1].operating_residual,
                    report.units[1].net_change,
                    report.units[1].closing
                ),
                (0, 60, 60)
            );
            assert_eq!(report.units[0].net_income, 0);
            assert!(check(&inputs.f, &bundle, &source_pin).is_err());
            assert!(check(&inputs.f, &bundle, &inputs.f.roll.source_certificate_digest).is_err());
        }
    }
}

#[test]
fn indirect_repaired_hashes_cannot_rewrite_income_noncash_detail_or_reconciliation() {
    for kind in 0..3 {
        let inputs = input(kind, 1);
        let (base, cash, _) = source(&inputs, kind);
        for case in 0..5 {
            let mut income = income_bytes(&inputs);
            let mut detail = ledger_bytes(&inputs.detail);
            let mut adjustments = inputs.adjustments.clone();
            if case == 0 {
                *income.last_mut().unwrap() ^= 1;
            }
            if case == 1 {
                *detail.last_mut().unwrap() ^= 1;
            }
            if case == 2 {
                adjustments[0].4 = "Substituted reason".into();
            }
            let mut output = indirect_output(&inputs, kind, &cash, &income, &detail, &adjustments);
            if case == 3 {
                *output.last_mut().unwrap() ^= 1;
            }
            if case == 4 {
                output.pop();
            }
            let (outer, pin) = indirect_certificate(
                kind,
                certificate(&base),
                &["P1"],
                &inputs.adjustments,
                &output,
            );
            assert!(
                check(&inputs.f, &replace_certificate(&base, &outer), &pin).is_err(),
                "kind={kind} forgery={case}"
            );
        }
    }
}

#[test]
fn indirect_adjustments_must_cite_original_noncash_legs_with_lawful_categories() {
    let inputs = input(2, 1);
    let (base, cash, _) = source(&inputs, 2);
    for case in 0..8 {
        let mut adjustments = inputs.adjustments.clone();
        match case {
            0 => adjustments[0].0 = [99; 32],
            1 => adjustments[0].1 = 999,
            2 => {
                let cash = &inputs.f.roll.movements[0];
                adjustments[0].0 = cash.entry_digest;
                adjustments[0].1 = cash.leg_index;
            }
            3 => {
                let closing = inputs
                    .detail
                    .movements
                    .iter()
                    .find(|m| m.bucket.class == 8)
                    .unwrap();
                adjustments[0].0 = closing.entry_digest;
                adjustments[0].1 = closing.leg_index;
            }
            4 => {
                let expense = adjustments.iter_mut().find(|a| a.2 == 0).unwrap();
                expense.2 = 1;
            }
            5 => adjustments[0].3 ^= 1,
            6 => {
                adjustments.pop();
            }
            7 => adjustments[0].4 = " \t".into(),
            _ => unreachable!(),
        }
        adjustments.sort_by_key(|a| (a.0, a.1));
        let output = indirect_output(
            &inputs,
            2,
            &cash,
            &income_bytes(&inputs),
            &ledger_bytes(&inputs.detail),
            &adjustments,
        );
        let (outer, pin) =
            indirect_certificate(2, certificate(&base), &["P1"], &adjustments, &output);
        assert!(
            check(&inputs.f, &replace_certificate(&base, &outer), &pin).is_err(),
            "adjustment attack={case}"
        );
    }
}

#[test]
fn indirect_periods_require_whole_historical_coverage_and_a_canonical_selection() {
    let inputs = input(0, 0);
    let (base, cash, _) = source(&inputs, 0);
    let output = indirect_output(
        &inputs,
        0,
        &cash,
        &income_bytes(&inputs),
        &ledger_bytes(&inputs.detail),
        &inputs.adjustments,
    );
    for periods in [
        vec![],
        vec!["P2"],
        vec!["P1", "P2"],
        vec!["P1", "P1"],
        vec!["P2", "P1"],
        vec![""],
    ] {
        let (outer, pin) = indirect_certificate(
            0,
            certificate(&base),
            &periods,
            &inputs.adjustments,
            &output,
        );
        assert!(
            check(&inputs.f, &replace_certificate(&base, &outer), &pin).is_err(),
            "periods={periods:?}"
        );
    }
    let mut partial = input(0, 0);
    partial.f.roll.effective_from = 1;
    partial.detail.effective_from = 1;
    let (bundle, pin, _, _) = artifact(&partial, 0);
    assert!(
        check(&partial.f, &bundle, &pin).is_err(),
        "whole P1 cannot be sliced at its first day"
    );
}

#[test]
fn indirect_strict_family_framing_and_bounded_counts_do_not_admit_recursive_sources() {
    let inputs = input(0, 0);
    let (bundle, pin, output, _) = artifact(&inputs, 0);
    let original = certificate(&bundle);
    for cut in [0, 1, 4, 32, original.len() / 2, original.len() - 1] {
        assert!(
            check(
                &inputs.f,
                &replace_certificate(&bundle, &original[..cut]),
                &pin
            )
            .is_err()
        );
    }
    let (base, _, _) = source(&inputs, 0);
    for (kind, source) in [
        (1, certificate(&base)),
        (2, certificate(&base)),
        (0, original),
        (0, certificate(&inputs.f.native)),
    ] {
        let (outer, pin) =
            indirect_certificate(kind, source, &["P1"], &inputs.adjustments, &output);
        assert!(check(&inputs.f, &replace_certificate(&base, &outer), &pin).is_err());
    }
    for after_periods in [false, true] {
        let mut w = Writer::default();
        w.bytes(b"fa:indirect-cash-flow-certificate:v1")
            .bytes(certificate(&base));
        if after_periods {
            w.count(1).bytes(b"P1").bytes(b"bounded");
        }
        w.u32(u32::MAX);
        let (outer, pin) = sealed(w, b"fa:indirect-cash-flow-certificate-digest:v1");
        assert!(check(&inputs.f, &replace_certificate(&base, &outer), &pin).is_err());
    }
    let mut w = Writer::default();
    w.fixed(&original[..original.len() - 32]).u8(0);
    let (outer, pin) = sealed(w, b"fa:indirect-cash-flow-certificate-digest:v1");
    assert!(check(&inputs.f, &replace_certificate(&base, &outer), &pin).is_err());
}
