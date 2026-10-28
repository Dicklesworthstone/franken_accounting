//! Independent cash fixtures: literal native records, a separate wire encoder,
//! and hand-calculated section totals. No production cash projection or encoder
//! supplies the expected bytes, including hostile artifacts with resealed hashes.
use super::*;

#[path = "cash_flow_split.rs"]
mod cash_flow_split;

type Assignment = ([u8; 32], u32, u8);
type Decision = ([u8; 32], u32, u8, u8);
type Unit = (u32, i128, [[i128; 3]; 4], i128, i128);

#[derive(Clone)]
struct Definition {
    name: String,
    accounts: Vec<u128>,
    assignments: Vec<Assignment>,
}

#[derive(Clone)]
struct Policy {
    name: String,
    accounts: Vec<u128>,
    rules: Vec<(u128, u8)>,
    overrides: Vec<Assignment>,
}

struct Fixture {
    native: Vec<u8>,
    anchor: SignedCheckpoint,
    roll: VerifiedRollForward,
    definition: Definition,
    policy: Policy,
    decisions: Vec<Decision>,
}

const ACCOUNTS: &[(&str, &str, u8)] = &[
    ("1000", "Till", 1),
    ("1100", "Bank", 1),
    ("2000", "Overdraft", 2),
    ("3000", "Equity", 3),
    ("4000", "Sales", 4),
    ("5000", "Equipment", 1),
    ("6000", "FX", 4),
    ("7000", "Unused expense", 5),
    ("9000", "Memo", 6),
];

fn chart_body(accounts: &[(&str, &str, u8)]) -> Vec<u8> {
    chart_body_with_unit_policy(accounts, 1)
}

fn chart_body_with_unit_policy(accounts: &[(&str, &str, u8)], policy: i64) -> Vec<u8> {
    let mut w = Writer::default();
    w.count(accounts.len());
    for (code, name, typ) in accounts {
        w.bytes(code.as_bytes())
            .bytes(name.as_bytes())
            .u8(*typ)
            .u8(u8::from([2, 3, 4].contains(typ)))
            .u8(1)
            .fixed(&policy.to_le_bytes())
            .u8(0);
    }
    w.buf
}

fn fixture(known_at: u64, from: i32, through: i32, cancelling_counterparts: bool) -> Fixture {
    let mut records = schema();
    records[0] = record(
        17,
        1,
        0,
        b"cash-chart",
        0,
        Some((1, &chart_body(ACCOUNTS))),
        None,
        None,
    );
    // Amounts are deliberately small and literal. The only derived stock
    // below is the independently written source transcript for these records.
    let mut sale = vec![
        leg("1000", true, 60),
        leg("1100", false, 20),
        leg("4000", false, 40),
    ];
    if cancelling_counterparts {
        sale.extend([leg("7000", true, 5), leg("7000", false, 5)]);
    }
    let inputs = vec![
        (
            3,
            5,
            1,
            vec![leg("1000", true, 100), leg("3000", false, 100)],
        ),
        (4, 6, 1, vec![leg("3000", true, 20), leg("2000", false, 20)]),
        (5, 10, 1, sale),
        (
            6,
            12,
            1,
            vec![leg("1000", false, 10), leg("4000", true, 10)],
        ),
        (
            7,
            13,
            1,
            vec![leg("1100", false, 15), leg("5000", true, 15)],
        ),
        (
            8,
            14,
            1,
            vec![leg("1000", true, 25), leg("3000", false, 25)],
        ),
        (9, 15, 1, vec![leg("1100", true, 3), leg("6000", false, 3)]),
        (
            10,
            16,
            1,
            vec![leg("1000", false, 12), leg("1100", true, 12)],
        ),
        (
            11,
            18,
            2,
            vec![leg("1000", true, 700), leg("3000", false, 700)],
        ),
        (
            12,
            31,
            1,
            vec![leg("1000", true, 900), leg("3000", false, 900)],
        ),
        (13, 5, 1, vec![leg("1000", true, 9), leg("3000", false, 9)]),
    ];
    for (seq, day, class, legs) in &inputs {
        records.push(
            dated(
                posting(*class, *seq, &seq.to_le_bytes(), legs, None, None),
                *day,
            )
            .0,
        );
    }
    // This account exists at the covering checkpoint, but not at known_at12.
    // A verifier that consults current rather than historical metadata errs.
    records.push(record(
        17,
        14,
        0,
        b"later-account",
        0,
        Some((1, &chart_body(&[("8000", "Future account", 1)]))),
        None,
        None,
    ));
    let mut totals: BTreeMap<(&str, u32), [i128; 4]> = BTreeMap::new();
    for (seq, day, class, legs) in &inputs {
        if *seq > known_at || *day > through {
            continue;
        }
        for input in legs {
            let index = usize::from(!input.debit) + if *class == 2 { 2 } else { 0 };
            totals.entry((input.code, input.unit)).or_default()[index] += input.amount;
        }
    }
    let source_rows: Vec<_> = totals
        .into_iter()
        .map(|((code, unit), amount)| {
            let (_, name, account_type) = ACCOUNTS.iter().find(|a| a.0 == code).unwrap();
            ReportRow {
                account: account_id(code),
                code: code.into(),
                name: (*name).into(),
                account_type: *account_type,
                unit,
                debits: amount[0],
                credits: amount[1],
                debits_pending: amount[2],
                credits_pending: amount[3],
            }
        })
        .collect();
    let (native, anchor, source_certificate_digest) =
        source_bundle(&records, known_at, through, &source_rows, &[]);
    let accounts: Vec<_> = ACCOUNTS[..3]
        .iter()
        .map(|(code, name, typ)| RollForwardAccount {
            id: account_id(code),
            code: (*code).into(),
            name: (*name).into(),
            account_type: *typ,
            is_leaf: true,
        })
        .collect();
    let units = vec![0, 1];
    let bucket = classification(1, "", None);
    let mut movements = Vec::new();
    let mut assignments = Vec::new();
    for (record, (seq, day, class, legs)) in records[2..13].iter().zip(&inputs) {
        if *seq > known_at || *day < from || *day > through || *class == 2 {
            continue;
        }
        for (ordinal, input) in legs.iter().enumerate() {
            if !accounts.iter().any(|a| a.id == account_id(input.code)) {
                continue;
            }
            movements.push(movement(
                record,
                ordinal as u32,
                input.code,
                input.debit,
                input.amount,
                &bucket,
            ));
            assignments.push((
                record.envelope.record_digest,
                ordinal as u32,
                match seq {
                    7 => 1,
                    8 => 2,
                    9 => 3,
                    10 => 4,
                    _ => 0,
                },
            ));
        }
    }
    let buckets = if movements.is_empty() {
        vec![]
    } else {
        vec![bucket]
    };
    let mut rows = Vec::new();
    for account in &accounts {
        for &unit in &units {
            let mut opening = 0;
            let mut change = 0;
            for (seq, day, class, legs) in &inputs {
                if *seq > known_at || *day > through || *class == 2 {
                    continue;
                }
                for input in legs {
                    if account_id(input.code) == account.id && input.unit == unit {
                        let amount = if input.debit {
                            input.amount
                        } else {
                            -input.amount
                        };
                        if *day < from {
                            opening += amount;
                        } else {
                            change += amount;
                        }
                    }
                }
            }
            rows.push(RollForwardRow {
                account_id: account.id,
                unit_id: unit,
                opening,
                activity: if buckets.is_empty() {
                    vec![]
                } else {
                    vec![change]
                },
                net_change: change,
                closing: opening + change,
            });
        }
    }
    let roll = VerifiedRollForward {
        book_id: BOOK,
        known_at,
        label: "Cash lead".into(),
        effective_from: from,
        effective_through: through,
        source_certificate_digest,
        accounts,
        units,
        buckets,
        rows,
        movements,
    };
    let mut ids: Vec<_> = roll.accounts.iter().map(|a| a.id).collect();
    ids.sort_unstable();
    assignments.sort_unstable();
    let definition = Definition {
        name: "Declared cash classification".into(),
        accounts: ids.clone(),
        assignments,
    };
    let mut rules = vec![
        (account_id("3000"), 2),
        (account_id("4000"), 0),
        (account_id("5000"), 1),
        (account_id("6000"), 3),
        (account_id("7000"), 0),
    ];
    rules.sort_unstable();
    let policy = Policy {
        name: definition.name.clone(),
        accounts: ids,
        rules,
        overrides: vec![],
    };
    let decisions = definition
        .assignments
        .iter()
        .map(|&(digest, ordinal, activity)| {
            (digest, ordinal, activity, if activity == 4 { 2 } else { 0 })
        })
        .collect();
    Fixture {
        native,
        anchor,
        roll,
        definition,
        policy,
        decisions,
    }
}

fn ledger_bytes(roll: &VerifiedRollForward) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:general-ledger:v1")
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(roll.known_at)
        .bytes(roll.label.as_bytes())
        .i32(roll.effective_from)
        .i32(roll.effective_through)
        .count(roll.accounts.len());
    for a in &roll.accounts {
        w.u128(a.id)
            .bytes(a.code.as_bytes())
            .bytes(a.name.as_bytes())
            .u8(a.account_type)
            .u8(u8::from(a.is_leaf));
    }
    w.count(roll.units.len());
    for unit in &roll.units {
        w.u32(*unit);
    }
    w.count(roll.buckets.len());
    for bucket in &roll.buckets {
        w.u16(bucket.class)
            .bytes(bucket.reason_code.as_bytes())
            .u8(u8::from(bucket.rule_digest.is_some()));
        if let Some(digest) = bucket.rule_digest {
            w.fixed(&digest);
        }
    }
    let mut lines = Writer::default();
    let mut position = 0usize;
    w.count(roll.rows.len());
    for (cell_index, row) in roll.rows.iter().enumerate() {
        let mut movements: Vec<_> = roll
            .movements
            .iter()
            .filter(|m| m.account_id == row.account_id && m.unit_id == row.unit_id)
            .collect();
        movements.sort_by_key(|m| (m.effective_day, m.recorded_seq, m.entry_digest, m.leg_index));
        let debits: i128 = movements.iter().map(|m| m.debits).sum();
        let credits: i128 = movements.iter().map(|m| m.credits).sum();
        w.u128(row.account_id)
            .u32(row.unit_id)
            .i128(row.opening)
            .i128(debits)
            .i128(credits)
            .i128(row.net_change)
            .i128(row.closing)
            .u32(position as u32)
            .u32((position + movements.len()) as u32);
        let mut running = row.opening;
        for movement in movements {
            running += movement.debits - movement.credits;
            let bucket = roll
                .buckets
                .iter()
                .position(|b| b == &movement.bucket)
                .unwrap();
            lines
                .u32(cell_index as u32)
                .fixed(&movement.entry_digest)
                .u32(movement.leg_index)
                .u64(movement.recorded_seq)
                .i32(movement.effective_day)
                .u32(bucket as u32)
                .i128(movement.debits)
                .i128(movement.credits)
                .i128(running);
            position += 1;
        }
        assert_eq!(running, row.closing, "independent fixture running balance");
    }
    w.count(position).fixed(&lines.buf);
    w.buf
}

fn write_definition(w: &mut Writer, definition: &Definition) {
    w.bytes(definition.name.as_bytes())
        .count(definition.accounts.len());
    for account in &definition.accounts {
        w.u128(*account);
    }
    w.count(definition.assignments.len());
    for (digest, ordinal, activity) in &definition.assignments {
        w.fixed(digest).u32(*ordinal).u8(*activity);
    }
}

fn cash_bytes(ledger: &[u8], definition: &Definition, units: &[Unit]) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:cash-flow:v1").bytes(ledger);
    write_definition(&mut w, definition);
    w.count(units.len());
    for (unit, opening, sections, change, closing) in units {
        w.u32(*unit).i128(*opening);
        for section in sections {
            for amount in section {
                w.i128(*amount);
            }
        }
        w.i128(*change).i128(*closing);
    }
    w.buf
}

fn policy_bytes(policy: &Policy) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:cash-flow-policy:v1")
        .bytes(policy.name.as_bytes())
        .count(policy.accounts.len());
    for account in &policy.accounts {
        w.u128(*account);
    }
    w.count(policy.rules.len());
    for (account, activity) in &policy.rules {
        w.u128(*account).u8(*activity);
    }
    w.count(policy.overrides.len());
    for (digest, ordinal, activity) in &policy.overrides {
        w.fixed(digest).u32(*ordinal).u8(*activity);
    }
    w.buf
}

fn write_decisions(w: &mut Writer, decisions: &[Decision]) {
    w.count(decisions.len());
    for (digest, ordinal, activity, basis) in decisions {
        w.fixed(digest).u32(*ordinal).u8(*activity).u8(*basis);
    }
}

fn sealed(mut w: Writer, domain: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let pin = hash_parts(domain, &[&(w.buf.len() as u32).to_le_bytes(), &w.buf]);
    w.fixed(&pin);
    (w.buf, pin)
}

fn cash_certificate(source: &[u8], definition: &Definition, output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    w.bytes(b"fa:cash-flow-certificate:v1").bytes(source);
    write_definition(&mut w, definition);
    w.bytes(output);
    sealed(w, b"fa:cash-flow-certificate-digest:v1")
}

fn policy_certificate(
    source: &[u8],
    policy: &Policy,
    decisions: &[Decision],
) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    w.bytes(b"fa:cash-flow-policy-certificate:v1")
        .bytes(source)
        .bytes(&policy_bytes(policy));
    write_decisions(&mut w, decisions);
    sealed(w, b"fa:cash-flow-policy-certificate-digest:v1")
}

fn certificate(bundle: &[u8]) -> &[u8] {
    let mut r = Reader::new(bundle);
    r.bytes(64, "bundle format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap()
}

fn replace_certificate(bundle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(bundle);
    r.bytes(64, "bundle format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap();
    let mut w = Writer::default();
    w.bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(replacement)
        .fixed(&bundle[bundle.len() - r.remaining()..]);
    w.buf
}

fn direct(
    f: &Fixture,
    definition: &Definition,
    units: &[Unit],
) -> (Vec<u8>, [u8; 32], Vec<u8>, [u8; 32]) {
    let (roll_bundle, roll_pin) = wrap(&f.native, &f.roll);
    let output = cash_bytes(&ledger_bytes(&f.roll), definition, units);
    let (cash, pin) = cash_certificate(certificate(&roll_bundle), definition, &output);
    (
        replace_certificate(&roll_bundle, &cash),
        pin,
        output,
        roll_pin,
    )
}

fn policy_bundle(
    f: &Fixture,
    definition: &Definition,
    policy: &Policy,
    decisions: &[Decision],
    units: &[Unit],
) -> (Vec<u8>, [u8; 32], Vec<u8>, [u8; 32]) {
    let (cash_bundle, cash_pin, cash_output, _) = direct(f, definition, units);
    let (outer, pin) = policy_certificate(certificate(&cash_bundle), policy, decisions);
    let mut output = Writer::default();
    output
        .bytes(b"fa:policy-cash-flow:v1")
        .bytes(&policy_bytes(policy))
        .bytes(&cash_output);
    write_decisions(&mut output, decisions);
    (
        replace_certificate(&cash_bundle, &outer),
        pin,
        output.buf,
        cash_pin,
    )
}

fn check(f: &Fixture, bundle: &[u8], pin: &[u8; 32]) -> Result<VerifiedReport, ReportError> {
    verify_report_with(bundle, &[], None, None, Some(pin), |_, _| {
        Ok(f.anchor.clone())
    })
}

fn expected_units(opening: i128) -> Vec<Unit> {
    vec![
        (0, 0, [[0; 3]; 4], 0, 0),
        (
            1,
            opening,
            [[40, 10, 30], [0, 15, -15], [25, 0, 25], [3, 0, 3]],
            43,
            opening + 43,
        ),
    ]
}

fn zero_units(closing: i128) -> Vec<Unit> {
    vec![
        (0, 0, [[0; 3]; 4], 0, 0),
        (1, closing, [[0; 3]; 4], 0, closing),
    ]
}

fn single_entry(legs: &[InputLeg], cash_codes: &[&str], activities: &[(u32, u8)]) -> Fixture {
    let mut records = schema();
    records[0] = record(
        17,
        1,
        0,
        b"multiunit-chart",
        0,
        Some((1, &chart_body_with_unit_policy(ACCOUNTS, -1))),
        None,
        None,
    );
    records.push(posting(1, 3, b"single-cash-entry", legs, None, None).0);
    let mut totals: BTreeMap<(&str, u32), [i128; 2]> = BTreeMap::new();
    for leg in legs.iter().filter(|leg| leg.amount != 0) {
        totals.entry((leg.code, leg.unit)).or_default()[usize::from(!leg.debit)] += leg.amount;
    }
    let source_rows: Vec<_> = totals
        .into_iter()
        .map(|((code, unit), [debits, credits])| {
            let (_, name, account_type) = ACCOUNTS.iter().find(|a| a.0 == code).unwrap();
            ReportRow {
                account: account_id(code),
                code: code.into(),
                name: (*name).into(),
                account_type: *account_type,
                unit,
                debits,
                credits,
                debits_pending: 0,
                credits_pending: 0,
            }
        })
        .collect();
    let (native, anchor, source_certificate_digest) =
        source_bundle(&records, 3, 20, &source_rows, &[]);
    let accounts: Vec<_> = ACCOUNTS
        .iter()
        .filter(|a| cash_codes.contains(&a.0))
        .map(|(code, name, typ)| RollForwardAccount {
            id: account_id(code),
            code: (*code).into(),
            name: (*name).into(),
            account_type: *typ,
            is_leaf: true,
        })
        .collect();
    let units = vec![0, 1];
    let bucket = classification(1, "", None);
    let mut movements = Vec::new();
    for (ordinal, leg) in legs
        .iter()
        .enumerate()
        .filter(|(_, leg)| leg.amount != 0 && cash_codes.contains(&leg.code))
    {
        let mut m = movement(
            &records[2],
            ordinal as u32,
            leg.code,
            leg.debit,
            leg.amount,
            &bucket,
        );
        m.unit_id = leg.unit;
        movements.push(m);
    }
    let mut rows = Vec::new();
    for a in &accounts {
        for &unit_id in &units {
            let net_change = movements
                .iter()
                .filter(|m| m.account_id == a.id && m.unit_id == unit_id)
                .map(|m| m.debits - m.credits)
                .sum();
            rows.push(RollForwardRow {
                account_id: a.id,
                unit_id,
                opening: 0,
                activity: vec![net_change],
                net_change,
                closing: net_change,
            });
        }
    }
    let roll = VerifiedRollForward {
        book_id: BOOK,
        known_at: 3,
        label: "One entry".into(),
        effective_from: 10,
        effective_through: 20,
        source_certificate_digest,
        accounts,
        units,
        buckets: vec![bucket],
        rows,
        movements,
    };
    let mut ids: Vec<_> = roll.accounts.iter().map(|a| a.id).collect();
    ids.sort_unstable();
    let mut assignments: Vec<_> = activities
        .iter()
        .map(|&(ordinal, activity)| (records[2].envelope.record_digest, ordinal, activity))
        .collect();
    assignments.sort_unstable();
    let definition = Definition {
        name: "One entry cash".into(),
        accounts: ids.clone(),
        assignments,
    };
    let policy = Policy {
        name: definition.name.clone(),
        accounts: ids,
        rules: vec![(account_id("4000"), 0)],
        overrides: vec![],
    };
    let decisions = definition
        .assignments
        .iter()
        .map(|&(d, i, a)| (d, i, a, 0))
        .collect();
    Fixture {
        native,
        anchor,
        roll,
        definition,
        policy,
        decisions,
    }
}

#[test]
fn direct_cash_reconstructs_gross_sections_overdraft_and_exact_ledger_bytes() {
    let f = fixture(12, 10, 20, false);
    let (bundle, pin, expected, roll_pin) = direct(&f, &f.definition, &expected_units(80));
    let actual = check(&f, &bundle, &pin).unwrap();
    assert_eq!(actual.output, expected);
    assert_eq!(actual.certificate_digest, pin);
    assert_eq!(actual.known_at, 12);
    assert_eq!(actual.checked_records, 14);
    assert_eq!(actual.unit_universe_source, "authenticated-registry");
    let cash = actual.cash_flow.unwrap();
    assert_eq!(cash.source_certificate_digest, roll_pin);
    assert!(cash.policy.is_none());
    assert_eq!(cash.ledger.cells.len(), 6);
    assert_eq!(cash.ledger.lines.len(), 8);
    assert_eq!(cash.units.len(), 2);
    assert_eq!(cash.units[0].unit_id, 0);
    assert_eq!(
        (
            cash.units[0].opening,
            cash.units[0].net_change,
            cash.units[0].closing
        ),
        (0, 0, 0)
    );
    let cash = &cash.units[1];
    assert_eq!((cash.opening, cash.net_change, cash.closing), (80, 43, 123));
    assert_eq!(
        (
            cash.operating.inflows,
            cash.operating.outflows,
            cash.operating.net
        ),
        (40, 10, 30)
    );
    assert_eq!(
        (
            cash.investing.inflows,
            cash.investing.outflows,
            cash.investing.net
        ),
        (0, 15, -15)
    );
    assert_eq!((cash.financing.inflows, cash.financing.outflows), (25, 0));
    assert_eq!(
        (
            cash.exchange_effects.inflows,
            cash.exchange_effects.outflows
        ),
        (3, 0)
    );
    assert!(check(&f, &bundle, &roll_pin).is_err());
    assert!(check(&f, &bundle, &f.roll.source_certificate_digest).is_err());
}

#[test]
fn cash_history_excludes_pending_future_and_later_backdated_movements() {
    for (known_at, opening) in [(12, 80), (13, 89)] {
        let f = fixture(known_at, 10, 20, false);
        let (bundle, pin, expected, _) = direct(&f, &f.definition, &expected_units(opening));
        let actual = check(&f, &bundle, &pin).unwrap();
        assert_eq!(actual.output, expected);
        let cash = actual.cash_flow.unwrap();
        assert_eq!(cash.ledger.lines.len(), 8);
        assert!(
            cash.ledger
                .lines
                .iter()
                .all(|l| (10..=20).contains(&l.effective_day) && l.recorded_seq <= 10)
        );
        assert_eq!(
            (cash.units[1].opening, cash.units[1].closing),
            (opening, opening + 43)
        );
    }
    let f = fixture(12, 21, 30, false);
    let (bundle, pin, expected, _) =
        policy_bundle(&f, &f.definition, &f.policy, &f.decisions, &zero_units(123));
    let actual = check(&f, &bundle, &pin).unwrap();
    assert_eq!(actual.output, expected);
    let cash = actual.cash_flow.unwrap();
    assert!(cash.ledger.lines.is_empty());
    assert_eq!(cash.units.len(), 2);
    assert_eq!(
        (
            cash.units[1].opening,
            cash.units[1].net_change,
            cash.units[1].closing
        ),
        (123, 0, 123)
    );
    assert_eq!(cash.policy.unwrap().policy.account_rules.len(), 5);
}

#[test]
fn separate_original_and_reversal_preserve_both_gross_cash_directions() {
    let (records, mut roll) = offsetting(40);
    let (native, anchor, source_pin) = source_bundle(&records, 4, 20, &stock(40, 40), &[]);
    roll.source_certificate_digest = source_pin;
    let mut assignments: Vec<_> = roll
        .movements
        .iter()
        .map(|m| (m.entry_digest, m.leg_index, 0))
        .collect();
    assignments.sort_unstable();
    let definition = Definition {
        name: "Reversed cash".into(),
        accounts: vec![account_id("1000")],
        assignments,
    };
    let policy = Policy {
        name: definition.name.clone(),
        accounts: definition.accounts.clone(),
        rules: vec![],
        overrides: vec![],
    };
    let f = Fixture {
        native,
        anchor,
        roll,
        definition,
        policy,
        decisions: vec![],
    };
    let units = vec![(1, 0, [[40, 40, 0], [0; 3], [0; 3], [0; 3]], 0, 0)];
    let (bundle, pin, expected, _) = direct(&f, &f.definition, &units);
    let actual = check(&f, &bundle, &pin).unwrap();
    assert_eq!(actual.output, expected);
    assert_eq!(actual.cash_flow.unwrap().ledger.lines.len(), 2);
    let mut netted = units.clone();
    netted[0].2[0] = [0; 3];
    let (bundle, pin, _, _) = direct(&f, &f.definition, &netted);
    assert!(
        check(&f, &bundle, &pin).is_err(),
        "opposing entries cannot erase gross turnover"
    );
    let mut across_entries = f.definition.clone();
    for a in &mut across_entries.assignments {
        a.2 = 4;
    }
    let (bundle, pin, _, _) = direct(&f, &across_entries, &netted);
    assert!(
        check(&f, &bundle, &pin).is_err(),
        "internal transfers cannot net across entries"
    );
}

#[test]
fn resealed_cash_cannot_omit_zero_net_transfers_or_forge_gross_and_running_balances() {
    let f = fixture(12, 10, 20, false);
    let (bundle, pin, _, _) = direct(&f, &f.definition, &expected_units(80));
    check(&f, &bundle, &pin).unwrap();
    let mut omitted = f.definition.clone();
    omitted.assignments.retain(|a| a.2 != 4);
    let (bundle, pin, _, _) = direct(&f, &omitted, &expected_units(80));
    assert!(
        check(&f, &bundle, &pin).is_err(),
        "zero-net transfers remain mandatory classified detail"
    );
    let mut wrong_gross = expected_units(80);
    wrong_gross[1].2[0] = [60, 30, 30];
    let (bundle, pin, _, _) = direct(&f, &f.definition, &wrong_gross);
    assert!(
        check(&f, &bundle, &pin).is_err(),
        "gross cash nets within entry/unit/section"
    );
    let (roll_bundle, _) = wrap(&f.native, &f.roll);
    let mut ledger = ledger_bytes(&f.roll);
    let end = ledger.len();
    ledger[end - 16..].copy_from_slice(&(-19i128).to_le_bytes());
    let output = cash_bytes(&ledger, &f.definition, &expected_units(80));
    let (cash, pin) = cash_certificate(certificate(&roll_bundle), &f.definition, &output);
    let bundle = replace_certificate(&roll_bundle, &cash);
    assert!(
        check(&f, &bundle, &pin).is_err(),
        "a fresh outer digest cannot authenticate forged running detail"
    );
}

#[test]
fn cash_scope_and_assignment_canonicality_are_enforced_after_resealing() {
    let f = fixture(12, 10, 20, false);
    let (bundle, pin, _, _) = direct(&f, &f.definition, &expected_units(80));
    check(&f, &bundle, &pin).unwrap();
    for case in 0..9 {
        let mut d = f.definition.clone();
        match case {
            0 => {
                d.accounts.pop();
            }
            1 => {
                d.accounts.push(account_id("4000"));
                d.accounts.sort_unstable();
            }
            2 => {
                d.accounts[1] = d.accounts[0];
            }
            3 => d.accounts.reverse(),
            4 => {
                d.assignments[1] = d.assignments[0];
            }
            5 => d.assignments.reverse(),
            6 => {
                d.assignments[0].1 = 999;
                d.assignments.sort_unstable();
            }
            7 => d.assignments[0].2 = 5,
            8 => d.name = " \t".into(),
            _ => unreachable!(),
        }
        let (bundle, pin, _, _) = direct(&f, &d, &expected_units(80));
        assert!(
            check(&f, &bundle, &pin).is_err(),
            "accepted malformed cash definition {case}"
        );
    }
}

#[test]
fn explicit_internal_transfers_require_distinct_accounts_and_one_native_unit() {
    let f = single_entry(
        &[leg("1000", true, 10), leg("1000", false, 10)],
        &["1000"],
        &[(0, 0), (1, 0)],
    );
    let (bundle, pin, _, _) = direct(&f, &f.definition, &zero_units(0));
    check(&f, &bundle, &pin).unwrap();
    let mut same_account = f.definition.clone();
    for a in &mut same_account.assignments {
        a.2 = 4;
    }
    let (bundle, pin, _, _) = direct(&f, &same_account, &zero_units(0));
    assert!(check(&f, &bundle, &pin).is_err());

    let mut other_cash = leg("1100", false, 10);
    other_cash.unit = 0;
    let mut other_counterpart = leg("4000", true, 10);
    other_counterpart.unit = 0;
    let f = single_entry(
        &[
            leg("1000", true, 10),
            leg("4000", false, 10),
            other_cash,
            other_counterpart,
        ],
        &["1000", "1100"],
        &[(0, 0), (2, 0)],
    );
    let units = vec![
        (0, 0, [[0, 10, -10], [0; 3], [0; 3], [0; 3]], -10, -10),
        (1, 0, [[10, 0, 10], [0; 3], [0; 3], [0; 3]], 10, 10),
    ];
    let (bundle, pin, expected, _) = direct(&f, &f.definition, &units);
    assert_eq!(check(&f, &bundle, &pin).unwrap().output, expected);
    let mut across_units = f.definition.clone();
    for a in &mut across_units.assignments {
        a.2 = 4;
    }
    let (bundle, pin, _, _) = direct(&f, &across_units, &units);
    assert!(
        check(&f, &bundle, &pin).is_err(),
        "equal magnitudes in different units do not cancel"
    );
}

#[test]
fn an_explicit_transfer_can_be_a_cancelling_subset_of_a_mixed_entry() {
    let f = single_entry(
        &[
            leg("1000", false, 12),
            leg("1100", true, 12),
            leg("1000", true, 5),
            leg("4000", false, 5),
        ],
        &["1000", "1100"],
        &[(0, 4), (1, 4), (2, 0)],
    );
    let units = vec![
        (0, 0, [[0; 3]; 4], 0, 0),
        (1, 0, [[5, 0, 5], [0; 3], [0; 3], [0; 3]], 5, 5),
    ];
    let (bundle, pin, expected, _) = direct(&f, &f.definition, &units);
    assert_eq!(check(&f, &bundle, &pin).unwrap().output, expected);
    let mut policy = f.policy.clone();
    policy.overrides = f
        .definition
        .assignments
        .iter()
        .copied()
        .filter(|a| a.2 == 4)
        .collect();
    let decisions: Vec<_> = f
        .definition
        .assignments
        .iter()
        .map(|&(d, i, a)| (d, i, a, u8::from(a == 4)))
        .collect();
    let (bundle, pin, expected, _) = policy_bundle(&f, &f.definition, &policy, &decisions, &units);
    assert_eq!(check(&f, &bundle, &pin).unwrap().output, expected);
    let (bundle, pin, _, _) = policy_bundle(&f, &f.definition, &f.policy, &decisions, &units);
    assert!(
        check(&f, &bundle, &pin).is_err(),
        "mixed entries do not acquire automatic transfer provenance"
    );
}

#[test]
fn policy_reproduces_every_classification_and_binds_the_outer_certificate() {
    let f = fixture(12, 10, 20, false);
    let (bundle, pin, expected, cash_pin) = policy_bundle(
        &f,
        &f.definition,
        &f.policy,
        &f.decisions,
        &expected_units(80),
    );
    let actual = check(&f, &bundle, &pin).unwrap();
    assert_eq!(actual.output, expected);
    assert_eq!(actual.certificate_digest, pin);
    let policy = actual.cash_flow.unwrap().policy.unwrap();
    assert_eq!(policy.source_certificate_digest, cash_pin);
    assert_eq!(policy.decisions.len(), 8);
    assert_eq!(policy.policy.account_rules.len(), 5);
    assert_eq!(
        policy
            .decisions
            .iter()
            .filter(|d| d.basis as u8 == 2)
            .count(),
        2
    );
    assert!(check(&f, &bundle, &cash_pin).is_err());
    let (_, roll_pin) = wrap(&f.native, &f.roll);
    assert!(check(&f, &bundle, &roll_pin).is_err());

    let mut changed = f.policy.clone();
    changed
        .rules
        .iter_mut()
        .find(|r| r.0 == account_id("4000"))
        .unwrap()
        .1 = 1;
    let (bundle, pin, _, _) = policy_bundle(
        &f,
        &f.definition,
        &changed,
        &f.decisions,
        &expected_units(80),
    );
    assert!(
        check(&f, &bundle, &pin).is_err(),
        "cash totals alone do not validate policy derivation"
    );
}

#[test]
fn a_redundant_explicit_override_still_changes_authenticated_decision_basis() {
    let f = fixture(12, 10, 20, false);
    let choice = f
        .definition
        .assignments
        .iter()
        .copied()
        .find(|a| a.2 == 0)
        .unwrap();
    let mut policy = f.policy.clone();
    policy.overrides = vec![choice];
    let mut decisions = f.decisions.clone();
    decisions
        .iter_mut()
        .find(|d| (d.0, d.1) == (choice.0, choice.1))
        .unwrap()
        .3 = 1;
    let (bundle, pin, expected, _) =
        policy_bundle(&f, &f.definition, &policy, &decisions, &expected_units(80));
    assert_eq!(check(&f, &bundle, &pin).unwrap().output, expected);
    let (bundle, pin, _, _) = policy_bundle(
        &f,
        &f.definition,
        &policy,
        &f.decisions,
        &expected_units(80),
    );
    assert!(check(&f, &bundle, &pin).is_err());
    let (bundle, pin, _, _) = policy_bundle(
        &f,
        &f.definition,
        &f.policy,
        &decisions,
        &expected_units(80),
    );
    assert!(check(&f, &bundle, &pin).is_err());
}

#[test]
fn even_unused_policy_rules_are_validated_at_the_historical_cut() {
    for from in [10, 21] {
        let f = fixture(12, from, 30, false);
        let units = if from == 10 {
            expected_units(80)
        } else {
            zero_units(123)
        };
        let (bundle, pin, _, _) = policy_bundle(&f, &f.definition, &f.policy, &f.decisions, &units);
        check(&f, &bundle, &pin).unwrap();
        for code in ["9999", "8000", "9000"] {
            let mut policy = f.policy.clone();
            policy.rules.push((account_id(code), 0));
            policy.rules.sort_unstable();
            let (bundle, pin, _, _) =
                policy_bundle(&f, &f.definition, &policy, &f.decisions, &units);
            assert!(
                check(&f, &bundle, &pin).is_err(),
                "accepted absent/future/nonmonetary unused account {code}"
            );
        }
        let mut policy = f.policy.clone();
        policy
            .rules
            .iter_mut()
            .find(|r| r.0 == account_id("7000"))
            .unwrap()
            .1 = 2;
        let (changed, new_pin, expected, _) =
            policy_bundle(&f, &f.definition, &policy, &f.decisions, &units);
        assert_eq!(check(&f, &changed, &new_pin).unwrap().output, expected);
        assert!(
            check(&f, &changed, &pin).is_err(),
            "unused valid input changes still require the new outer pin"
        );
    }
}

#[test]
fn cancelling_noncash_counterparts_still_require_complete_policy_choices() {
    let f = fixture(12, 10, 20, true);
    let (bundle, pin, _, _) = policy_bundle(
        &f,
        &f.definition,
        &f.policy,
        &f.decisions,
        &expected_units(80),
    );
    check(&f, &bundle, &pin).unwrap();
    let sale = f
        .roll
        .movements
        .iter()
        .find(|m| m.recorded_seq == 5)
        .unwrap()
        .entry_digest;
    for mixed in [false, true] {
        let mut policy = f.policy.clone();
        if mixed {
            policy
                .rules
                .iter_mut()
                .find(|r| r.0 == account_id("7000"))
                .unwrap()
                .1 = 1;
        } else {
            policy.rules.retain(|r| r.0 != account_id("7000"));
        }
        let (bundle, pin, _, _) = policy_bundle(
            &f,
            &f.definition,
            &policy,
            &f.decisions,
            &expected_units(80),
        );
        assert!(
            check(&f, &bundle, &pin).is_err(),
            "opposing noncash legs do not erase ambiguity"
        );
        policy.overrides = f
            .definition
            .assignments
            .iter()
            .copied()
            .filter(|a| a.0 == sale)
            .collect();
        assert_eq!(policy.overrides.len(), 2);
        let mut decisions = f.decisions.clone();
        for d in &mut decisions {
            if d.0 == sale {
                d.3 = 1;
            }
        }
        let (bundle, pin, expected, _) =
            policy_bundle(&f, &f.definition, &policy, &decisions, &expected_units(80));
        assert_eq!(check(&f, &bundle, &pin).unwrap().output, expected);
        policy.overrides.pop();
        let (bundle, pin, _, _) =
            policy_bundle(&f, &f.definition, &policy, &decisions, &expected_units(80));
        assert!(
            check(&f, &bundle, &pin).is_err(),
            "every ambiguous cash leg needs its own explicit choice"
        );
    }
}

#[test]
fn policy_canonicality_extra_overrides_and_decision_tampering_fail_closed() {
    let f = fixture(12, 10, 20, false);
    let (bundle, pin, _, _) = policy_bundle(
        &f,
        &f.definition,
        &f.policy,
        &f.decisions,
        &expected_units(80),
    );
    check(&f, &bundle, &pin).unwrap();
    for case in 0..10 {
        let mut policy = f.policy.clone();
        let mut decisions = f.decisions.clone();
        match case {
            0 => policy.rules.push((policy.rules[0].0, 0)),
            1 => policy.rules.reverse(),
            2 => {
                policy.rules.push((account_id("1000"), 0));
                policy.rules.sort_unstable();
            }
            3 => policy.rules[0].1 = 4,
            4 => policy.overrides.push(([99; 32], 0, 0)),
            5 => {
                decisions.pop();
            }
            6 => decisions.reverse(),
            7 => decisions[1] = decisions[0],
            8 => decisions[0].3 = 3,
            9 => policy.name.push('x'),
            _ => unreachable!(),
        }
        let (bundle, pin, _, _) =
            policy_bundle(&f, &f.definition, &policy, &decisions, &expected_units(80));
        assert!(
            check(&f, &bundle, &pin).is_err(),
            "accepted malformed policy {case}"
        );
    }
}

#[test]
fn cash_certificate_framing_counts_and_wrapper_order_fail_closed() {
    let f = fixture(12, 10, 20, false);
    let (bundle, pin, _, _) = direct(&f, &f.definition, &expected_units(80));
    check(&f, &bundle, &pin).unwrap();
    let original = certificate(&bundle);
    for cut in [0, 1, 4, 32, original.len() / 2, original.len() - 1] {
        let bad = replace_certificate(&bundle, &original[..cut]);
        assert!(check(&f, &bad, &pin).is_err());
    }
    let (roll_bundle, _) = wrap(&f.native, &f.roll);
    for assignment_count in [false, true] {
        let mut w = Writer::default();
        w.bytes(b"fa:cash-flow-certificate:v1")
            .bytes(certificate(&roll_bundle))
            .bytes(b"bounded");
        if assignment_count {
            w.count(1).u128(account_id("1000"));
        }
        w.u32(u32::MAX);
        let (cash, pin) = sealed(w, b"fa:cash-flow-certificate-digest:v1");
        assert!(check(&f, &replace_certificate(&bundle, &cash), &pin).is_err());
    }
    let mut trailing = Writer::default();
    trailing.fixed(&original[..original.len() - 32]).u8(0);
    let (cash, pin) = sealed(trailing, b"fa:cash-flow-certificate-digest:v1");
    assert!(check(&f, &replace_certificate(&bundle, &cash), &pin).is_err());
    let (policy, pin) = policy_certificate(certificate(&roll_bundle), &f.policy, &f.decisions);
    assert!(
        check(&f, &replace_certificate(&bundle, &policy), &pin).is_err(),
        "policy cannot skip the direct-cash certificate"
    );
    let (recursive, pin) = cash_certificate(original, &f.definition, b"");
    assert!(
        check(&f, &replace_certificate(&bundle, &recursive), &pin).is_err(),
        "arbitrary recursive cash wrappers are unsupported"
    );
}
