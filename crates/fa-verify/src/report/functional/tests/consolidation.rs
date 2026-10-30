//! Independently authored group histories and hand-calculated consolidation
//! outputs. Every hostile bundle below has its entry, prefix, registry,
//! certificate and output commitments resealed, so a refusal must come from
//! source interpretation or accounting recomputation, not a stale hash.
//!
//! As in the other complete-prefix fixtures, a trusted checkpoint is supplied
//! at the signature boundary. Production signature tests exercise that boundary
//! separately; none of the expected accounting values calls the evaluator.

use super::*;
use crate::report::{ReportError, VerifiedReport};

const NATIVE_CERTIFICATE: &[u8] = b"fa:report-certificate:v6";
const FUNCTIONAL_CERTIFICATE: &[u8] = b"fa:report-certificate:v7";
const NATIVE_OUTPUT: &[u8] = b"fa:consolidation:v1";
const FUNCTIONAL_OUTPUT: &[u8] = b"fa:functional-consolidation:v1";

fn chart() -> [(&'static str, &'static str, u8); 12] {
    [
        ("1000", "Cash", 1),
        ("1100", "Due from group", 1),
        ("1600", "Investment", 1),
        ("2000", "Due to group", 2),
        ("3000", "Capital", 3),
        ("3100", "Unused retained earnings", 3),
        ("3200", "Minority equity", 3),
        ("4000", "External sales", 4),
        ("4100", "Group sales", 4),
        ("5000", "External costs", 5),
        ("5100", "Group costs", 5),
        ("5200", "Minority income allocation", 5),
    ]
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
        .bytes(&seq.to_le_bytes())
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

fn role(seq: u64, code: &str, name: &str, assigned: bool) -> Record {
    let mut w = Writer::default();
    w.fixed(b"fa:account-role:v1")
        .u128(id(code))
        .bytes(name.as_bytes())
        .u8(u8::from(assigned));
    control(seq, 16, &w.buf)
}

fn legal_entity(code: &str) -> u128 {
    let digest = framed_hash(b"fa:vid:legal-entity:v1", &[&BOOK, code.as_bytes()]);
    u128::from_le_bytes(digest[..16].try_into().unwrap())
}

fn ownership(seq: u64, from: &str, to: &str, num: i128, den: u128) -> Record {
    let mut w = Writer::default();
    w.u128(legal_entity(from))
        .u128(legal_entity(to))
        .u8(1)
        .i128(num)
        .u128(den)
        .bytes(format!("Retained acquisition terms {seq}").as_bytes())
        .i32(0)
        .u8(0);
    control(seq, 9, &w.buf)
}

fn declarations() -> Vec<Record> {
    let mut c = Writer::default();
    c.count(chart().len());
    for (code, name, kind) in chart() {
        c.bytes(code.as_bytes())
            .bytes(name.as_bytes())
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
    let mut records = vec![control(1, 1, &c.buf), control(2, 13, &periods.buf)];
    for (code, name) in [
        ("1100", "intercompany"),
        ("2000", "intercompany"),
        ("4100", "intercompany_activity"),
        ("5100", "intercompany_activity"),
        ("1600", "investment_in_subsidiary"),
        ("3000", "contributed_capital"),
        ("3200", "noncontrolling_interest"),
        ("5200", "noncontrolling_interest_income"),
    ] {
        records.push(role(next(&records), code, name, true));
    }
    records.push(ownership(next(&records), "P", "S", 4, 5));
    records
}

fn next(records: &[Record]) -> u64 {
    records.last().unwrap().envelope.commit_seq + 1
}

fn scaled(value: i128, functional: bool) -> i128 {
    if functional {
        // All oracle amounts are even: the fixture's 3/2 quote converts
        // exactly, independently of the implementation's rounding routine.
        assert_eq!(value % 2, 0);
        value.checked_mul(3).unwrap() / 2
    } else {
        value
    }
}

fn entity_pair(
    entity: Option<&'static str>,
    debit: &'static str,
    credit: &'static str,
    amount: i128,
    functional: bool,
) -> Vec<TestLeg> {
    [(debit, true), (credit, false)]
        .into_iter()
        .map(|(code, debit)| TestLeg {
            code,
            debit,
            unit: u32::from(functional),
            native: amount,
            base: functional.then(|| scaled(amount, true)),
            entity,
        })
        .collect()
}

#[derive(Clone)]
struct Fixture {
    functional: bool,
    records: Vec<Record>,
    rates: Vec<RateFixture>,
    known_at: u64,
    ownership: usize,
    nci_role: usize,
    sub_sale: usize,
    sub_service: usize,
}

impl Fixture {
    fn new(functional: bool) -> Self {
        let mut records = declarations();
        let ownership_index = records.len() - 1;
        let nci_role = 8;
        let capital_rate = rate_fixture(3, 2, 1, 10);
        let activity_rate = rate_fixture(3, 2, 1, 40);
        if functional {
            records.push(intake(&capital_rate, next(&records)));
        }
        for (key, entity, debit, credit, amount) in [
            (b"parent-capital".as_slice(), "P", "1000", "3000", 1000),
            (b"parent-investment".as_slice(), "P", "1600", "1000", 80),
            (b"subsidiary-capital".as_slice(), "S", "1000", "3000", 100),
        ] {
            records.push(entry(
                next(&records),
                1,
                10,
                key,
                &entity_pair(Some(entity), debit, credit, amount, functional),
                functional.then_some((1, &capital_rate, None)),
                None,
                None,
            ));
        }
        if functional {
            records.push(intake(&activity_rate, next(&records)));
        }
        let mut sub_sale = 0;
        let mut sub_service = 0;
        for (key, entity, debit, credit, amount) in [
            (b"parent-loan".as_slice(), "P", "1100", "1000", 20),
            (b"subsidiary-loan".as_slice(), "S", "1000", "2000", 20),
            (b"parent-service".as_slice(), "P", "1100", "4100", 10),
            (b"subsidiary-service".as_slice(), "S", "5100", "2000", 10),
            (b"parent-sale".as_slice(), "P", "1000", "4000", 200),
            (b"subsidiary-sale".as_slice(), "S", "1000", "4000", 100),
            (b"parent-expense".as_slice(), "P", "5000", "1000", 50),
            (b"subsidiary-expense".as_slice(), "S", "5000", "1000", 20),
        ] {
            if key == b"subsidiary-sale" {
                sub_sale = records.len();
            }
            if key == b"subsidiary-service" {
                sub_service = records.len();
            }
            records.push(entry(
                next(&records),
                1,
                40,
                key,
                &entity_pair(Some(entity), debit, credit, amount, functional),
                functional.then_some((1, &activity_rate, None)),
                None,
                None,
            ));
        }
        // A reservation is not group stock, income, or an NCI entitlement.
        records.push(entry(
            next(&records),
            2,
            40,
            b"pending-subsidiary-sale",
            &entity_pair(Some("S"), "1000", "4000", 500, functional),
            functional.then_some((1, &activity_rate, None)),
            None,
            None,
        ));
        let known_at = records.last().unwrap().envelope.commit_seq;
        // The checkpoint is deliberately newer than the selected report.
        records.push(entry(
            next(&records),
            1,
            40,
            b"later-backdated-sale",
            &entity_pair(Some("S"), "1000", "4000", 600, functional),
            functional.then_some((1, &activity_rate, None)),
            None,
            None,
        ));
        records.push(role(
            next(&records),
            "3200",
            "noncontrolling_interest",
            false,
        ));
        records.push(ownership(next(&records), "P", "S", 9, 10));
        if functional {
            // Not a source of any selected carrying amount. It cannot become
            // the report's rate simply because it is in the signed prefix.
            records.push(intake(&rate_fixture(2, 1, 1, 40), next(&records)));
        }
        Self {
            functional,
            records,
            rates: if functional {
                vec![capital_rate, activity_rate]
            } else {
                vec![]
            },
            known_at,
            ownership: ownership_index,
            nci_role,
            sub_sale,
            sub_service,
        }
    }

    fn output(&self, lie: Lie) -> Vec<u8> {
        expected_output(self.functional, self.known_at, lie)
    }

    fn pack(&self, output: &[u8]) -> Packed {
        pack(
            self,
            output,
            &book(&["P", "S"]),
            &documents(self.functional, false),
        )
    }

    fn replace_sale_entity(&mut self, entity: Option<&'static str>) {
        let seq = self.records[self.sub_sale].envelope.commit_seq;
        self.records[self.sub_sale] = entry(
            seq,
            1,
            40,
            b"subsidiary-sale",
            &entity_pair(entity, "1000", "4000", 100, self.functional),
            self.functional.then(|| (1, &self.rates[1], None)),
            None,
            None,
        );
    }
}

// The registry document is encoded from the six public semantic role rows,
// independently from both the producer's TOML reader and the verifier decoder.
fn registry_text(w: &mut Writer, value: &str) {
    w.u64(value.len() as u64).fixed(value.as_bytes());
}
fn registry_value(w: &mut Writer, value: &str) {
    w.u8(1);
    registry_text(w, value);
}
fn registry_array(w: &mut Writer, values: &[&str]) {
    w.u8(4).u64(values.len() as u64);
    for value in values {
        registry_value(w, value);
    }
}
fn roles_document(wrong_nci_type: bool) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"fa:registry-document:v1").u64(1);
    registry_text(&mut w, "schema_version");
    w.u8(2).i128(1).u64(0).u64(1);
    registry_text(&mut w, "role");
    let rows: [(&str, &[&str]); 6] = [
        ("intercompany", &["Asset", "Liability"]),
        ("intercompany_activity", &["Revenue", "Expense"]),
        ("investment_in_subsidiary", &["Asset"]),
        ("contributed_capital", &["Equity"]),
        (
            "noncontrolling_interest",
            if wrong_nci_type {
                &["Expense"]
            } else {
                &["Equity"]
            },
        ),
        ("noncontrolling_interest_income", &["Expense"]),
    ];
    w.u64(rows.len() as u64);
    for (name, kinds) in rows {
        w.u64(5);
        registry_text(&mut w, "account_types");
        registry_array(&mut w, kinds);
        registry_text(&mut w, "consumers");
        registry_array(&mut w, &[]);
        registry_text(&mut w, "meaning");
        registry_value(
            &mut w,
            "The retained consolidation role selects these account types.",
        );
        registry_text(&mut w, "name");
        registry_value(&mut w, name);
        registry_text(&mut w, "verbs");
        registry_array(&mut w, &["consolidate"]);
    }
    w.buf
}
fn documents(functional: bool, wrong_nci_type: bool) -> Vec<(String, Vec<u8>)> {
    let original = registries();
    let mut result = original[..4].to_vec();
    result.push(("account_roles".into(), roles_document(wrong_nci_type)));
    if functional {
        result.push(
            original
                .iter()
                .find(|(name, _)| name == "fx_laws")
                .unwrap()
                .clone(),
        );
    }
    result.push(
        original
            .iter()
            .find(|(name, _)| name == "rounding_laws")
            .unwrap()
            .clone(),
    );
    result
}

#[derive(Clone, Copy, Debug)]
enum Lie {
    None,
    OmitMember,
    OmitIntercompany,
    ChangeNci,
    IncludePendingIncome,
}

#[derive(Clone)]
struct ExpectedLeg {
    entity: &'static str,
    account: &'static str,
    debit: i128,
    credit: i128,
}
struct ExpectedElimination {
    code: String,
    description: String,
    legs: Vec<ExpectedLeg>,
}
fn expected_eliminations(income: bool, lie: Lie) -> Vec<ExpectedElimination> {
    let mut legs = Vec::new();
    if !income {
        let mut balances = vec![
            ExpectedLeg {
                entity: "P",
                account: "1100",
                debit: 0,
                credit: 30,
            },
            ExpectedLeg {
                entity: "S",
                account: "2000",
                debit: 30,
                credit: 0,
            },
        ];
        balances.sort_by_key(|leg| (legal_entity(leg.entity).to_be_bytes(), id(leg.account)));
        legs.extend(balances);
    }
    let mut activity = vec![
        ExpectedLeg {
            entity: "P",
            account: "4100",
            debit: 10,
            credit: 0,
        },
        ExpectedLeg {
            entity: "S",
            account: "5100",
            debit: 0,
            credit: 10,
        },
    ];
    activity.sort_by_key(|leg| (legal_entity(leg.entity).to_be_bytes(), id(leg.account)));
    legs.extend(activity);
    let mut entries = vec![ExpectedElimination {
        code: "ELIM-IC-GROUP-U0".into(),
        description: "Eliminate the group's intercompany balances and transactions in unit 0"
            .into(),
        legs,
    }];
    if matches!(lie, Lie::OmitIntercompany) {
        entries.clear();
    }
    let subsidiary = format!("{:032x}", legal_entity("S"));
    if !income {
        entries.push(ExpectedElimination {
            code: format!("ELIM-EQ-{subsidiary}-U0"),
            description: format!("Eliminate investment in subsidiary {subsidiary} (8000 bps) against subsidiary equity"),
            legs: vec![
                ExpectedLeg { entity: "S", account: "3000", debit: 100, credit: 0 },
                ExpectedLeg { entity: "P", account: "1600", debit: 0, credit: 80 },
                ExpectedLeg { entity: "S", account: "3200", debit: 0, credit: 20 },
            ],
        });
    }
    let share = if matches!(lie, Lie::ChangeNci) {
        16
    } else {
        14
    };
    let what = if income {
        "earnings for the period"
    } else {
        "unclosed earnings"
    };
    entries.push(ExpectedElimination {
        code: format!("ELIM-NCI-{subsidiary}-U0"),
        description: format!("Allocate the noncontrolling interest's share of subsidiary {subsidiary}'s {what} (8000 bps owned)"),
        legs: vec![
            ExpectedLeg { entity: "S", account: "5200", debit: share, credit: 0 },
            ExpectedLeg { entity: "S", account: "3200", debit: 0, credit: share },
        ],
    });
    entries
}
fn write_eliminations(w: &mut Writer, entries: &[ExpectedElimination], functional: bool) {
    w.count(entries.len());
    for entry in entries {
        w.bytes(entry.code.as_bytes())
            .bytes(entry.description.as_bytes())
            .u32(0)
            .count(entry.legs.len());
        for leg in &entry.legs {
            w.fixed(&legal_entity(leg.entity).to_be_bytes())
                .u128(id(leg.account))
                .u32(0)
                .i128(scaled(leg.debit, functional))
                .i128(scaled(leg.credit, functional));
        }
    }
}

fn statement_output(income: bool, functional: bool, known_at: u64, lie: Lie) -> Vec<u8> {
    let definition = unhex(if income {
        include_str!("../../tests/income-statement.hex")
    } else {
        include_str!("../../tests/balance-sheet.hex")
    });
    let definition_digest = framed_hash(b"fa:statement-definition:v1", &[&definition]);
    let mut w = Writer::default();
    w.fixed(b"FA-STATEMENT\0")
        .u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(known_at)
        .bytes(if income {
            b"income-statement"
        } else {
            b"balance-sheet"
        })
        .u32(1)
        .fixed(&definition_digest)
        .bytes(&definition)
        .count(1)
        .bytes(b"P2")
        .count(1)
        .bytes(b"P2")
        .u8(u8::from(income));
    if income {
        w.i32(31);
    }
    w.i32(58);
    let rows: Vec<(&str, &str, i128)> = if income {
        let includes_pending = matches!(lie, Lie::IncludePendingIncome);
        vec![
            (
                "revenue",
                "Revenue",
                if includes_pending { 800 } else { 300 },
            ),
            (
                "expense",
                "Expenses",
                if includes_pending { 184 } else { 84 },
            ),
            (
                "net_income",
                "Net income",
                if includes_pending { 616 } else { 216 },
            ),
        ]
    } else {
        vec![
            ("assets", "Assets", 1250),
            ("liabilities", "Liabilities", 0),
            ("equity", "Posted equity", 1034),
            ("unclosed_revenue", "Unclosed revenue, all years", 300),
            ("unclosed_expense", "Unclosed expenses, all years", 84),
            ("unclosed_earnings", "Unclosed earnings, all years", 216),
            ("total_equity", "Equity including unclosed earnings", 1250),
            (
                "liabilities_and_equity",
                "Liabilities and equity including unclosed earnings",
                1250,
            ),
            (
                "balance_check",
                "Assets less liabilities and equity (must equal zero)",
                0,
            ),
        ]
    };
    let units = if functional { 1 } else { 13 };
    w.count(rows.len() * units);
    for (code, label, amount) in rows {
        for unit in 0..units {
            w.bytes(code.as_bytes())
                .bytes(label.as_bytes())
                .u32(unit as u32)
                .count(1)
                .i128(if unit == 0 {
                    scaled(amount, functional)
                } else {
                    0
                });
        }
    }
    let mappings: Vec<_> = chart()
        .into_iter()
        .filter(|(_, _, kind)| !income || matches!(kind, 4 | 5))
        .collect();
    w.count(mappings.len());
    for (code, name, kind) in mappings {
        let line = match (income, kind) {
            (true, 4) => "revenue",
            (true, 5) => "expense",
            (false, 1) => "assets",
            (false, 2) => "liabilities",
            (false, 3) => "equity",
            (false, 4) => "unclosed_revenue",
            (false, 5) => "unclosed_expense",
            _ => unreachable!(),
        };
        w.u128(id(code))
            .bytes(code.as_bytes())
            .bytes(name.as_bytes())
            .u8(kind)
            .u8(1)
            .bytes(line.as_bytes());
    }
    w.buf
}

fn expected_output(functional: bool, known_at: u64, lie: Lie) -> Vec<u8> {
    let mut run = Writer::default();
    run.fixed(b"fa:consolidation-run:v1")
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(known_at)
        .bytes(b"P2")
        .count(0);
    write_eliminations(&mut run, &expected_eliminations(false, lie), functional);
    write_eliminations(&mut run, &expected_eliminations(true, lie), functional);
    let units = if functional { 1 } else { 13 };
    run.count(units);
    for unit in 0..units {
        run.u32(unit as u32);
        // The reconciliation names the elimination impact BEFORE adding
        // the separately recognized NCI: 1160 + 170 - 114 + 34 = 1250.
        for amount in [1160, 170, -114, 34, 1216, 1250] {
            run.i128(if unit == 0 {
                scaled(amount, functional)
            } else {
                0
            });
        }
    }
    run.bytes(&statement_output(false, functional, known_at, lie))
        .bytes(&statement_output(true, functional, known_at, lie));
    let mut group = Writer::default();
    group
        .fixed(NATIVE_OUTPUT)
        .bytes(b"P2")
        .u64(known_at)
        .i32(58)
        .count(if matches!(lie, Lie::OmitMember) { 1 } else { 2 })
        .bytes(b"P")
        .bytes(b"P")
        .u8(0)
        .u8(0);
    if !matches!(lie, Lie::OmitMember) {
        group
            .bytes(b"S")
            .bytes(b"S")
            .u8(1)
            .bytes(b"P")
            .u8(1)
            .u16(8000);
    }
    group.bytes(b"HalfEven").bytes(&run.buf);
    if functional {
        let mut wrapper = Writer::default();
        wrapper
            .fixed(FUNCTIONAL_OUTPUT)
            .u32(0)
            .bytes(b"retained-base-amounts")
            .bytes(&group.buf);
        wrapper.buf
    } else {
        group.buf
    }
}

struct Packed {
    bytes: Vec<u8>,
    checkpoint: SignedCheckpoint,
    pin: [u8; 32],
}
impl Packed {
    fn verify(&self) -> Result<VerifiedReport, ReportError> {
        verify_report_with_inputs(
            &self.bytes,
            &[],
            None,
            None,
            Some(&self.pin),
            None,
            |_, _| Ok(self.checkpoint.clone()),
        )
    }
}

fn pack(fixture: &Fixture, output: &[u8], spec: &[u8], docs: &[(String, Vec<u8>)]) -> Packed {
    let historical: Vec<_> = fixture
        .records
        .iter()
        .filter(|record| {
            record.envelope.kind == KIND_ENTRY && record.envelope.commit_seq <= fixture.known_at
        })
        .map(|record| leaf_hash(&record.envelope.encode()))
        .collect();
    let format = if fixture.functional {
        FUNCTIONAL_CERTIFICATE
    } else {
        NATIVE_CERTIFICATE
    };
    let mut cert = Writer::default();
    cert.fixed(format)
        .bytes(b"fa-fold-over-prefix")
        .bytes(b"embedded-owner")
        .bytes(if fixture.functional {
            FUNCTIONAL_OUTPUT
        } else {
            NATIVE_OUTPUT
        })
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(fixture.known_at)
        .u8(if fixture.functional { 5 } else { 4 })
        .bytes(b"P2")
        .fixed(&closure(docs))
        .fixed(&root_of(&historical))
        .u64(historical.len() as u64);
    let inputs = if fixture.functional { 8 } else { 7 };
    cert.count(inputs);
    for _ in 0..inputs {
        cert.bytes(b"native read witnesses are opaque");
    }
    cert.bytes(output)
        .fixed(&hash_parts(b"fa:report-output:v1", &[output]))
        .u8(0);
    let pin = hash_parts(format, &[&cert.buf]);
    cert.fixed(&pin);
    let envelopes: Vec<_> = fixture
        .records
        .iter()
        .map(|record| record.envelope.encode())
        .collect();
    let checkpoint = Checkpoint {
        book_id: BOOK,
        branch_id: [0; 16],
        through_seq: fixture
            .records
            .iter()
            .map(|record| record.envelope.commit_seq)
            .max()
            .unwrap(),
        leaf_count: envelopes.len() as u64,
        root: root_of(
            &envelopes
                .iter()
                .map(|bytes| leaf_hash(bytes))
                .collect::<Vec<_>>(),
        ),
    };
    let mut prefix = Writer::default();
    prefix
        .bytes(PREFIX_FORMAT)
        .fixed(&checkpoint.encode())
        .count(envelopes.len());
    for envelope in envelopes {
        prefix.bytes(&envelope);
    }
    let mut bundle = Writer::default();
    bundle
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(3)
        .u16(0)
        .bytes(&cert.buf)
        .bytes(b"externally trusted fixture")
        .bytes(&prefix.buf)
        .count(fixture.records.len());
    for record in &fixture.records {
        bundle.u32(record.len as u32).bytes(&record.bytes);
    }
    bundle.count(0).count(docs.len());
    for (name, bytes) in docs {
        bundle.bytes(name.as_bytes()).bytes(bytes);
    }
    bundle.bytes(spec).count(fixture.rates.len());
    let mut rates: Vec<_> = fixture.rates.iter().collect();
    rates.sort_by_key(|rate| rate.oid);
    for rate in rates {
        bundle.fixed(&rate.oid).bytes(&rate.document);
    }
    Packed {
        bytes: bundle.buf,
        checkpoint: SignedCheckpoint {
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
        },
        pin,
    }
}

#[test]
fn native_group_bundle_recomputes_eliminations_minority_equity_and_both_statements() {
    let fixture = Fixture::new(false);
    let expected = fixture.output(Lie::None);
    let report = fixture.pack(&expected).verify().unwrap();
    let group = report.consolidation.as_ref().unwrap();
    assert_eq!(report.output, expected);
    assert_eq!(group.base_unit, None);
    assert_eq!(group.members.len(), 2);
    assert_eq!(group.members[1].ownership_bps, Some(8000));
    assert_eq!(group.eliminations.len(), 3);
    assert_eq!(group.income_eliminations.len(), 2);
    assert_eq!(
        group.equity_reconciliations[0].non_controlling_interest_equity,
        34
    );
    assert_eq!(
        group.equity_reconciliations[0].controlling_interest_equity,
        1216
    );
    assert_eq!(
        group.equity_reconciliations[0].consolidated_total_equity,
        1250
    );
    assert_eq!(group.equity_reconciliations.len(), 13);
    let income = group
        .income_statement
        .lines
        .iter()
        .find(|line| line.code == "net_income" && line.unit == 0)
        .unwrap();
    assert_eq!(income.amounts, [216]);
    assert!(
        group
            .balance_sheet
            .mappings
            .iter()
            .any(|mapping| mapping.code == "3100")
    );
}

#[test]
fn functional_group_bundle_uses_retained_fx_without_remeasuring_at_the_newest_quote() {
    let fixture = Fixture::new(true);
    let expected = fixture.output(Lie::None);
    let report = fixture.pack(&expected).verify().unwrap();
    let group = report.consolidation.as_ref().unwrap();
    assert_eq!(report.output, expected);
    assert_eq!(group.base_unit, Some(0));
    assert_eq!(group.equity_reconciliations.len(), 1);
    assert_eq!(
        group.equity_reconciliations[0].non_controlling_interest_equity,
        51
    );
    assert_eq!(
        group.equity_reconciliations[0].consolidated_total_equity,
        1875
    );
    let income = group
        .income_statement
        .lines
        .iter()
        .find(|line| line.code == "net_income")
        .unwrap();
    assert_eq!(income.amounts, [324]);
    assert!(
        group
            .book_parameters_source
            .contains("genesis-registration-not-proved")
    );
}

#[test]
fn pinned_groups_ignore_later_backdates_role_removals_and_ownership_changes() {
    for functional in [false, true] {
        let fixture = Fixture::new(functional);
        let complete = fixture.pack(&fixture.output(Lie::None));
        let from_later_checkpoint = complete.verify().unwrap();
        assert!(from_later_checkpoint.checkpoint.checkpoint.through_seq > fixture.known_at);
        let mut old_prefix = fixture.clone();
        old_prefix
            .records
            .retain(|record| record.envelope.commit_seq <= fixture.known_at);
        let old = old_prefix.pack(&old_prefix.output(Lie::None));
        assert_eq!(complete.pin, old.pin);
        assert_eq!(old.verify().unwrap().output, from_later_checkpoint.output);
        let mut current = fixture;
        current.known_at = current.records.last().unwrap().envelope.commit_seq;
        let error = current
            .pack(&current.output(Lie::None))
            .verify()
            .unwrap_err();
        assert_eq!(error.predicate, "consolidation_recomputation");
        assert!(error.detail.contains("active group parent"), "{error}");
    }
}

#[test]
fn resealed_output_cannot_omit_members_eliminations_or_allocate_the_wrong_nci() {
    for functional in [false, true] {
        let fixture = Fixture::new(functional);
        let authentic = fixture.pack(&fixture.output(Lie::None));
        authentic.verify().unwrap();
        for lie in [
            Lie::OmitMember,
            Lie::OmitIntercompany,
            Lie::ChangeNci,
            Lie::IncludePendingIncome,
        ] {
            let forged = fixture.pack(&fixture.output(lie));
            assert_ne!(forged.pin, authentic.pin);
            let error = forged.verify().unwrap_err();
            assert_eq!(error.predicate, "report_recomputation", "{lie:?}: {error}");
        }
    }
}

#[test]
fn fresh_source_commitments_still_require_roles_and_an_acyclic_single_parent_graph() {
    for functional in [false, true] {
        let original = Fixture::new(functional);
        for attack in 0..3 {
            let mut fixture = original.clone();
            let (index, replacement, detail) = match attack {
                0 => (
                    fixture.nci_role,
                    role(
                        fixture.records[fixture.nci_role].envelope.commit_seq,
                        "3200",
                        "noncontrolling_interest",
                        false,
                    ),
                    "noncontrolling_interest",
                ),
                1 => {
                    fixture.records[fixture.ownership] = ownership(
                        fixture.records[fixture.ownership].envelope.commit_seq,
                        "P",
                        "S",
                        1,
                        1,
                    );
                    (
                        fixture.nci_role,
                        ownership(
                            fixture.records[fixture.nci_role].envelope.commit_seq,
                            "S",
                            "P",
                            1,
                            1,
                        ),
                        "cycle",
                    )
                }
                2 => (
                    fixture.ownership,
                    ownership(
                        fixture.records[fixture.ownership].envelope.commit_seq,
                        "P",
                        "S",
                        7,
                        10,
                    ),
                    "investment",
                ),
                _ => unreachable!(),
            };
            fixture.records[index] = replacement;
            let error = fixture
                .pack(&fixture.output(Lie::None))
                .verify()
                .unwrap_err();
            assert_eq!(error.predicate, "consolidation_recomputation", "{error}");
            assert!(
                error.detail.to_lowercase().contains(detail),
                "{detail}: {error}"
            );
        }
    }
}

#[test]
fn entity_attribution_is_recomputed_even_when_the_whole_book_totals_do_not_change() {
    for functional in [false, true] {
        let mut fixture = Fixture::new(functional);
        // Move both balanced legs to the parent: the ordinary book TB is
        // identical, but the subsidiary's earnings and NCI entitlement differ.
        fixture.replace_sale_entity(Some("P"));
        assert_eq!(
            fixture
                .pack(&fixture.output(Lie::None))
                .verify()
                .unwrap_err()
                .predicate,
            "report_recomputation"
        );
        for entity in [None, Some("undeclared")] {
            let mut fixture = Fixture::new(functional);
            fixture.replace_sale_entity(entity);
            let error = fixture
                .pack(&fixture.output(Lie::None))
                .verify()
                .unwrap_err();
            assert_eq!(
                error.predicate,
                if functional {
                    "functional_entity"
                } else {
                    "consolidation_recomputation"
                },
                "{error}"
            );
        }
    }
}

#[test]
fn unbalanced_intercompany_categories_cannot_cancel_against_each_other() {
    for functional in [false, true] {
        let mut fixture = Fixture::new(functional);
        let seq = fixture.records[fixture.sub_service].envelope.commit_seq;
        // Each source entry is balanced. The extra expense and liability
        // would cancel if balance-sheet and activity IC were pooled together.
        fixture.records[fixture.sub_service] = entry(
            seq,
            1,
            40,
            b"subsidiary-service",
            &entity_pair(Some("S"), "5100", "2000", 12, functional),
            functional.then(|| (1, &fixture.rates[1], None)),
            None,
            None,
        );
        let error = fixture
            .pack(&fixture.output(Lie::None))
            .verify()
            .unwrap_err();
        assert_eq!(error.predicate, "consolidation_recomputation");
        assert!(error.detail.contains("intercompany"), "{error}");
    }
}

#[test]
fn functional_group_requires_each_original_conversion_and_complete_rate_bodies() {
    let mut fixture = Fixture::new(true);
    let seq = fixture.records[fixture.sub_sale].envelope.commit_seq;
    let mut legs = entity_pair(Some("S"), "1000", "4000", 100, true);
    for leg in &mut legs {
        leg.base = Some(152);
    }
    fixture.records[fixture.sub_sale] = entry(
        seq,
        1,
        40,
        b"subsidiary-sale",
        &legs,
        Some((1, &fixture.rates[1], None)),
        None,
        None,
    );
    assert_eq!(
        fixture
            .pack(&fixture.output(Lie::None))
            .verify()
            .unwrap_err()
            .predicate,
        "functional_valuation"
    );
    let mut fixture = Fixture::new(true);
    fixture.rates.pop();
    assert_eq!(
        fixture
            .pack(&fixture.output(Lie::None))
            .verify()
            .unwrap_err()
            .predicate,
        "functional_rates"
    );
}

#[test]
fn consolidation_recipient_pins_and_role_semantics_are_required() {
    for functional in [false, true] {
        let fixture = Fixture::new(functional);
        let output = fixture.output(Lie::None);
        let packed = fixture.pack(&output);
        let verify = |pin| {
            verify_report_with_inputs(&packed.bytes, &[], None, None, pin, None, |_, _| {
                Ok(packed.checkpoint.clone())
            })
        };
        assert_eq!(
            verify(None).unwrap_err().predicate,
            "report_input_authority"
        );
        assert_eq!(
            verify(Some(&[77; 32])).unwrap_err().predicate,
            "recipient_certificate"
        );
        let wrong = pack(
            &fixture,
            &output,
            &book(&["P", "S"]),
            &documents(functional, true),
        );
        assert_eq!(wrong.verify().unwrap_err().predicate, "registry_closure");
        let unknown_member = pack(
            &fixture,
            &output,
            &book(&["P", "X"]),
            &documents(functional, false),
        );
        assert_eq!(
            unknown_member.verify().unwrap_err().predicate,
            if functional {
                "functional_entity"
            } else {
                "consolidation_recomputation"
            }
        );
    }
}
