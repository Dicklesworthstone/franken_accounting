//! The Canon differential (plan §16.1, bead fa-c34): every rule the engine
//! compiles is evaluated by fa-canon and by fa-reference's independent naive
//! reading of the same source text (its own parser, unbounded integers and
//! rounding laws read from their registered definitions), over the same
//! events and inputs. The two must agree on every leg, date and failure
//! class.
//!
//! Rules come from a hand-written set (every rounding law at ties of both
//! signs, units of other scales, dimensions, inputs, effective and reversal
//! dates, every failure class) and from a seeded generator of balanced
//! rules. The test counts what it compared, so a vacuous run fails.
//!
//! No-claim: agreement shows the engine computes what the language says for
//! these rules; it does not show a rule encodes the right policy, and values
//! stay far inside i128, so the overflow path is not compared.

use std::collections::BTreeMap;

use fa_canon::{CompiledRule, EvalError, InputValue, Inputs, compile, evaluate};
use fa_model::{Erasable, EventKind, EventResource, EventSpec, EvidenceRef, Oid, SealKey};
use fa_money::{Amount, Side, UnitRegistry};
use fa_reference::canon::{self as naive, Failure};
use fa_time::DateDay;

const LAWS: [&str; 9] = [
    "HalfUp",
    "HalfDown",
    "HalfEven",
    "HalfAwayFromZero",
    "HalfTowardZero",
    "Ceiling",
    "Floor",
    "TowardZero",
    "AwayFromZero",
];

/// A deterministic generator (Knuth's MMIX LCG): the run is a seed, not luck.
struct Lcg(u64);

impl Lcg {
    fn below(&mut self, n: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % n
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len() as u64) as usize]
    }
}

/// One event and its inputs, in the reference's plain values.
struct Case {
    event: naive::Event,
    inputs: BTreeMap<String, naive::Input>,
}

fn kind(name: &str) -> EventKind {
    EventKind::from_name(name).unwrap()
}

fn engine_event(units: &UnitRegistry, event: &naive::Event) -> EventSpec {
    let key = SealKey([9u8; 32]);
    EventSpec {
        code: "EVT-D".to_string(),
        kind: kind(&event.kind),
        occurred_on: DateDay(event.occurred_on),
        description: Erasable::seal(&String::new(), None, &key, [1u8; 32], [2u8; 24]),
        participants: Vec::new(),
        resources: event
            .resources
            .iter()
            .map(|(label, unit, mantissa)| EventResource {
                label: label.clone(),
                amount: Amount::new(units.lookup(unit).unwrap(), *mantissa),
                instrument: None,
            })
            .collect(),
        evidence: vec![EvidenceRef {
            document_oid: Oid([11u8; 32]),
            doc_commit: [12u8; 32],
            role: 1,
        }],
        external_ids: Vec::new(),
    }
}

fn engine_inputs(units: &UnitRegistry, inputs: &BTreeMap<String, naive::Input>) -> Inputs {
    let mut out = Inputs::new();
    for (name, value) in inputs {
        out.set(
            name.clone(),
            match value {
                naive::Input::Date(day) => InputValue::Date(DateDay(*day)),
                naive::Input::Amount(unit, mantissa) => {
                    InputValue::Amount(Amount::new(units.lookup(unit).unwrap(), *mantissa))
                }
            },
        );
    }
    out
}

/// The engine's derivation in the reference's terms.
fn engine(
    rule: &CompiledRule,
    units: &UnitRegistry,
    case: &Case,
) -> Result<naive::Derivation, Failure> {
    let derived = evaluate(
        rule,
        &engine_event(units, &case.event),
        &engine_inputs(units, &case.inputs),
    )
    .map_err(|error| match error {
        EvalError::WrongEventKind { .. } => Failure::WrongEventKind,
        EvalError::UndeclaredInput { .. } => Failure::UndeclaredInput,
        EvalError::MissingInput { .. } => Failure::MissingInput,
        EvalError::InputType { .. } => Failure::InputType,
        EvalError::MissingResource { .. } => Failure::MissingResource,
        EvalError::AmbiguousResource { .. } => Failure::AmbiguousResource,
        EvalError::ResourceUnit { .. } => Failure::ResourceUnit,
        EvalError::NegativeLeg { .. } => Failure::NegativeLeg,
        EvalError::Overflow { .. } => Failure::OutOfRange,
        EvalError::ReversalNotAfter { .. } => Failure::ReversalNotAfter,
        EvalError::Encode(message) => Failure::Syntax(message),
    })?;
    Ok(naive::Derivation {
        produces: rule.produces().name().to_string(),
        effective: derived.effective.0,
        reverse_on: derived.reverse_on.map(|day| day.0),
        legs: derived
            .legs
            .iter()
            .map(|leg| {
                let mut dims = leg.dims.clone();
                dims.sort();
                naive::Leg {
                    debit: leg.side == Side::Debit,
                    account: leg.account.clone(),
                    unit: units.get(leg.amount.unit).unwrap().code.clone(),
                    mantissa: leg.amount.mantissa,
                    dims,
                }
            })
            .collect(),
    })
}

/// Runs both readers over every case and tallies the outcomes by class.
struct Differential {
    units: UnitRegistry,
    scales: BTreeMap<String, u32>,
    outcomes: BTreeMap<String, usize>,
}

impl Differential {
    fn new() -> Self {
        let units = UnitRegistry::with_defaults();
        let scales = ["USD", "EUR", "JPY"]
            .into_iter()
            .map(|code| {
                let id = units.lookup(code).unwrap();
                (code.to_string(), u32::from(units.get(id).unwrap().scale))
            })
            .collect();
        Self {
            units,
            scales,
            outcomes: BTreeMap::new(),
        }
    }

    fn run(&mut self, source: &str, cases: &[Case]) {
        let rule = compile(source, &self.units)
            .unwrap_or_else(|error| panic!("the engine refuses\n{source}\n=> {error}"));
        for case in cases {
            let engine = engine(&rule, &self.units, case);
            let reference = naive::evaluate(source, &self.scales, &case.event, &case.inputs);
            assert_eq!(
                engine, reference,
                "\n{source}\nevent {:?}\ninputs {:?}",
                case.event, case.inputs
            );
            let class = match &engine {
                Ok(_) => "derived".to_string(),
                Err(failure) => format!("{failure:?}"),
            };
            *self.outcomes.entry(class).or_insert(0) += 1;
        }
    }

    fn count(&self, class: &str) -> usize {
        self.outcomes.get(class).copied().unwrap_or(0)
    }
}

fn sale(resources: &[(&str, &str, i128)]) -> naive::Event {
    naive::Event {
        kind: "Sale".into(),
        occurred_on: DateDay::from_ymd(2026, 3, 20).unwrap().0,
        resources: resources
            .iter()
            .map(|(label, unit, mantissa)| (label.to_string(), unit.to_string(), *mantissa))
            .collect(),
    }
}

fn case(event: naive::Event, inputs: &[(&str, naive::Input)]) -> Case {
    Case {
        event,
        inputs: inputs
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone()))
            .collect(),
    }
}

fn usd(mantissa: i128) -> naive::Input {
    naive::Input::Amount("USD".into(), mantissa)
}

fn day(y: i32, m: u8, d: u8) -> naive::Input {
    naive::Input::Date(DateDay::from_ymd(y, m, d).unwrap().0)
}

#[test]
fn every_law_at_every_tie_agrees_with_the_naive_reader() {
    let mut differential = Differential::new();
    // a - b in tenths of a cent's worth around every tie, both signs.
    let gaps: [i128; 10] = [25, -25, 35, -35, 24, -26, 0, 30, 15, -15];
    for law in LAWS {
        let source = format!(
            r#"rule r_{law} v1 for event Sale {{
  let d = event.resource("a", "USD") - event.resource("b", "USD")
  let x = d * 1 / 10 round {law}
  debit "1" "1000.00 USD" + x
  credit "2" "1000.00 USD" + x
}}"#
        );
        let cases: Vec<Case> = gaps
            .iter()
            .map(|gap| case(sale(&[("a", "USD", 500 + gap), ("b", "USD", 500)]), &[]))
            .collect();
        differential.run(&source, &cases);
    }
    assert_eq!(differential.count("derived"), LAWS.len() * gaps.len());
}

#[test]
fn hand_written_rules_agree_on_legs_dates_and_failures() {
    let mut differential = Differential::new();
    let tax = r#"rule sale_with_tax v3 for event Sale {
  inputs { as_of: date }
  let net = event.resource("net", "USD")
  let tax = net * 7 / 100 round HalfEven   # sales tax at 7%
  debit  "1200" net + tax dims { region = "EU", cost_center = "CC1" }
  credit "4000" net
  credit "2300" tax
  effective as_of
}"#;
    let as_of = ("as_of", day(2026, 3, 31));
    differential.run(
        tax,
        &[
            case(sale(&[("net", "USD", 10_005)]), &[as_of.clone()]),
            case(sale(&[("net", "USD", 7)]), &[as_of.clone()]),
            case(sale(&[("net", "USD", 0)]), &[as_of.clone()]),
            case(sale(&[("net", "USD", -100)]), &[as_of.clone()]),
            case(sale(&[]), &[as_of.clone()]),
            case(
                sale(&[("net", "USD", 1), ("net", "USD", 2)]),
                &[as_of.clone()],
            ),
            case(sale(&[("net", "EUR", 100)]), &[as_of.clone()]),
            case(sale(&[("net", "USD", 100)]), &[]),
            case(sale(&[("net", "USD", 100)]), &[("as_of", usd(1))]),
            case(
                sale(&[("net", "USD", 100)]),
                &[as_of.clone(), ("extra", usd(1))],
            ),
            case(
                naive::Event {
                    kind: "Purchase".into(),
                    ..sale(&[("net", "USD", 100)])
                },
                &[as_of],
            ),
        ],
    );
    // Units of other scales in one rule.
    differential.run(
        r#"rule fx_split v1 for event Receipt {
  let yen = event.resource("y", "JPY") * 3 / 4 round Floor
  let euro = event.resource("e", "EUR")
  debit "1010" yen
  credit "1020" yen
  debit "1030" euro - "0.01 EUR"
  credit "1040" euro - "0.01 EUR"
}"#,
        &[
            case(
                naive::Event {
                    kind: "Receipt".into(),
                    ..sale(&[("y", "JPY", 1_001), ("e", "EUR", 250)])
                },
                &[],
            ),
            case(
                naive::Event {
                    kind: "Receipt".into(),
                    ..sale(&[("y", "JPY", 3), ("e", "EUR", 0)])
                },
                &[],
            ),
        ],
    );
    // The adjusting family: amount inputs, an input effective date, and a
    // reversal on, before or after it.
    let accrual = |resources: &[(&str, &str, i128)]| naive::Event {
        kind: "Accrual".into(),
        ..sale(resources)
    };
    differential.run(
        r#"rule accrue_rent v2 for event Accrual produces Adjusting {
  inputs { as_of: date, back: date, fee: amount("USD") }
  let rent = event.resource("rent", "USD") + fee
  debit "6000" rent
  credit "2100" rent
  effective as_of
  reverses back
}"#,
        &[
            case(
                accrual(&[("rent", "USD", 100_000)]),
                &[
                    ("as_of", day(2026, 3, 31)),
                    ("back", day(2026, 4, 1)),
                    ("fee", usd(250)),
                ],
            ),
            case(
                accrual(&[("rent", "USD", 100_000)]),
                &[
                    ("as_of", day(2026, 3, 31)),
                    ("back", day(2026, 3, 31)),
                    ("fee", usd(250)),
                ],
            ),
            case(
                accrual(&[("rent", "USD", 100_000)]),
                &[
                    ("as_of", day(2026, 3, 31)),
                    ("back", day(2026, 4, 1)),
                    ("fee", naive::Input::Amount("EUR".into(), 250)),
                ],
            ),
            case(
                accrual(&[("rent", "USD", 100)]),
                &[
                    ("as_of", day(2026, 3, 31)),
                    ("back", day(2026, 4, 1)),
                    ("fee", usd(-200)),
                ],
            ),
        ],
    );
    differential.run(
        r#"rule defer v1 for event Accrual produces Adjusting {
  let rent = event.resource("rent", "USD")
  debit "1500" rent
  credit "6000" rent
  reverses event.occurred_on
}"#,
        &[case(accrual(&[("rent", "USD", 100)]), &[])],
    );
    // Every failure class the engine reports, reached by both readers.
    for class in [
        "derived",
        "WrongEventKind",
        "UndeclaredInput",
        "MissingInput",
        "InputType",
        "MissingResource",
        "AmbiguousResource",
        "ResourceUnit",
        "NegativeLeg",
        "ReversalNotAfter",
    ] {
        assert!(
            differential.count(class) > 0,
            "no case reached {class}: {:?}",
            differential.outcomes
        );
    }
}

/// A balanced rule over random expressions: one let, then the same
/// expression on a debit and a credit, so it always proves.
fn generated(rng: &mut Lcg, index: usize) -> String {
    fn expr(rng: &mut Lcg, depth: u32, names: &[&str]) -> String {
        if depth == 0 || rng.below(3) == 0 {
            return match rng.below(4) {
                0 => {
                    let m = rng.below(100_000);
                    format!("\"{}.{:02} USD\"", m / 100, m % 100)
                }
                1 => format!(
                    "event.resource(\"{}\", \"USD\")",
                    rng.pick(&["a", "b", "c"])
                ),
                2 if !names.is_empty() => rng.pick(names).to_string(),
                _ => "fee".to_string(),
            };
        }
        match rng.below(4) {
            0 => format!(
                "({}) + ({})",
                expr(rng, depth - 1, names),
                expr(rng, depth - 1, names)
            ),
            1 => format!(
                "({}) - ({})",
                expr(rng, depth - 1, names),
                expr(rng, depth - 1, names)
            ),
            2 => format!("({}) * {}", expr(rng, depth - 1, names), 1 + rng.below(9)),
            _ => format!(
                "({}) * {} / {} round {}",
                expr(rng, depth - 1, names),
                1 + rng.below(9),
                2 + rng.below(11),
                rng.pick(&LAWS)
            ),
        }
    }
    let x = expr(rng, 3, &[]);
    let leg = expr(rng, 3, &["x"]);
    let dims = if rng.below(2) == 0 {
        " dims { project = \"P1\" }"
    } else {
        ""
    };
    format!(
        "rule g{index} v1 for event Sale {{\n  inputs {{ fee: amount(\"USD\") }}\n  let x = {x}\n  debit \"1000\" {leg}{dims}\n  credit \"2000\" {leg}\n}}"
    )
}

#[test]
fn seeded_generated_rules_agree_with_the_naive_reader() {
    let mut differential = Differential::new();
    let mut rng = Lcg(0x00c0_ffee_0c34);
    let mut events = Vec::new();
    for _ in 0..6 {
        let mut resources = vec![
            ("a", "USD", rng.below(10_000_000) as i128),
            ("b", "USD", rng.below(10_000_000) as i128),
        ];
        match rng.below(6) {
            0 => {}
            1 => resources.push(("c", "EUR", 100)),
            _ => resources.push(("c", "USD", rng.below(10_000_000) as i128)),
        }
        events.push((resources, rng.below(1_000_000) as i128, rng.below(8) == 0));
    }
    for index in 0..400 {
        let source = generated(&mut rng, index);
        let cases: Vec<Case> = events
            .iter()
            .map(|(resources, fee, no_fee)| {
                let inputs: Vec<(&str, naive::Input)> = if *no_fee {
                    Vec::new()
                } else {
                    vec![("fee", usd(*fee))]
                };
                case(sale(resources), &inputs)
            })
            .collect();
        differential.run(&source, &cases);
    }
    let total: usize = differential.outcomes.values().sum();
    assert_eq!(total, 400 * 6);
    // Not vacuous: most comparisons derive legs, and the failure paths are
    // reached too.
    assert!(
        differential.count("derived") * 3 >= total,
        "{:?}",
        differential.outcomes
    );
    for class in ["NegativeLeg", "MissingResource"] {
        assert!(
            differential.count(class) > 0,
            "{class}: {:?}",
            differential.outcomes
        );
    }
}
