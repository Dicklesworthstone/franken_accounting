//! Canon end to end through the public API: compile a source, evaluate it
//! over a recorded event, and refuse what cannot be proven or computed.

use fa_canon::{
    CompiledRule, EvalError, InputType, InputValue, Inputs, Produces, compile, evaluate,
};
use fa_model::{Erasable, EventKind, EventResource, EventSpec, EvidenceRef, Oid, SealKey};
use fa_money::{Amount, RoundingLaw, Side, Unit, UnitKind, UnitRegistry};
use fa_time::DateDay;

const SALE: &str = r#"
rule sale_with_tax v3 for event Sale {
  inputs { as_of: date }
  let net = event.resource("net", "USD")
  let tax = net * 7 / 100 round HalfEven   # sales tax at 7%
  debit  "1200" net + tax dims { cost_center = "CC1" }
  credit "4000" net
  credit "2300" tax
  effective as_of
}
"#;

fn units() -> UnitRegistry {
    UnitRegistry::with_defaults()
}

fn usd(units: &UnitRegistry, mantissa: i128) -> Amount {
    Amount::new(units.lookup("USD").unwrap(), mantissa)
}

fn event(kind: EventKind, resources: Vec<(&str, Amount)>) -> EventSpec {
    let key = SealKey([9u8; 32]);
    EventSpec {
        code: "EVT-1".to_string(),
        kind,
        occurred_on: DateDay::from_ymd(2026, 3, 20).unwrap(),
        description: Erasable::seal(&"a sale".to_string(), None, &key, [1u8; 32], [2u8; 24]),
        participants: Vec::new(),
        resources: resources
            .into_iter()
            .map(|(label, amount)| EventResource {
                label: label.to_string(),
                amount,
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

fn as_of() -> Inputs {
    let mut inputs = Inputs::new();
    inputs.set(
        "as_of",
        InputValue::Date(DateDay::from_ymd(2026, 3, 31).unwrap()),
    );
    inputs
}

fn legs(derivation: &fa_canon::Derivation) -> Vec<(Side, &str, i128)> {
    derivation
        .legs
        .iter()
        .map(|l| (l.side, l.account.as_str(), l.amount.mantissa))
        .collect()
}

#[test]
fn a_balanced_rule_derives_exact_legs_from_an_event() {
    let units = units();
    let rule = compile(SALE, &units).unwrap();
    assert_eq!(
        (rule.name(), rule.version(), rule.event()),
        ("sale_with_tax", 3, EventKind::Sale)
    );
    let deps = rule.dependencies();
    assert_eq!(
        deps.accounts.iter().map(String::as_str).collect::<Vec<_>>(),
        ["1200", "2300", "4000"]
    );
    assert_eq!(
        deps.laws.iter().map(String::as_str).collect::<Vec<_>>(),
        ["HalfEven"]
    );
    assert!(
        deps.resources
            .contains(&("net".to_string(), "USD".to_string()))
    );
    assert!(
        deps.dimensions
            .contains(&("cost_center".to_string(), "CC1".to_string()))
    );

    // 100.05 × 7% = 7.0035, which HalfEven rounds to 7.00.
    let sale = event(EventKind::Sale, vec![("net", usd(&units, 10_005))]);
    let derived = evaluate(&rule, &sale, &as_of()).unwrap();
    assert_eq!(
        legs(&derived),
        [
            (Side::Debit, "1200", 10_705),
            (Side::Credit, "4000", 10_005),
            (Side::Credit, "2300", 700),
        ]
    );
    assert_eq!(
        derived.legs[0].dims,
        [("cost_center".to_string(), "CC1".to_string())]
    );
    assert_eq!(derived.effective, DateDay::from_ymd(2026, 3, 31).unwrap());
    assert_eq!(derived.rule_version_oid, rule.ir_digest());
    assert_eq!(derived.event_digest, sale.event_digest().unwrap());

    // 100.50 × 7% = 7.035 exactly half way: HalfEven goes to the even 7.04.
    let tie = event(EventKind::Sale, vec![("net", usd(&units, 10_050))]);
    let derived_tie = evaluate(&rule, &tie, &as_of()).unwrap();
    assert_eq!(
        legs(&derived_tie),
        [
            (Side::Debit, "1200", 10_754),
            (Side::Credit, "4000", 10_050),
            (Side::Credit, "2300", 704),
        ]
    );
    // The inputs digest moves with the inputs and only with them.
    let mut later = Inputs::new();
    later.set(
        "as_of",
        InputValue::Date(DateDay::from_ymd(2026, 4, 1).unwrap()),
    );
    assert_eq!(derived_tie.inputs_digest, derived.inputs_digest);
    assert_ne!(
        evaluate(&rule, &tie, &later).unwrap().inputs_digest,
        derived_tie.inputs_digest
    );
}

#[test]
fn the_content_address_ignores_let_names_and_layout_but_not_meaning() {
    let units = units();
    let digest = |source: &str| compile(source, &units).unwrap().ir_digest();
    let base = digest(SALE);
    let renamed = r#"rule sale_with_tax v3 for event Sale { inputs { as_of: date }
        let amount = event.resource("net", "USD") // renamed, reflowed
        let levy = amount * 7 / 100 round HalfEven
        debit "1200" amount + levy dims { cost_center = "CC1" }
        credit "4000" amount credit "2300" levy effective as_of }"#;
    assert_eq!(digest(renamed), base);
    for changed in [
        SALE.replace("HalfEven", "HalfUp"),
        SALE.replace(" v3 ", " v4 "),
        SALE.replace("\"CC1\"", "\"CC2\""),
        SALE.replace("effective as_of", "effective event.occurred_on"),
    ] {
        assert_ne!(digest(&changed), base, "{changed}");
    }
    let rule = compile(SALE, &units).unwrap();
    assert_eq!(
        rule.ir_digest(),
        fa_model::domain_digest(fa_canon::CANON_IR_DOMAIN, &[rule.ir()])
    );
}

#[test]
fn a_stored_ir_decodes_through_the_same_validation_and_proof() {
    let units = units();
    let rule = compile(SALE, &units).unwrap();
    let decoded = CompiledRule::decode(rule.ir(), &units).unwrap();
    assert_eq!(decoded, rule);
    let sale = event(EventKind::Sale, vec![("net", usd(&units, 10_005))]);
    assert_eq!(
        evaluate(&decoded, &sale, &as_of()).unwrap(),
        evaluate(&rule, &sale, &as_of()).unwrap()
    );

    // A stored IR whose credit literal was changed no longer balances: the
    // decoder re-runs the proof rather than trusting what was stored.
    let plain = compile(
        r#"rule r v1 for event Sale { debit "1" "1.00 USD" credit "2" "1.00 USD" }"#,
        &units,
    )
    .unwrap();
    let hundred = 100i128.to_le_bytes();
    let at: Vec<usize> = plain
        .ir()
        .windows(16)
        .enumerate()
        .filter(|(_, w)| *w == hundred)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(at.len(), 2, "both literals are 100 minor units");
    let mut mutated = plain.ir().to_vec();
    mutated[at[1]] = 101;
    let error = CompiledRule::decode(&mutated, &units).unwrap_err();
    assert!(error.0.contains("does not balance in USD"), "{error}");

    let bytes = plain.ir();
    assert!(CompiledRule::decode(&bytes[..bytes.len() - 1], &units).is_err());
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(CompiledRule::decode(&trailing, &units).is_err());

    // A book must hold exactly the unit version and scale the IR spells.
    let error = CompiledRule::decode(bytes, &UnitRegistry::empty()).unwrap_err();
    assert!(error.0.contains("not registered in this book"), "{error}");
    let mut other_scale = UnitRegistry::empty();
    other_scale
        .register(Unit {
            code: "USD".to_string(),
            scale: 3,
            version: 0,
            kind: UnitKind::Currency { iso4217: 840 },
            rounding_default: RoundingLaw::HalfEven,
        })
        .unwrap();
    let error = CompiledRule::decode(bytes, &other_scale).unwrap_err();
    assert!(error.0.contains("another scale"), "{error}");
}

#[test]
fn a_rule_is_compiled_only_when_its_balance_is_proven_per_unit() {
    let units = units();
    let unbalanced = SALE.replace("credit \"2300\" tax\n", "");
    let error = compile(&unbalanced, &units).unwrap_err();
    assert!(error.message.contains("does not balance in USD"), "{error}");
    assert!(
        error.message.contains("never adds a residual leg"),
        "{error}"
    );

    // Two laws round differently, so the checker cannot equate them.
    let two_laws = r#"rule r v1 for event Sale {
        debit "1" event.resource("net", "USD") * 7 / 100 round HalfEven
        credit "2" event.resource("net", "USD") * 7 / 100 round HalfUp }"#;
    assert!(
        compile(two_laws, &units)
            .unwrap_err()
            .message
            .contains("does not balance")
    );

    // The same rounding of the same value, written differently, is one atom.
    let same_atom = r#"rule r v1 for event Sale {
        inputs { fee: amount("USD") }
        let net = event.resource("net", "USD")
        debit "1" (net + fee) * 7 / 100 round HalfEven
        credit "2" (fee + net) * 14 / 200 round HalfEven }"#;
    let rule = compile(same_atom, &units).unwrap();
    let mut fee = Inputs::new();
    fee.set("fee", InputValue::Amount(usd(&units, 333)));
    let derived = evaluate(
        &rule,
        &event(EventKind::Sale, vec![("net", usd(&units, 10_000))]),
        &fee,
    )
    .unwrap();
    // (100.00 + 3.33) × 7% = 7.2331 → 7.23 on both sides.
    assert_eq!(
        legs(&derived),
        [(Side::Debit, "1", 723), (Side::Credit, "2", 723)]
    );

    // Integer scaling is linear: 2·x on one side balances x + x on the other.
    let linear = r#"rule r v1 for event Sale {
        let x = event.resource("net", "USD")
        debit "1" x * 2
        credit "2" x + x - "0.00 USD" }"#;
    compile(linear, &units).unwrap();
    // A balance in one unit does not excuse another.
    let two_units = r#"rule r v1 for event Sale {
        debit "1" event.resource("net", "USD")
        credit "2" event.resource("net", "USD")
        debit "3" event.resource("fx", "EUR") }"#;
    assert!(
        compile(two_units, &units)
            .unwrap_err()
            .message
            .contains("does not balance in EUR")
    );
}

/// Plan §10.2 rule families: a rule names the entry class its derivations
/// post. The class is part of the IR, so it moves the content address and
/// survives decoding, and only the bound families compile.
#[test]
fn a_rule_names_the_entry_class_it_produces() {
    let units = units();
    let rule = |header: &str| {
        compile(
            &format!(
                r#"rule rent v1 for event Accrual {header} {{ debit "6000" "1.00 USD" credit "2100" "1.00 USD" }}"#
            ),
            &units,
        )
    };
    let original = rule("").unwrap();
    assert_eq!(original.produces(), Produces::Original);
    assert_eq!(
        rule("produces Original").unwrap().ir_digest(),
        original.ir_digest()
    );
    let adjusting = rule("produces Adjusting").unwrap();
    assert_eq!(adjusting.produces(), Produces::Adjusting);
    assert_ne!(adjusting.ir_digest(), original.ir_digest());
    assert_eq!(
        CompiledRule::decode(adjusting.ir(), &units).unwrap(),
        adjusting
    );
    // The two IRs differ in the class byte alone; an unknown class does not
    // decode.
    let differ: Vec<usize> = (0..original.ir().len())
        .filter(|&i| original.ir()[i] != adjusting.ir()[i])
        .collect();
    assert_eq!(differ.len(), 1, "{differ:?}");
    let mut unknown = adjusting.ir().to_vec();
    unknown[differ[0]] = 9;
    let error = CompiledRule::decode(&unknown, &units).unwrap_err();
    assert!(error.0.contains("rule.produces"), "{error}");
    for (header, needle) in [
        ("produces Allocation", "not bound to a rule family"),
        ("produces Accrued", "not an entry class"),
        ("produces", "expected the entry class"),
    ] {
        let error = rule(header).unwrap_err();
        assert!(error.message.contains(needle), "{header}\n=> {error}");
    }
}

/// An Adjusting rule schedules its entry's reversal (`reverses`): a date
/// after the effective date, carried by the IR and the derivation.
#[test]
fn an_adjusting_rule_schedules_its_reversal_after_its_effective_date() {
    let units = units();
    let source = r#"rule accrue_rent v1 for event Accrual produces Adjusting {
  inputs { back: date }
  let rent = event.resource("rent", "USD")
  debit "6000" rent
  credit "2100" rent
  reverses back
}"#;
    let rule = compile(source, &units).unwrap();
    assert_eq!(CompiledRule::decode(rule.ir(), &units).unwrap(), rule);
    let accrual = event(EventKind::Accrual, vec![("rent", usd(&units, 10_000))]);
    let on = |day: DateDay| {
        let mut inputs = Inputs::new();
        inputs.set("back", InputValue::Date(day));
        inputs
    };
    let april = DateDay::from_ymd(2026, 4, 1).unwrap();
    let derived = evaluate(&rule, &accrual, &on(april)).unwrap();
    assert_eq!(derived.reverse_on, Some(april));
    assert_eq!(derived.effective, accrual.occurred_on);
    // A reversal on or before the effective date cannot be scheduled.
    assert!(matches!(
        evaluate(&rule, &accrual, &on(accrual.occurred_on)),
        Err(EvalError::ReversalNotAfter { .. })
    ));
    // Without the clause there is no reversal, and the address moves.
    let plain = compile(&source.replace("reverses back", ""), &units).unwrap();
    assert_ne!(plain.ir_digest(), rule.ir_digest());
    assert_eq!(
        evaluate(&plain, &accrual, &on(april)).unwrap().reverse_on,
        None
    );
    for (changed, needle) in [
        (
            source.replace(" produces Adjusting", ""),
            "only an Adjusting entry schedules its reversal",
        ),
        (
            source.replace("reverses back", "reverses back reverses back"),
            "names its reversal date once",
        ),
        (
            source.replace("reverses back", "reverses rent"),
            "not a declared date input",
        ),
    ] {
        let error = compile(&changed, &units).unwrap_err();
        assert!(error.message.contains(needle), "{changed}\n=> {error}");
    }
}

#[test]
fn units_laws_names_and_kinds_are_checked_before_anything_runs() {
    let units = units();
    let base = |body: &str| {
        format!("rule r v1 for event Sale {{ let net = event.resource(\"net\", \"USD\") {body} }}")
    };
    for (source, needle) in [
        (
            base(r#"debit "1" net + "1.00 EUR" credit "2" net"#),
            "cannot be added",
        ),
        (
            base(r#"debit "1" net * 7 / 100 round Banker credit "2" net"#),
            "not a registered rounding law",
        ),
        (
            base(r#"debit "1" net credit "2" net effective today"#),
            "not a declared date input",
        ),
        (
            base(r#"debit "1" today credit "2" net"#),
            "not a let or a declared input",
        ),
        (
            base(r#"debit "1" event.resource("x", "XYZ") credit "2" net"#),
            "not registered in this book",
        ),
        (
            base(r#"debit "1" "1.001 USD" credit "2" net"#),
            "fractional digits",
        ),
        (
            base(r#"debit "1" net / 3 credit "2" net / 3"#),
            "names its rounding law",
        ),
        (
            base(r#"debit "1" net round HalfEven credit "2" net"#),
            "divides nothing",
        ),
        (
            base(r#"debit "1" net dims { color = "red" } credit "2" net"#),
            "not a registered dimension",
        ),
        (
            base(r#"debit "1" net dims { project = "P", project = "Q" } credit "2" net"#),
            "tagged twice",
        ),
        (
            base(r#"debit "1" net credit "2" net / 0 round HalfEven"#),
            "division by zero",
        ),
        (
            base(r#"let net = net debit "1" net credit "2" net"#),
            "already bound",
        ),
        (
            base(r#"debit "1" net debit "2" net"#),
            "at least one debit and one credit",
        ),
        (base(r#"debit " 1" net credit "2" net"#), "without spaces"),
        (
            "rule r v1 for event Lease { debit \"1\" \"1.00 USD\" credit \"2\" \"1.00 USD\" }"
                .to_string(),
            "not a registered event kind",
        ),
        (
            "rule r v1 for event Sale { inputs { d: date } debit \"1\" d credit \"2\" d }"
                .to_string(),
            "is a date input",
        ),
    ] {
        let error = compile(&source, &units).unwrap_err();
        assert!(error.message.contains(needle), "{source}\n=> {error}");
    }
}

#[test]
fn evaluation_refuses_what_it_cannot_compute_exactly() {
    let units = units();
    let rule = compile(SALE, &units).unwrap();
    let sale = event(EventKind::Sale, vec![("net", usd(&units, 10_000))]);

    let purchase = event(EventKind::Purchase, vec![("net", usd(&units, 10_000))]);
    assert_eq!(
        evaluate(&rule, &purchase, &as_of()).unwrap_err(),
        EvalError::WrongEventKind {
            rule: EventKind::Sale,
            event: EventKind::Purchase
        }
    );
    let no_net = event(EventKind::Sale, vec![("gross", usd(&units, 10_000))]);
    assert!(matches!(
        evaluate(&rule, &no_net, &as_of()).unwrap_err(),
        EvalError::MissingResource { label } if label == "net"
    ));
    let twice = event(
        EventKind::Sale,
        vec![("net", usd(&units, 1)), ("net", usd(&units, 2))],
    );
    assert!(matches!(
        evaluate(&rule, &twice, &as_of()).unwrap_err(),
        EvalError::AmbiguousResource { .. }
    ));
    let euros = event(
        EventKind::Sale,
        vec![("net", Amount::new(units.lookup("EUR").unwrap(), 10_000))],
    );
    assert!(matches!(
        evaluate(&rule, &euros, &as_of()).unwrap_err(),
        EvalError::ResourceUnit { .. }
    ));
    assert!(matches!(
        evaluate(&rule, &sale, &Inputs::new()).unwrap_err(),
        EvalError::MissingInput { name } if name == "as_of"
    ));
    let mut extra = as_of();
    extra.set(
        "today",
        InputValue::Date(DateDay::from_ymd(2026, 5, 1).unwrap()),
    );
    assert!(matches!(
        evaluate(&rule, &sale, &extra).unwrap_err(),
        EvalError::UndeclaredInput { name } if name == "today"
    ));
    let mut wrong_type = Inputs::new();
    wrong_type.set("as_of", InputValue::Amount(usd(&units, 1)));
    assert_eq!(
        evaluate(&rule, &sale, &wrong_type).unwrap_err(),
        EvalError::InputType {
            name: "as_of".to_string(),
            expected: InputType::Date
        }
    );

    let net_of_fee = compile(
        r#"rule r v1 for event Sale { inputs { fee: amount("USD") }
            debit "5000" event.resource("net", "USD") - fee
            credit "1000" event.resource("net", "USD") - fee }"#,
        &units,
    )
    .unwrap();
    let mut fee = Inputs::new();
    fee.set("fee", InputValue::Amount(usd(&units, 10_001)));
    assert!(matches!(
        evaluate(&net_of_fee, &sale, &fee).unwrap_err(),
        EvalError::NegativeLeg { account, .. } if account == "5000"
    ));
    // A leg that evaluates to zero is omitted, never posted.
    fee.set("fee", InputValue::Amount(usd(&units, 10_000)));
    assert!(evaluate(&net_of_fee, &sale, &fee).unwrap().legs.is_empty());

    let huge = compile(
        r#"rule r v1 for event Sale {
            debit "1" event.resource("net", "USD") * 18446744073709551615
            credit "2" event.resource("net", "USD") * 18446744073709551615 }"#,
        &units,
    )
    .unwrap();
    let big = event(EventKind::Sale, vec![("net", usd(&units, 10_i128.pow(30)))]);
    assert_eq!(
        evaluate(&huge, &big, &Inputs::new()).unwrap_err(),
        EvalError::Overflow {
            at: "the leg on 1".to_string()
        }
    );
}
