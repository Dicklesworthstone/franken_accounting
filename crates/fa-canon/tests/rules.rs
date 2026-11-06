//! Canon end to end through the public API: compile a source, evaluate it
//! over a recorded event, and refuse what cannot be proven or computed.

use fa_canon::{
    AuthorityError, AuthorityGrant, CompiledRule, EvalError, InputType, InputValue, Inputs,
    Produces, RuleAuthority, RuleIntentKind, compile, evaluate, validate_authority,
};
use fa_model::{Erasable, EventKind, EventResource, EventSpec, EvidenceRef, Oid, SealKey, Writer};
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

/// A rule compiles only when its stored IR decodes. The decoder reads no
/// text longer than 1024 bytes back, so a longer account code, rule name,
/// input name, resource label or dimension code is refused at compile time
/// instead of being journaled as an IR every later read refuses.
#[test]
fn every_compiled_ir_decodes_so_overlong_text_is_refused_at_compile() {
    let units = units();
    let at_bound = "A".repeat(1024);
    let over = "A".repeat(1025);
    let rule = |account: &str, name: &str, input: &str, label: &str, code: &str| {
        format!(
            "rule {name} v1 for event Sale {{ inputs {{ {input}: date }} \
             let net = event.resource(\"{label}\", \"USD\") \
             debit \"{account}\" net dims {{ project = \"{code}\" }} credit \"2000\" net \
             effective {input} }}"
        )
    };
    let fits = rule(&at_bound, &at_bound, &at_bound, &at_bound, &at_bound);
    let compiled = compile(&fits, &units).unwrap();
    assert_eq!(
        CompiledRule::decode(compiled.ir(), &units).unwrap(),
        compiled
    );
    for (source, what) in [
        (rule(&over, "r", "d", "net", "P"), "an account code"),
        (rule("1000", &over, "d", "net", "P"), "the rule name"),
        (rule("1000", "r", &over, "net", "P"), "an input name"),
        (rule("1000", "r", "d", &over, "P"), "a resource label"),
        (rule("1000", "r", "d", "net", &over), "a dimension code"),
    ] {
        let error = compile(&source, &units).unwrap_err();
        assert!(
            error.message.contains(&format!("{what} is 1025 bytes")),
            "{what}: {error}"
        );
    }
}

/// The balance proof shares a `let` instead of copying it, so a chain of
/// lets that each use the previous one twice no longer doubles the proof at
/// every link. Copying did: 40 links were about 2^40 terms, and every decode
/// of a stored IR paid that again.
#[test]
fn nested_lets_are_proven_without_copying_each_use() {
    let units = units();
    let mut source =
        String::from("rule chain v1 for event Sale { let a0 = event.resource(\"net\", \"USD\")\n");
    for k in 1..=40 {
        let prev = k - 1;
        source.push_str(&format!(
            "let a{k} = (a{prev} + a{prev} * 1 / 2 round HalfEven) * 1 / 3 round HalfEven\n"
        ));
    }
    source.push_str("debit \"1000\" a40 credit \"2000\" a40 }");
    let rule = compile(&source, &units).unwrap();
    assert_eq!(CompiledRule::decode(rule.ir(), &units).unwrap(), rule);
    // Each link halves the amount, so start high enough that a40 is not 0.
    let sale = event(EventKind::Sale, vec![("net", usd(&units, 1i128 << 60))]);
    let derivation = evaluate(&rule, &sale, &Inputs::new()).unwrap();
    let legs = legs(&derivation);
    assert_eq!(legs.len(), 2);
    assert_eq!(legs[0].2, legs[1].2, "{legs:?}");

    // The proof still tells the rounded atoms apart: crediting one link
    // earlier is refused, and the refusal stays bounded however deep the
    // residual's roundings nest.
    let unbalanced = source.replace("credit \"2000\" a40", "credit \"2000\" a39");
    let error = compile(&unbalanced, &units).unwrap_err();
    assert!(error.message.contains("does not balance in USD"), "{error}");
    assert!(error.message.len() < 8 * 1024, "{}", error.message.len());
}

const AUTHORIZED_SPLIT: &str = r#"
rule bounded_sale v1 for event Sale {
  authority {
    debit "1200" upto "100.00 USD" dims { project = "P1", cost_center = "CC1" }
    credit "4000" upto "100.00 USD"
  }
  let net = event.resource("net", "USD")
  debit "1200" net dims { cost_center = "CC1", project = "P1" }
  debit "1200" net dims { project = "P1", cost_center = "CC1" }
  credit "4000" net * 2
}
"#;

#[test]
fn rule_authority_sums_split_legs_and_enforces_exact_ceilings() {
    let units = units();
    let rule = compile(AUTHORIZED_SPLIT, &units).unwrap();
    let RuleAuthority::Declared(grants) = rule.authority() else {
        panic!("the source declares bounded authority");
    };
    assert_eq!(grants.len(), 2);
    assert_eq!(grants[0].ceiling, usd(&units, 10_000));
    assert_eq!(
        grants[0].dims,
        [
            ("cost_center".into(), "CC1".into()),
            ("project".into(), "P1".into())
        ]
    );

    for amount in [4_999, 5_000] {
        let sale = event(EventKind::Sale, vec![("net", usd(&units, amount))]);
        let result = evaluate(&rule, &sale, &Inputs::new()).unwrap();
        assert_eq!(result.legs.len(), 3);
        assert_eq!(result.legs[0].amount, usd(&units, amount));
        assert_eq!(result.legs[1].amount, usd(&units, amount));
        assert_eq!(validate_authority(&rule, &result), Ok(()));
    }
    let over = event(EventKind::Sale, vec![("net", usd(&units, 5_001))]);
    assert!(matches!(
        evaluate(&rule, &over, &Inputs::new()),
        Err(EvalError::Authority(AuthorityError::CeilingExceeded {
            grant: 0,
            requested,
            ceiling,
            ..
        })) if requested == 10_002 && ceiling == usd(&units, 10_000)
    ));
    let zero = event(EventKind::Sale, vec![("net", usd(&units, 0))]);
    assert!(
        evaluate(&rule, &zero, &Inputs::new())
            .unwrap()
            .legs
            .is_empty()
    );
}

#[test]
fn rule_authority_refuses_forged_cells_and_checked_sum_overflow() {
    let units = units();
    let rule = compile(AUTHORIZED_SPLIT, &units).unwrap();
    let sale = event(EventKind::Sale, vec![("net", usd(&units, 4_000))]);
    let result = evaluate(&rule, &sale, &Inputs::new()).unwrap();
    for changed in 0..6 {
        let mut forged = result.clone();
        let leg = &mut forged.legs[0];
        match changed {
            0 => leg.account = "9999".into(),
            1 => leg.side = Side::Credit,
            2 => leg.amount.unit = units.lookup("EUR").unwrap(),
            3 => leg.dims[0].1 = "CC2".into(),
            4 => leg.dims.clear(),
            5 => leg.dims.swap(0, 1),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                validate_authority(&rule, &forged),
                Err(EvalError::Authority(AuthorityError::OutsideScope {
                    leg: 0,
                    ..
                }))
            ),
            "changed={changed}"
        );
    }
    for amount in [-1, 0] {
        let mut forged = result.clone();
        forged.legs[0].amount = usd(&units, amount);
        assert!(matches!(
            validate_authority(&rule, &forged),
            Err(EvalError::Authority(AuthorityError::NonPositiveLeg {
                leg: 0,
                ..
            }))
        ));
    }
    let mut another_rule = result.clone();
    another_rule.rule_version_oid[0] ^= 1;
    assert_eq!(
        validate_authority(&rule, &another_rule),
        Err(EvalError::Authority(AuthorityError::WrongRuleVersion))
    );

    let huge = compile(
        &format!(
            "rule huge v1 for event Sale {{ authority {{ \
             debit \"1\" upto \"{} JPY\" credit \"2\" upto \"{} JPY\" }} \
             debit \"1\" \"1 JPY\" credit \"2\" \"1 JPY\" }}",
            i128::MAX,
            i128::MAX
        ),
        &units,
    )
    .unwrap();
    let mut overflowing = evaluate(&huge, &event(EventKind::Sale, vec![]), &Inputs::new()).unwrap();
    overflowing.legs[0].amount.mantissa = i128::MAX;
    overflowing.legs.insert(1, overflowing.legs[0].clone());
    assert!(matches!(
        validate_authority(&huge, &overflowing),
        Err(EvalError::Authority(AuthorityError::Overflow {
            grant: 0,
            ..
        }))
    ));
}

#[test]
fn rule_authority_is_static_complete_and_never_implicitly_widened() {
    let units = units();
    for (declaration, needle) in [
        ("", "at least one grant"),
        (r#"debit "1" upto "1.00 USD""#, "no authority grant"),
        (
            r#"debit "1" upto "1.00 EUR" credit "2" upto "1.00 USD""#,
            "no authority grant",
        ),
        (
            r#"debit "1" upto "1.00 USD" dims { project = "P" } credit "2" upto "1.00 USD""#,
            "no authority grant",
        ),
        (
            r#"debit "1" upto "0 USD" credit "2" upto "1.00 USD""#,
            "positive exact amount",
        ),
        (
            r#"debit "1" upto "-1 USD" credit "2" upto "1.00 USD""#,
            "positive exact amount",
        ),
        (
            r#"debit "1" upto "1.001 USD" credit "2" upto "1.00 USD""#,
            "fractional digits",
        ),
        (
            r#"debit "1" upto "1 USD" debit "1" upto "2 USD" credit "2" upto "1 USD""#,
            "unique",
        ),
        (
            r#"debit "1" upto "1 USD" dims { project = "P", project = "Q" } credit "2" upto "1 USD""#,
            "tagged twice",
        ),
        (
            r#"debit "1" upto "1 USD" dims { unregistered = "P" } credit "2" upto "1 USD""#,
            "not a registered dimension",
        ),
        (
            r#"debit "1" upto event.resource("net", "USD") credit "2" upto "1 USD""#,
            "fixed authority ceiling",
        ),
    ] {
        let source = format!(
            "rule r v1 for event Sale {{ authority {{ {declaration} }} \
             debit \"1\" \"1.00 USD\" credit \"2\" \"1.00 USD\" }}"
        );
        let error = compile(&source, &units).unwrap_err();
        assert!(error.message.contains(needle), "{source}\n{error}");
    }
    let duplicated_header = AUTHORIZED_SPLIT.replace(
        "  let net",
        "  authority { debit \"1200\" upto \"100 USD\" }\n  let net",
    );
    assert!(compile(&duplicated_header, &units).is_err());

    let mut oversized = String::from("rule r v1 for event Sale { authority { ");
    oversized.push_str(&r#"debit "1" upto "1 USD" "#.repeat(513));
    oversized.push_str(r#"} debit "1" "1 USD" credit "2" "1 USD" }"#);
    assert!(
        compile(&oversized, &units)
            .unwrap_err()
            .message
            .contains("at most 512")
    );
}

/// Write a deliberately editable declaration in the documented extension
/// format, independent of the private IR encoder. Tests below mutate semantic
/// fields while preserving the surrounding framing and balanced expressions.
fn authority_ir_with(
    rule: &CompiledRule,
    units: &UnitRegistry,
    version: u16,
    grants: &[AuthorityGrant],
) -> Vec<u8> {
    let start = rule
        .ir()
        .windows(8)
        .position(|w| w == b"FARAUTH\0")
        .unwrap();
    let mut bytes = rule.ir()[..start].to_vec();
    let mut extension = Writer::new();
    extension.fixed(b"FARAUTH\0").u16(version);
    extension.list(grants, |w, grant| {
        w.u8(if grant.side == Side::Debit { 1 } else { 2 })
            .str(&grant.account);
        let unit = units.get(grant.ceiling.unit).unwrap();
        w.str(&unit.code)
            .u16(unit.version)
            .u8(unit.scale)
            .i128(grant.ceiling.mantissa);
        w.list(&grant.dims, |w, (kind, code)| {
            w.str(kind).str(code);
        });
    });
    bytes.extend(extension.finish().unwrap());
    bytes
}

#[test]
fn rule_authority_ir_rejects_unknown_duplicate_noncanonical_and_incomplete_grants() {
    let units = units();
    let rule = compile(AUTHORIZED_SPLIT, &units).unwrap();
    let RuleAuthority::Declared(grants) = rule.authority() else {
        panic!("declared authority");
    };
    assert_eq!(authority_ir_with(&rule, &units, 1, grants), rule.ir());
    assert_eq!(CompiledRule::decode(rule.ir(), &units).unwrap(), rule);
    assert!(CompiledRule::decode(&authority_ir_with(&rule, &units, 2, grants), &units).is_err());
    assert!(CompiledRule::decode(&authority_ir_with(&rule, &units, 1, &[]), &units).is_err());
    for changed in 0..9 {
        let mut malformed = grants.clone();
        match changed {
            0 => malformed.reverse(),
            1 => malformed.push(malformed[0].clone()),
            2 => malformed[0].ceiling.mantissa = 0,
            3 => malformed[0].ceiling.mantissa = -1,
            4 => malformed[0].account = "1201".into(),
            5 => malformed[0].dims.clear(),
            6 => malformed[0].dims.swap(0, 1),
            7 => {
                let duplicate = malformed[0].dims[0].clone();
                malformed[0].dims.push(duplicate);
            }
            8 => malformed[0].account = "X".repeat(1025),
            _ => unreachable!(),
        }
        let bytes = authority_ir_with(&rule, &units, 1, &malformed);
        assert!(
            CompiledRule::decode(&bytes, &units).is_err(),
            "changed={changed}"
        );
    }
    let start = rule
        .ir()
        .windows(8)
        .position(|w| w == b"FARAUTH\0")
        .unwrap();
    let mut unknown = rule.ir().to_vec();
    unknown[start] ^= 1;
    assert!(CompiledRule::decode(&unknown, &units).is_err());
    let mut duplicated = rule.ir().to_vec();
    duplicated.extend(&rule.ir()[start..]);
    assert!(CompiledRule::decode(&duplicated, &units).is_err());
    assert!(CompiledRule::decode(&rule.ir()[..rule.ir().len() - 1], &units).is_err());
    let mut oversized = rule.ir()[..start + 10].to_vec();
    oversized.extend(513u32.to_le_bytes());
    assert!(CompiledRule::decode(&oversized, &units).is_err());
}

#[test]
fn rule_authority_order_and_unit_ids_do_not_change_the_content_address() {
    let units = units();
    let source = r#"rule multi v1 for event Sale {
        authority {
            debit "1" upto "2.00 USD" credit "2" upto "2.00 USD"
            debit "1" upto "3.00 EUR" credit "2" upto "3.00 EUR"
        }
        debit "1" "1.00 USD" credit "2" "1.00 USD"
        debit "1" "1.00 EUR" credit "2" "1.00 EUR"
    }"#;
    let reordered = source.replace(
        "debit \"1\" upto \"2.00 USD\" credit \"2\" upto \"2.00 USD\"\n            debit \"1\" upto \"3.00 EUR\" credit \"2\" upto \"3.00 EUR\"",
        "credit \"2\" upto \"3.00 EUR\" debit \"1\" upto \"3.00 EUR\" credit \"2\" upto \"2.00 USD\" debit \"1\" upto \"2.00 USD\"",
    );
    assert_ne!(source, reordered);
    let rule = compile(source, &units).unwrap();
    assert_eq!(compile(&reordered, &units).unwrap(), rule);
    let changed = source.replace("upto \"2.00 USD\"", "upto \"2.01 USD\"");
    assert_ne!(
        compile(&changed, &units).unwrap().ir_digest(),
        rule.ir_digest()
    );
    let mut remapped = UnitRegistry::empty();
    for code in ["EUR", "USD"] {
        remapped
            .register(units.get(units.lookup(code).unwrap()).unwrap().clone())
            .unwrap();
    }
    assert_ne!(remapped.lookup("USD"), units.lookup("USD"));
    let recompiled = compile(source, &remapped).unwrap();
    assert_eq!(recompiled.ir(), rule.ir());
    assert_eq!(
        CompiledRule::decode(rule.ir(), &remapped).unwrap(),
        recompiled
    );
}

#[test]
fn legacy_rules_keep_their_original_ir_and_explicit_unbounded_posture() {
    // Frozen legacy v1 encoding from before the authority extension. Neither
    // a default tag nor an empty extension may silently change old addresses.
    const LEGACY_IR: &[u8] = &[
        1, 0, 0, 0, 114, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 1, 0, 0, 0, 49,
        1, 3, 0, 0, 0, 85, 83, 68, 0, 0, 2, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 2, 1, 0, 0, 0, 50, 1, 3, 0, 0, 0, 85, 83, 68, 0, 0, 2, 100, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let units = units();
    let source = r#"rule r v1 for event Sale { debit "1" "1.00 USD" credit "2" "1.00 USD" }"#;
    let rule = compile(source, &units).unwrap();
    assert_eq!(rule.authority(), &RuleAuthority::LegacyUnbounded);
    assert_eq!(rule.ir(), LEGACY_IR);
    assert_eq!(CompiledRule::decode(LEGACY_IR, &units).unwrap(), rule);
    let bounded = source.replace(
        "{ debit",
        "{ authority { debit \"1\" upto \"1 USD\" credit \"2\" upto \"1 USD\" } debit",
    );
    let declared = compile(&bounded, &units).unwrap();
    assert!(declared.ir().starts_with(LEGACY_IR));
    assert_ne!(declared.ir_digest(), rule.ir_digest());
    let contextual = compile(
        r#"rule authority v1 for event Sale { inputs { upto: amount("USD") }
           let authority = upto debit "1" authority credit "2" authority }"#,
        &units,
    )
    .unwrap();
    assert_eq!(contextual.authority(), &RuleAuthority::LegacyUnbounded);
}

#[test]
fn retained_source_binds_authority_without_reinterpreting_historical_units() {
    let units = units();
    let mut later = units.clone();
    let mut usd4 = units.get(units.lookup("USD").unwrap()).unwrap().clone();
    usd4.version = 1;
    usd4.scale = 4;
    later.register(usd4).unwrap();
    for source in [SALE, AUTHORIZED_SPLIT] {
        let recorded = compile(source, &units).unwrap();
        // A naive recompilation chooses today's USD@v1 rather than the
        // recorded USD@v0. The retained IR still decodes and its source must
        // be interpreted at that explicit historical binding instead.
        assert_ne!(compile(source, &later).unwrap().ir(), recorded.ir());
        let retained = CompiledRule::decode(recorded.ir(), &later).unwrap();
        assert_eq!(retained.check_source(source, &later), Ok(()));
        assert_eq!(
            retained.check_source(&format!("# equivalent layout\n{source}"), &later),
            Ok(())
        );
        assert!(
            retained
                .check_source(source, &UnitRegistry::empty())
                .is_err()
        );
    }

    let recorded = compile(AUTHORIZED_SPLIT, &units).unwrap();
    let broader_source = AUTHORIZED_SPLIT.replace("100.00 USD", "200.00 USD");
    assert!(
        recorded
            .check_source(&broader_source, &units)
            .unwrap_err()
            .0
            .contains("does not reproduce")
    );
    let broad = compile(&broader_source, &units).unwrap();
    assert!(broad.check_source(AUTHORIZED_SPLIT, &units).is_err());
    let start = recorded
        .ir()
        .windows(8)
        .position(|w| w == b"FARAUTH\0")
        .unwrap();
    let downgraded = CompiledRule::decode(&recorded.ir()[..start], &units).unwrap();
    assert_eq!(downgraded.authority(), &RuleAuthority::LegacyUnbounded);
    assert!(downgraded.check_source(AUTHORIZED_SPLIT, &units).is_err());
    let derived = evaluate(
        &recorded,
        &event(EventKind::Sale, vec![("net", usd(&units, 1))]),
        &Inputs::new(),
    )
    .unwrap();
    assert_eq!(
        validate_authority(&downgraded, &derived),
        Err(EvalError::Authority(AuthorityError::WrongRuleVersion))
    );

    let mut other_scale = UnitRegistry::empty();
    let mut usd3 = units.get(units.lookup("USD").unwrap()).unwrap().clone();
    usd3.scale = 3;
    other_scale.register(usd3).unwrap();
    assert!(
        recorded
            .check_source(AUTHORIZED_SPLIT, &other_scale)
            .unwrap_err()
            .0
            .contains("another scale")
    );
}

/// Accrue and Defer invoke the existing Adjusting family. Selecting either
/// business intent retains the source-bound authority and schedule, and does
/// not create another IR or input encoding for the same derivation.
#[test]
fn adjusting_business_intents_preserve_the_rule_inputs_and_reversal() {
    let units = units();
    let source = r#"rule rent_policy v1 for event Accrual produces Adjusting {
        inputs { charge: amount("USD"), as_of: date, back: date }
        authority {
            debit "6000" upto "100.00 USD" dims { cost_center = "CC1" }
            credit "2100" upto "100.00 USD"
        }
        debit "6000" charge dims { cost_center = "CC1" }
        credit "2100" charge
        effective as_of
        reverses back
    }"#;
    let rule = compile(source, &units).unwrap();
    let ir = rule.ir().to_vec();
    let digest = rule.ir_digest();
    let mut inputs = as_of();
    let reverse_on = DateDay::from_ymd(2026, 4, 1).unwrap();
    inputs.set("back", InputValue::Date(reverse_on));
    inputs.set("charge", InputValue::Amount(usd(&units, 7_500)));
    let encoded_inputs = fa_canon::encode_inputs(&rule, &inputs).unwrap();
    let accrual = event(EventKind::Accrual, Vec::new());
    let direct = evaluate(&rule, &accrual, &inputs).unwrap();
    assert_eq!(
        legs(&direct),
        [(Side::Debit, "6000", 7_500), (Side::Credit, "2100", 7_500)]
    );
    assert_eq!(direct.effective, DateDay::from_ymd(2026, 3, 31).unwrap());
    assert_eq!(direct.reverse_on, Some(reverse_on));
    assert!(matches!(rule.authority(), RuleAuthority::Declared(_)));

    // Exercise retained source and inputs as a reopened caller would.
    let retained = CompiledRule::decode(&ir, &units).unwrap();
    let retained_inputs = fa_canon::decode_inputs(&retained, &encoded_inputs).unwrap();
    for intent in [RuleIntentKind::Accrue, RuleIntentKind::Defer] {
        assert_eq!(intent.required_produces(), Produces::Adjusting);
        assert_eq!(intent.validate_rule(&rule), Ok(()));
        assert_eq!(intent.validate_rule(&retained), Ok(()));
        assert_eq!(retained.ir(), ir);
        assert_eq!(retained.ir_digest(), digest);
        assert_eq!(
            fa_canon::encode_inputs(&retained, &retained_inputs).unwrap(),
            encoded_inputs
        );
        assert_eq!(
            evaluate(&retained, &accrual, &retained_inputs).unwrap(),
            direct
        );
    }

    // A compatible family does not waive missing inputs, output ceilings
    // or the rule's own requirement that the reversal follows the entry.
    assert!(matches!(
        evaluate(&retained, &accrual, &Inputs::new()),
        Err(EvalError::MissingInput { .. })
    ));
    let mut over = inputs.clone();
    over.set("charge", InputValue::Amount(usd(&units, 10_001)));
    assert!(matches!(
        evaluate(&retained, &accrual, &over),
        Err(EvalError::Authority(_))
    ));
    let mut too_early = inputs;
    too_early.set(
        "back",
        InputValue::Date(DateDay::from_ymd(2026, 3, 31).unwrap()),
    );
    assert!(matches!(
        evaluate(&retained, &accrual, &too_early),
        Err(EvalError::ReversalNotAfter { .. })
    ));
}

/// Neither an accrual event nor an intent-like rule name authorizes an
/// Original rule to implement an Adjusting business intent.
#[test]
fn adjusting_business_intents_refuse_original_rules_with_or_without_authority() {
    let units = units();
    let legacy = r#"rule accrue v1 for event Accrual {
        debit "6000" "1.00 USD" credit "2100" "1.00 USD"
    }"#;
    let declared = r#"rule defer v1 for event Accrual produces Original {
        authority {
            debit "6000" upto "1.00 USD" credit "2100" upto "1.00 USD"
        }
        debit "6000" "1.00 USD" credit "2100" "1.00 USD"
    }"#;
    for source in [legacy, declared] {
        let rule = compile(source, &units).unwrap();
        let retained = CompiledRule::decode(rule.ir(), &units).unwrap();
        for intent in [RuleIntentKind::Accrue, RuleIntentKind::Defer] {
            for selected in [&rule, &retained] {
                let error = intent.validate_rule(selected).unwrap_err();
                assert_eq!(error.intent, intent);
                assert_eq!(error.actual_produces, Produces::Original);
                let message = error.to_string();
                assert!(message.contains(intent.name()), "{message}");
                assert!(message.contains("Adjusting"), "{message}");
                assert!(message.contains("Original"), "{message}");
            }
        }
        // Existing Adjusting policies need no new marker or authority block.
        let adjusting_source = source
            .replace("produces Original", "produces Adjusting")
            .replace("event Accrual {", "event Accrual produces Adjusting {");
        let adjusting = compile(&adjusting_source, &units).unwrap();
        for intent in [RuleIntentKind::Accrue, RuleIntentKind::Defer] {
            assert_eq!(intent.validate_rule(&adjusting), Ok(()));
        }
    }
}
