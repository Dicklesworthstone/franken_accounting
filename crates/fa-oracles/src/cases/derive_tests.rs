//! A2's tests (bead fa-yugf.6): every rule recomputes its example, a planted
//! wrong value fails every rule, and each named refusal is its error.

use super::*;

fn rules() -> Rules {
    Rules::embedded()
        .map_err(|e| {
            e.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .expect("data/case_derivations.toml loads")
}

fn p(pairs: &[(&str, &str)]) -> Params {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn eval(id: &str, params: &[(&str, &str)], inputs: &[&str]) -> Result<String, DeriveError> {
    let inputs: Vec<String> = inputs.iter().map(|s| (*s).to_string()).collect();
    rules().evaluate(id, &p(params), &inputs)
}

/// The example output altered by one unit: one minor unit, one day, the next
/// label, the other boolean.
fn altered(output: &str) -> String {
    if let Ok(v) = output.parse::<i128>() {
        return (v + 1).to_string();
    }
    if let Some(d) = crate::cases::date::Day::parse(output) {
        return d.add_days(1).to_string();
    }
    match output {
        "true" => return "false".into(),
        "false" => return "true".into(),
        _ => {}
    }
    if let Some(i) = crate::cases::date::WEEKDAYS
        .iter()
        .position(|w| *w == output)
    {
        return crate::cases::date::WEEKDAYS[(i + 1) % 7].to_string();
    }
    // Composite outputs: bump the last digit run by one.
    let bytes: Vec<char> = output.chars().collect();
    if let Some(end) = bytes.iter().rposition(char::is_ascii_digit) {
        let start = bytes[..=end]
            .iter()
            .rposition(|c| !c.is_ascii_digit())
            .map_or(0, |s| s + 1);
        let run: String = bytes[start..=end].iter().collect();
        if let Ok(v) = run.parse::<i128>() {
            let head: String = bytes[..start].iter().collect();
            let tail: String = bytes[end + 1..].iter().collect();
            return format!("{head}{}{tail}", v + 1);
        }
    }
    format!("{output}|altered")
}

#[test]
fn every_rule_recomputes_its_example() {
    let rules = rules();
    assert!(rules.rules.len() >= 27, "every §2.4 rule has a row");
    for rule in &rules.rules {
        match rules.check_example(rule) {
            Ok(()) => println!("RULE {} PASS example={}", rule.id, rule.example_basis),
            Err(e) => panic!("RULE {} FAIL example={}: {e}", rule.id, rule.example_basis),
        }
    }
}

#[test]
fn planted_wrong_value_fails_for_every_rule() {
    let rules = rules();
    for rule in &rules.rules {
        let params = rules.params(rule, &rule.example_params).expect("params");
        let computed = rules
            .evaluate(&rule.id, &params, &rule.example_inputs)
            .expect("computes");
        let wrong = altered(&rule.example_output);
        assert_ne!(
            wrong, rule.example_output,
            "{}: the alteration changes the value",
            rule.id
        );
        match compare(rule, &rule.example_params, &wrong, &computed) {
            Err(DeriveError::Mismatch {
                rule: r,
                params,
                expected,
                computed: c,
            }) => {
                assert_eq!(r, rule.id);
                assert_eq!(params, rule.example_params);
                assert_eq!(expected, wrong);
                assert_eq!(c, rule.example_output);
            }
            other => panic!(
                "{}: a planted wrong value must mismatch, got {other:?}",
                rule.id
            ),
        }
    }
}

#[test]
fn every_rule_row_records_arity_params_semantics_and_example() {
    for rule in &rules().rules {
        assert!(!rule.semantics.is_empty(), "{}: semantics", rule.id);
        assert!(
            !rule.example_inputs.is_empty(),
            "{}: example inputs",
            rule.id
        );
        assert!(
            !rule.example_output.is_empty(),
            "{}: example output",
            rule.id
        );
        assert!(
            rule.example_basis == "synthetic" || rule.example_basis.starts_with("plan §"),
            "{}: example_basis is `plan §…` or synthetic, not `{}`",
            rule.id,
            rule.example_basis
        );
        assert!(rule.arity >= 0, "{}", rule.id);
        for t in &rule.example_params {
            let name = t.split_once('=').map_or(t.as_str(), |(n, _)| n);
            assert!(
                rule.params.iter().any(|(n, _)| n == name),
                "{}: `{name}` is declared",
                rule.id
            );
        }
    }
}

#[test]
fn interpretive_flags_match_section_2_4() {
    let rules = rules();
    let interpretive: Vec<&str> = rules
        .rules
        .iter()
        .filter(|r| r.interpretive)
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(
        interpretive,
        [
            "role_map",
            "one_leg_per_named_account",
            "subledger_to_gl_legs",
            "round_dollar_lower_bound",
            "trustee_transfer_credit",
            "same_day_display_reorder",
        ]
    );
    let legacy = rules.get("legacy_tb_from_chunks").expect("the rule");
    assert!(legacy.semantics.contains("supports no claim"));
    for id in [
        "scale",
        "date_literal",
        "number_word",
        "period_literal",
        "date_range_literal",
        "month_literal",
        "month_day_literal",
        "day_in_period",
        "sum",
        "difference",
        "negate",
        "date_offset",
        "remainder",
        "last_balance_on_or_before",
        "legacy_tb_from_chunks",
        "round_residue",
        "weekday_of",
        "same_leg_multiset_same_day",
        "same_leg_multiset_within",
        "rsf_ratio",
        "first_digit_counts",
        "round_density_z2",
        "benford_mad",
    ] {
        assert!(
            rules.get(id).is_some_and(|r| !r.interpretive),
            "{id} is a non-interpretive row"
        );
    }
}

#[test]
fn plan_examples_recompute() {
    assert_eq!(
        eval("scale", &[("k", "0"), ("unit", "USD")], &["$742,725,000"]),
        Ok("74272500000".into())
    );
    assert_eq!(
        eval(
            "scale",
            &[("k", "6"), ("unit", "USD"), ("precision", "6")],
            &["$560 million"]
        ),
        Ok("56000000000".into())
    );
    assert_eq!(
        eval("date_offset", &[("days", "3")], &["2001-08-22"]),
        Ok("2001-08-25".into())
    );
    assert_eq!(
        eval("weekday_of", &[], &["2001-08-25"]),
        Ok("Saturday".into())
    );
    // trustee_transfer_credit's two in-file pairs (whole dollars at USD's scale).
    assert_eq!(
        eval("trustee_transfer_credit", &[], &["400000000", "485500000"]),
        Ok("400000000".into())
    );
    assert_eq!(
        eval("trustee_transfer_credit", &[], &["20000000", "-485468800"]),
        Ok("0".into())
    );
    assert_eq!(
        eval("sum", &[], &["1130", "6637", "1803"]),
        Ok("9570".into())
    );
    assert_eq!(
        eval(
            "date_range_literal",
            &[],
            &["on or about and between July 17 and 19, 2000"]
        ),
        Ok("2000-07-17..2000-07-19".into())
    );
    let month = eval("month_literal", &[], &["In September 2001"]).expect("a month");
    assert_eq!(month, "2001-09");
    assert_eq!(
        crate::cases::date::days_in_month(2001, 9),
        30,
        "a branch over 30 days"
    );
    assert_eq!(
        eval("remainder", &[], &["98727", "41000", "20000"]),
        Ok("37727".into())
    );
}

/// A year-less booking day (WorldCom's "Friday, April 20", "On August 22")
/// takes its year from the reporting period it adjusts: the one matching
/// day from the period's first day through `after_days` past its close. A
/// written weekday must agree; an ambiguous or empty window is refused.
#[test]
fn day_in_period_reads_its_year_from_the_period_and_checks_the_weekday() {
    assert_eq!(
        eval("month_day_literal", &[], &["Friday, April 20"]),
        Ok("--04-20 Friday".into())
    );
    assert_eq!(
        eval("month_day_literal", &[], &["On August 22"]),
        Ok("--08-22".into())
    );
    // F2's "Over the course of April 23 and 24": a same-month range.
    assert_eq!(
        eval(
            "month_day_literal",
            &[],
            &["Over the course of April 23 and 24"]
        ),
        Ok("--04-23..--04-24".into())
    );
    for planted in [
        "July 17, 2001",
        "February 30",
        "Friday",
        "April 24 and 23",
        "April 23 and 24, 2001",
    ] {
        assert!(
            eval("month_day_literal", &[], &[planted]).is_err(),
            "{planted} is refused"
        );
    }
    assert_eq!(
        eval("day_in_period", &[("day", "--04-23..--04-24")], &["2001Q1"]),
        Ok("2001-04-23..2001-04-24".into())
    );
    // F1 (1Q01, booked after the close), F6 (inside 3Q01), and a 4Q01 entry
    // booked in January, whose year is the next one.
    assert_eq!(
        eval("day_in_period", &[("day", "--04-20 Friday")], &["2001Q1"]),
        Ok("2001-04-20".into())
    );
    assert_eq!(
        eval("day_in_period", &[("day", "--08-22")], &["2001Q3"]),
        Ok("2001-08-22".into())
    );
    assert_eq!(
        eval("day_in_period", &[("day", "--01-23")], &["2001Q4"]),
        Ok("2002-01-23".into())
    );
    // 2002-04-20 is a Saturday: the written weekday refuses the wrong year.
    let wrong_year = eval("day_in_period", &[("day", "--04-20 Friday")], &["2002Q1"]);
    assert!(
        wrong_year
            .as_ref()
            .is_err_and(|e| e.to_string().contains("2002-04-20 is a Saturday")),
        "{wrong_year:?}"
    );
    // Before the period (a 2Q01 entry dated in January), and a fiscal year
    // whose window holds the day twice, are refused, never guessed.
    for (period, day) in [("2001Q2", "--01-15"), ("FY2001", "--02-10")] {
        let r = eval("day_in_period", &[("day", day)], &[period]);
        assert!(
            r.as_ref()
                .is_err_and(|e| e.to_string().contains("exactly one is required")),
            "{period} {day}: {r:?}"
        );
    }
    // A 29 February outside a leap year matches no day.
    assert!(eval("day_in_period", &[("day", "--02-29")], &["2001Q1"]).is_err());
}

#[test]
fn round_density_flags_its_example_and_the_equal_sides_boundary() {
    // (12*200 - 20*30)^2 = 3,240,000 >= 9*20*30*170 = 918,000, below 4x: Medium.
    assert_eq!(
        eval(
            "round_density_z2",
            &[("min_legs", "20"), ("z_squared", "9")],
            &["12", "20", "30", "200"]
        ),
        Ok("flagged:Medium".into())
    );
    // x=1, n=1, X=1, N=2: (1*2 - 1*1)^2 = 1 and 1*1*1*(2 - 1) = 1, equal sides:
    // flagged, since the test is >=; with z_squared = 2 the right side is 2: not.
    let r = |z: &str| {
        eval(
            "round_density_z2",
            &[("min_legs", "1"), ("z_squared", z)],
            &["1", "1", "1", "2"],
        )
    };
    assert_eq!(r("1"), Ok("flagged:Medium".into()));
    assert_eq!(r("2"), Ok("not_flagged".into()));
}

#[test]
fn round_density_below_min_legs_is_untested() {
    assert_eq!(
        eval(
            "round_density_z2",
            &[("min_legs", "20"), ("z_squared", "9")],
            &["19", "19", "30", "200"]
        ),
        Ok("untested".into())
    );
}

#[test]
fn benford_mad_over_the_harness_copy_of_the_table() {
    assert_eq!(check_benford_table(&BENFORD_1E9), Ok(()));
    assert_eq!(
        BENFORD_1E9,
        [
            301_029_996,
            176_091_259,
            124_938_737,
            96_910_013,
            79_181_246,
            66_946_790,
            57_991_947,
            51_152_522,
            45_757_490
        ],
        "the nine constants, with FA's lowered last entry"
    );
    let params = [
        ("min_population", "500"),
        ("mad_close", "6"),
        ("mad_acceptable", "12"),
        ("mad_marginal", "15"),
    ];
    assert_eq!(
        eval(
            "benford_mad",
            &params,
            &["301", "176", "125", "97", "79", "67", "58", "51", "46"]
        ),
        Ok("mad_1e9=101116 band=close".into())
    );
    // Every leading digit a 1: far from Benford.
    assert_eq!(
        eval(
            "benford_mad",
            &params,
            &["600", "0", "0", "0", "0", "0", "0", "0", "0"]
        ),
        Ok("mad_1e9=155326667 band=nonconformity".into())
    );
    assert_eq!(
        eval(
            "benford_mad",
            &params,
            &["100", "0", "0", "0", "0", "0", "0", "0", "0"]
        ),
        Ok("untested population=100".into())
    );
}

#[test]
fn benford_table_copy_that_does_not_sum_to_1e9_fails() {
    let mut copy = BENFORD_1E9;
    copy[8] += 1;
    assert_eq!(check_benford_table(&copy), Err(1_000_000_001));
}

#[test]
fn sum_overflow_is_refused() {
    let max = i128::MAX.to_string();
    assert_eq!(eval("sum", &[], &[&max, &max]), Err(DeriveError::Overflow));
}

#[test]
fn unknown_rule_is_refused() {
    assert_eq!(
        eval("made_up", &[], &["1"]),
        Err(DeriveError::UnknownRule("made_up".into()))
    );
}

#[test]
fn rounding_law_not_in_the_registry_is_refused() {
    let copy = TABLE.replacen("rounding_law = \"\"", "rounding_law = \"NoSuchLaw\"", 1);
    let errs = Rules::from_text(&copy).expect_err("refused");
    assert!(
        errs.iter()
            .any(|e| e.kind == LoadErrorKind::DanglingKey && e.detail.contains("NoSuchLaw")),
        "{errs:?}"
    );
    let ok = TABLE.replacen("rounding_law = \"\"", "rounding_law = \"HalfEven\"", 1);
    Rules::from_text(&ok).expect("a registered rounding law loads");
}

#[test]
fn date_offset_from_an_invalid_date_is_refused() {
    assert!(matches!(
        eval("date_offset", &[("days", "3")], &["2001-02-29"]),
        Err(DeriveError::BadParam(_))
    ));
}

#[test]
fn subledger_to_gl_legs_with_a_nonzero_residual_is_refused() {
    // 544,000,000.00 into ten legs of 54,400,000.01.
    assert!(matches!(
        eval(
            "subledger_to_gl_legs",
            &[("decomposition", "ten_two_leg_entries")],
            &["54400000000", "10", "5440000001"]
        ),
        Err(DeriveError::Infeasible(_))
    ));
    assert_eq!(
        eval(
            "subledger_to_gl_legs",
            &[("decomposition", "ten_two_leg_entries")],
            &["54400000000", "10", "5440000000"]
        ),
        Ok("ten_two_leg_entries:10x5440000000".into())
    );
}

#[test]
fn inverted_date_range_is_refused() {
    assert!(matches!(
        eval("date_range_literal", &[], &["July 19 and 17, 2000"]),
        Err(DeriveError::BadParam(_))
    ));
}

#[test]
fn month_literal_with_an_unknown_month_is_refused() {
    assert!(matches!(
        eval("month_literal", &[], &["In Septober 2001"]),
        Err(DeriveError::BadParam(_))
    ));
}

/// A text extraction can drop the space after a comma ("19,2000"): words
/// split on commas as on spaces, so the reading is the same (case_fetch's
/// rules read it alike).
#[test]
fn a_comma_without_its_space_reads_the_same() {
    assert_eq!(
        eval("date_range_literal", &[], &["July 17 and 19,2000"]),
        Ok("2000-07-17..2000-07-19".into())
    );
    assert_eq!(
        eval("date_literal", &[], &["On or about May 12,2000"]),
        Ok("2000-05-12".into())
    );
}

#[test]
fn year_less_date_range_is_refused() {
    assert!(matches!(
        eval(
            "date_range_literal",
            &[],
            &["on or about and between July 17 and 19"]
        ),
        Err(DeriveError::BadParam(_))
    ));
}

#[test]
fn year_less_quarter_is_refused() {
    assert!(matches!(
        eval("period_literal", &[], &["the second quarter"]),
        Err(DeriveError::BadParam(_))
    ));
    assert_eq!(eval("period_literal", &[], &["1Q02"]), Ok("2002Q1".into()));
    assert_eq!(
        eval("period_literal", &[], &["fiscal year 2001"]),
        Ok("FY2001".into())
    );
}

#[test]
fn scale_reads_parenthesized_minus_and_dash_forms() {
    let usd6 = [("k", "6"), ("unit", "USD")];
    assert_eq!(eval("scale", &usd6, &["(153)"]), Ok("-15300000000".into()));
    assert_eq!(
        eval("scale", &usd6, &["\u{2212}153"]),
        Ok("-15300000000".into())
    );
    assert_eq!(eval("scale", &usd6, &["-153"]), Ok("-15300000000".into()));
    assert_eq!(eval("scale", &usd6, &["\u{2014}"]), Ok("0".into()));
    assert_eq!(eval("scale", &usd6, &["-"]), Ok("0".into()));
}

#[test]
fn scale_writes_a_unitless_ratio_at_its_precision() {
    assert_eq!(
        eval("scale", &[("k", "0"), ("precision", "-1")], &["13.9x"]),
        Ok("139".into())
    );
    assert_eq!(
        eval("scale", &[("k", "0"), ("precision", "0")], &["98,727"]),
        Ok("98727".into())
    );
}

#[test]
fn scale_result_finer_than_its_scale_is_refused() {
    assert!(matches!(
        eval("scale", &[("k", "0"), ("unit", "USD")], &["0.125"]),
        Err(DeriveError::BadParam(_))
    ));
}

#[test]
fn ratio_suffix_on_a_currency_value_is_refused() {
    assert!(matches!(
        eval("scale", &[("k", "0"), ("unit", "USD")], &["13.9x"]),
        Err(DeriveError::BadParam(_))
    ));
}

fn derived(from: &[&str], params: &[&str]) -> Derived {
    Derived {
        from: from.iter().map(|s| (*s).to_string()).collect(),
        rule: "scale".into(),
        params: Some(
            params
                .iter()
                .map(|s| TomlValue::Str((*s).to_string()))
                .collect(),
        ),
    }
}

fn value(fact: &str, v: &str) -> Value {
    Value {
        fact: fact.into(),
        ordinal: 1,
        literal: v.into(),
        rule: crate::cases::fact::LiteralRule::Scale,
        param: Some(0),
        value: v.into(),
        unit: String::new(),
        precision: Some(0),
        line: None,
    }
}

#[test]
fn two_input_scale_reads_its_multiplier_fact() {
    let rules = rules();
    let values = [
        value("W-ST-ta1999", "91072"),
        value("W-ST-ex27-1999-mult", "1000000"),
    ];
    let d = derived(
        &["W-ST-ta1999", "W-ST-ex27-1999-mult"],
        &["multiplier=from:W-ST-ex27-1999-mult", "unit=USD"],
    );
    let params = rules.params_of(&d, &values).expect("params resolve");
    assert_eq!(
        params.get("multiplier").map(String::as_str),
        Some("1000000")
    );
    assert_eq!(
        rules.evaluate("scale", &params, &["91072".into()]),
        Ok("9107200000000".into())
    );
}

#[test]
fn two_input_scale_with_a_multiplier_that_is_not_a_power_of_ten_is_refused() {
    let rules = rules();
    let values = [value("A", "91072"), value("M", "1500")];
    let params = rules
        .params_of(
            &derived(&["A", "M"], &["multiplier=from:M", "unit=USD"]),
            &values,
        )
        .expect("params");
    assert!(matches!(
        rules.evaluate("scale", &params, &["91072".into()]),
        Err(DeriveError::BadParam(_))
    ));
}

/// `from:<fact>#<n>` reads the value of ordinal n, so a sentence whose
/// booking day is not its first value (WorldCom's p.116: "$818 million …
/// $718 million on April 12") feeds `day_in_period` without renumbering the
/// values its book legs cite; a missing ordinal is refused.
#[test]
fn param_from_a_numbered_value_reads_that_value() {
    let rules = rules();
    let values = [
        value("P", "2002Q1"),
        value("S", "81800000000"),
        Value {
            ordinal: 2,
            ..value("S", "--04-12")
        },
    ];
    let d = Derived {
        rule: "day_in_period".into(),
        ..derived(&["P", "S"], &["day=from:S#2"])
    };
    let params = rules.params_of(&d, &values).expect("params resolve");
    assert_eq!(params.get("day").map(String::as_str), Some("--04-12"));
    assert_eq!(
        rules.evaluate("day_in_period", &params, &["2002Q1".into()]),
        Ok("2002-04-12".into())
    );
    for bad in ["day=from:S#3", "day=from:S#two"] {
        let d = Derived {
            rule: "day_in_period".into(),
            ..derived(&["P", "S"], &[bad])
        };
        assert!(
            matches!(rules.params_of(&d, &values), Err(DeriveError::BadParam(_))),
            "{bad} is refused"
        );
    }
}

#[test]
fn param_from_a_fact_outside_from_is_refused() {
    let rules = rules();
    let values = [value("A", "91072"), value("M", "1000000")];
    assert!(matches!(
        rules.params_of(
            &derived(&["A"], &["multiplier=from:M", "unit=USD"]),
            &values
        ),
        Err(DeriveError::BadParam(_))
    ));
}

/// M2t's row shape: two accounts, a TRANS row, a same-day pair, a
/// parenthesized negative (synthetic values).
const ROWS: &str = "[[row]]\naccount = \"1ZA001\"\ndate = \"1995-01-03\"\ntransaction_description = \"CHECK\"\ncolumn = \"Cash Deposits\"\namount_literal = \"1,000\"\nbalance_literal = \"1,000\"\n\n\
[[row]]\naccount = \"1ZA001\"\ndate = \"1995-02-01\"\ntransaction_description = \"TRANS FROM 1ZA002\"\ncolumn = \"Transfers In\"\namount_literal = \"500\"\nbalance_literal = \"1,500\"\n\n\
[[row]]\naccount = \"1ZA001\"\ndate = \"1995-03-01\"\ntransaction_description = \"CHECK\"\ncolumn = \"Cash Withdrawals\"\namount_literal = \"(250)\"\nbalance_literal = \"1,250\"\n\n\
[[row]]\naccount = \"1ZA001\"\ndate = \"1995-03-01\"\ntransaction_description = \"STOP PAYMENT\"\ncolumn = \"Cash Withdrawals\"\namount_literal = \"250\"\nbalance_literal = \"1,500\"\n\n\
[[row]]\naccount = \"1ZA002\"\ndate = \"1995-01-10\"\ntransaction_description = \"CHECK\"\ncolumn = \"Cash Deposits\"\namount_literal = \"9,000\"\nbalance_literal = \"9,000\"\n";

#[test]
fn sum_over_a_row_selection() {
    assert_eq!(
        eval("sum", &[("account", "1ZA001"), ("unit", "USD")], &[ROWS]),
        Ok("150000".into())
    );
    assert_eq!(
        eval(
            "sum",
            &[
                ("account", "1ZA001"),
                ("unit", "USD"),
                ("column", "Cash Withdrawals")
            ],
            &[ROWS]
        ),
        Ok("0".into())
    );
    assert_eq!(
        eval(
            "sum",
            &[
                ("account", "1ZA001"),
                ("unit", "USD"),
                ("token", "TRANS FROM 1ZA002")
            ],
            &[ROWS]
        ),
        Ok("50000".into())
    );
    assert_eq!(
        eval(
            "sum",
            &[
                ("account", "1ZA001"),
                ("unit", "USD"),
                ("through", "1995-02-01")
            ],
            &[ROWS]
        ),
        Ok("150000".into())
    );
}

#[test]
fn difference_of_a_row_selection_and_its_closing_balance() {
    // Running sum 1,500.00 against a printed closing balance of 1,500.00: no drift.
    assert_eq!(
        eval(
            "difference",
            &[("account", "1ZA001"), ("unit", "USD")],
            &[ROWS, "150000"]
        ),
        Ok("0".into())
    );
    assert_eq!(
        eval(
            "difference",
            &[("account", "1ZA001"), ("unit", "USD")],
            &[ROWS, "149999"]
        ),
        Ok("1".into())
    );
}

#[test]
fn last_balance_on_or_before_selects_by_account_and_date() {
    let at = |date: &str| {
        eval(
            "last_balance_on_or_before",
            &[("account", "1ZA001"), ("date", date), ("unit", "USD")],
            &[ROWS],
        )
    };
    assert_eq!(at("1995-02-01"), Ok("150000".into()), "the exact date");
    assert_eq!(at("1995-02-15"), Ok("150000".into()), "between rows");
    assert_eq!(
        at("1995-03-01"),
        Ok("150000".into()),
        "same day: the last printed row"
    );
    assert!(
        matches!(at("1994-12-31"), Err(DeriveError::Infeasible(_))),
        "before the first row, never 0"
    );
}

#[test]
fn row_selection_matching_no_row_is_infeasible() {
    assert!(matches!(
        eval("sum", &[("account", "1ZZ999"), ("unit", "USD")], &[ROWS]),
        Err(DeriveError::Infeasible(_))
    ));
}

#[test]
fn row_input_without_an_account_param_is_refused() {
    assert!(matches!(
        eval("sum", &[("unit", "USD")], &[ROWS]),
        Err(DeriveError::BadParam(_))
    ));
}

const CHART_HEADER: &str = "schema_version = 1\n";

#[test]
fn chart_rule_row_with_two_reads_loads() {
    let text = format!(
        "{CHART_HEADER}\n[[chart_rule_row]]\nchart_rule = \"us-gaap-xbrl-v1\"\nconcept = \"us-gaap:StockholdersEquity\"\ntype = \"Equity\"\nrole = \"\"\nbalance_side = \"credit\"\nread = [\"bs:equity\", \"account\"]\nexample = \"X2's StockholdersEquity\"\n"
    );
    let rules = Rules::from_text(&text).expect("two reads load");
    assert_eq!(rules.chart_rows[0].read, ["bs:equity", "account"]);
}

#[test]
fn chart_rule_row_with_not_modelled_beside_a_read_is_refused() {
    let text = format!(
        "{CHART_HEADER}\n[[chart_rule_row]]\nchart_rule = \"us-gaap-xbrl-v1\"\nconcept = \"us-gaap:Goodwill\"\ntype = \"Asset\"\nrole = \"\"\nbalance_side = \"debit\"\nread = [\"not_modelled\", \"account\"]\nreason = \"no goodwill line\"\nexample = \"X2\"\n"
    );
    let errs = Rules::from_text(&text).expect_err("refused");
    assert!(
        errs.iter()
            .any(|e| e.detail.contains("never beside a read")),
        "{errs:?}"
    );
    let alone = text.replace(
        "read = [\"not_modelled\", \"account\"]",
        "read = [\"not_modelled\"]",
    );
    Rules::from_text(&alone).expect("not_modelled alone, with its reason, loads");
    let no_reason = alone.replace("reason = \"no goodwill line\"\n", "");
    let errs = Rules::from_text(&no_reason).expect_err("a not_modelled row without a reason");
    assert!(
        errs.iter().any(|e| e.kind == LoadErrorKind::MissingField),
        "{errs:?}"
    );
}

#[test]
fn chart_rule_role_must_admit_its_type() {
    let text = format!(
        "{CHART_HEADER}\n[[chart_rule_row]]\nchart_rule = \"c\"\nconcept = \"Line costs\"\ntype = \"Expense\"\nrole = \"fixed_asset\"\nbalance_side = \"debit\"\nread = [\"account\"]\nexample = \"x\"\n"
    );
    let errs = Rules::from_text(&text).expect_err("refused");
    assert!(
        errs.iter().any(|e| e.detail.contains("does not admit")),
        "{errs:?}"
    );
}
