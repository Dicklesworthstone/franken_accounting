//! X-T-02's reader and comparator (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §10.1; bead fa-yugf.49, X4): fa-oracles' own std-only reading of the
//! instance `fa export xbrl` writes, on documents written here in the
//! writer's layout (`crates/fa-formats/src/xbrl.rs`
//! `write_xbrl_instance_xml`: `ctx_*` contexts, units named by their code,
//! `decimals` the unit's scale).

use fa_oracles::cases::instance::{InstanceError, Period, compare, minor_units, read};

/// An instance in the writer's layout: a balance-sheet instant and an
/// income-statement duration, both non-dimensional, in USD at scale 2.
fn exported(assets_element: &str, assets: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<xbrli:xbrl xmlns:xbrli="http://www.xbrl.org/2003/instance" xmlns:link="http://www.xbrl.org/2003/linkbase" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:iso4217="http://www.xbrl.org/2003/iso4217" xmlns:us-gaap="http://fasb.org/us-gaap/2026">
  <link:schemaRef xlink:type="simple" xlink:href="us_gaap_2026_small_company.xsd"/>
  <xbrli:context id="ctx_current">
    <xbrli:entity>
      <xbrli:identifier scheme="http://frankenaccounting.org/entity">statement-sunpower</xbrli:identifier>
    </xbrli:entity>
    <xbrli:period>
      <xbrli:instant>2023-01-01</xbrli:instant>
    </xbrli:period>
  </xbrli:context>
  <xbrli:context id="ctx_duration_current">
    <xbrli:entity>
      <xbrli:identifier scheme="http://frankenaccounting.org/entity">statement-sunpower</xbrli:identifier>
    </xbrli:entity>
    <xbrli:period>
      <xbrli:startDate>2022-01-03</xbrli:startDate>
      <xbrli:endDate>2023-01-01</xbrli:endDate>
    </xbrli:period>
  </xbrli:context>
  <xbrli:unit id="USD">
    <xbrli:measure>iso4217:USD</xbrli:measure>
  </xbrli:unit>
  <{assets_element} contextRef="ctx_current" unitRef="USD" decimals="2">{assets}</{assets_element}>
  <us-gaap:Liabilities contextRef="ctx_current" unitRef="USD" decimals="2">1100000.00</us-gaap:Liabilities>
  <us-gaap:NetIncomeLoss contextRef="ctx_duration_current" unitRef="USD" decimals="2">250.00</us-gaap:NetIncomeLoss>
</xbrli:xbrl>
"#
    )
}

/// The writer's instant fact reads as its QName, instant, unit and value:
/// 1,654,000.00 USD is 165,400,000 minor units at scale 2.
#[test]
fn reads_instant_fact() {
    let inst = read(&exported("us-gaap:Assets", "1654000.00")).expect("it reads");
    let fact = inst
        .facts
        .iter()
        .find(|f| f.concept == "us-gaap:Assets")
        .expect("the Assets fact");
    assert_eq!(
        (
            fact.context.as_str(),
            fact.unit.as_deref(),
            fact.decimals.as_deref(),
            fact.value.as_str()
        ),
        ("ctx_current", Some("USD"), Some("2"), "1654000.00")
    );
    let context = &inst.contexts["ctx_current"];
    assert_eq!(context.period, Period::Instant("2023-01-01".into()));
    assert!(!context.dimensional);
    assert_eq!(inst.units["USD"], "iso4217:USD");
    assert_eq!(
        compare(&inst, "us-gaap:Assets", "2023-01-01", "USD", 2, 165_400_000),
        Ok(165_400_000)
    );
    assert_eq!(minor_units("-12.5", 2), Ok(-1250));
    assert!(minor_units("12.501", 2).is_err());
    assert_eq!(minor_units("12.500", 2), Ok(1250));
}

/// The independent reader distinguishes the two equity QNames even when
/// they share their instant, currency and precision.
#[test]
fn parent_and_minority_equity_are_distinct_instant_concepts() {
    let xml = exported("us-gaap:Assets", "1000.00").replace(
        "</xbrli:xbrl>",
        "<us-gaap:StockholdersEquity contextRef=\"ctx_current\" unitRef=\"USD\" decimals=\"2\">600.00</us-gaap:StockholdersEquity>\n<us-gaap:MinorityInterest contextRef=\"ctx_current\" unitRef=\"USD\" decimals=\"2\">400.00</us-gaap:MinorityInterest>\n</xbrli:xbrl>",
    );
    let instance = read(&xml).unwrap();
    assert_eq!(
        compare(
            &instance,
            "us-gaap:StockholdersEquity",
            "2023-01-01",
            "USD",
            2,
            60_000
        ),
        Ok(60_000)
    );
    assert_eq!(
        compare(
            &instance,
            "us-gaap:MinorityInterest",
            "2023-01-01",
            "USD",
            2,
            40_000
        ),
        Ok(40_000)
    );
    assert!(
        compare(
            &instance,
            "us-gaap:StockholdersEquity",
            "2023-01-01",
            "USD",
            2,
            100_000
        )
        .is_err()
    );
    assert!(
        compare(
            &instance,
            "us-gaap:MinorityInterest",
            "2023-01-01",
            "USD",
            2,
            60_000
        )
        .is_err()
    );
}

/// A duration context reads as a duration and never matches an instant
/// target, even at its end date.
#[test]
fn duration_context_is_flagged() {
    let inst = read(&exported("us-gaap:Assets", "1654000.00")).expect("it reads");
    assert_eq!(
        inst.contexts["ctx_duration_current"].period,
        Period::Duration {
            start: "2022-01-03".into(),
            end: "2023-01-01".into()
        }
    );
    let miss = compare(
        &inst,
        "us-gaap:NetIncomeLoss",
        "2023-01-01",
        "USD",
        2,
        25_000,
    )
    .expect_err("a duration fact is no instant fact");
    assert!(
        miss.contains("us-gaap:NetIncomeLoss") && miss.contains("observed none"),
        "{miss}"
    );
}

/// A context with a segment or a scenario is dimensional and never matched.
#[test]
fn dimensional_context_is_flagged() {
    for (part, close) in [
        (
            "<xbrli:segment><xbrldi:explicitMember dimension=\"us-gaap:StatementBusinessSegmentsAxis\">x:Y</xbrldi:explicitMember></xbrli:segment>",
            "</xbrli:entity>",
        ),
        (
            "<xbrli:scenario><xbrldi:explicitMember dimension=\"us-gaap:RestatementAxis\">us-gaap:ScenarioPreviouslyReportedMember</xbrldi:explicitMember></xbrli:scenario>",
            "</xbrli:period>",
        ),
    ] {
        let xml =
            exported("us-gaap:Assets", "1654000.00").replacen(close, &format!("{close}{part}"), 1);
        let inst = read(&xml).expect("it reads");
        assert!(inst.contexts["ctx_current"].dimensional, "{part}");
        let miss = compare(&inst, "us-gaap:Assets", "2023-01-01", "USD", 2, 165_400_000)
            .expect_err("a dimensional fact is never matched");
        assert!(miss.contains("observed none"), "{miss}");
    }
}

/// One concept in one context and unit with two different values is a
/// named error; the same value twice is not.
#[test]
fn conflicting_duplicate_fact_is_error() {
    let line = "  <us-gaap:Liabilities contextRef=\"ctx_current\" unitRef=\"USD\" decimals=\"2\">1100000.00</us-gaap:Liabilities>\n";
    let again =
        exported("us-gaap:Assets", "1654000.00").replacen(line, &format!("{line}{line}"), 1);
    assert!(read(&again).is_ok());
    let other = line.replace("1100000.00", "1100000.01");
    let conflicting =
        exported("us-gaap:Assets", "1654000.00").replacen(line, &format!("{line}{other}"), 1);
    assert_eq!(
        read(&conflicting),
        Err(InstanceError::ConflictingFact {
            concept: "us-gaap:Liabilities".into(),
            context: "ctx_current".into(),
            first: "1100000.00".into(),
            second: "1100000.01".into(),
        })
    );
}

/// An unclosed or mismatched element is a named error, never a partial
/// read.
#[test]
fn malformed_xml_is_error() {
    let whole = exported("us-gaap:Assets", "1654000.00");
    let unclosed = whole.replace("</xbrli:xbrl>\n", "");
    match read(&unclosed) {
        Err(InstanceError::Malformed(why)) => assert!(why.contains("never closed"), "{why}"),
        other => panic!("expected a malformed instance, observed {other:?}"),
    }
    let mismatched = whole.replacen("</xbrli:instant>", "</xbrli:endDate>", 1);
    match read(&mismatched) {
        Err(InstanceError::Malformed(why)) => assert!(why.contains("is closed by"), "{why}"),
        other => panic!("expected a malformed instance, observed {other:?}"),
    }
    assert!(matches!(
        read("<html><body/></html>"),
        Err(InstanceError::Malformed(_))
    ));
}

/// An instance whose us-gaap:Assets element is renamed fails the match: the
/// comparator reports Assets missing rather than matching another element.
#[test]
fn renamed_qname_fails_match() {
    let inst = read(&exported("us-gaap:AssetsNoncurrent", "1654000.00")).expect("it reads");
    let miss = compare(&inst, "us-gaap:Assets", "2023-01-01", "USD", 2, 165_400_000)
        .expect_err("a renamed element is not us-gaap:Assets");
    assert_eq!(
        miss,
        "expected a non-dimensional instant fact us-gaap:Assets at 2023-01-01 in USD observed none"
    );
}

/// An exported value one unit off the tagged B fails, naming the concept,
/// the instant and both values.
#[test]
fn value_off_by_one_unit_fails_match() {
    let inst = read(&exported("us-gaap:Assets", "1654000.01")).expect("it reads");
    let miss = compare(&inst, "us-gaap:Assets", "2023-01-01", "USD", 2, 165_400_000)
        .expect_err("one cent over");
    assert_eq!(
        miss,
        "expected us-gaap:Assets at 2023-01-01 = 165400000 observed 165400001 (minor units at scale 2)"
    );
}

/// X7 (§10.1, §2.6): SunPower's Item 4.02 8-K states the day its Audit
/// Committee determined that the fiscal 2022 10-K and the first two 2023
/// 10-Qs should no longer be relied upon, 2023-10-19, and every SunPower
/// Restatement case is determined on that sourced fact, the 8-K's stub its
/// authority. The 8-K was filed 2023-10-24 (and its document is named for
/// 2023-10-18), so the determination day is the sentence's, not the filing
/// date. The fact binds through its receipt (K-BIND).
#[test]
fn x7_cases_are_determined_on_the_audit_committees_day() {
    use fa_oracles::cases::check::{Verdict, run_load_checks};
    use fa_oracles::cases::embedded::XBRL;

    let case = fa_oracles::cases::load(&XBRL.case_files()).expect("the xbrl case loads");
    let day: Vec<&str> = case
        .values
        .iter()
        .filter(|v| v.fact == "spwr8k.determined_on")
        .map(|v| v.value.as_str())
        .collect();
    assert_eq!(day, ["2023-10-19"]);
    let source = case
        .sources
        .iter()
        .find(|s| s.id == "SRC-SPWR-8K-ITEM402")
        .expect("the 8-K's row");
    assert_eq!(source.filed_on.as_deref(), Some("2023-10-24"));
    let mut cases = 0;
    for book in case.books.values() {
        for c in &book.cases {
            cases += 1;
            assert_eq!(c.determined_on, "spwr8k.determined_on", "{}", c.id);
            let authority = book
                .documents
                .iter()
                .find(|d| d.id == c.authority)
                .expect("the authority's document");
            assert_eq!(authority.stub_of, "SRC-SPWR-8K-ITEM402", "{}", c.id);
        }
    }
    assert_eq!(cases, 3);
    let bind = run_load_checks(&case)
        .into_iter()
        .find(|r| r.check == "K-BIND")
        .expect("K-BIND ran");
    assert_ne!(bind.verdict, Verdict::Fail, "{}", bind.render(Some("xbrl")));
}
