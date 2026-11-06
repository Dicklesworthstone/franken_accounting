use super::*;

fn native(text: &str) -> (Profiled, Native) {
    let profiled = rewrite(text).map_err(|r| format!("{r:?}")).expect(text);
    let native = match &profiled.selection {
        Selection::Native(native) => Some(native.clone()),
        Selection::TrialBalance
        | Selection::ExplainBalance { .. }
        | Selection::OpenItems { .. }
        | Selection::Statement { .. }
        | Selection::AccessLog { .. }
        | Selection::Procedure { .. } => None,
    }
    .expect("a native read");
    (profiled, native)
}

fn refused(text: &str) -> Refusal {
    rewrite(text).expect_err(text)
}

#[test]
fn known_at_compiles_to_the_one_system_time_clause() {
    let (p, n) = native(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs AS KNOWN AT 7",
    );
    assert_eq!(p.known_at, KnownAt::Seq(7));
    assert_eq!(
        n.statement(7),
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) FOR SYSTEM_TIME AS OF SEQ 7 RETURN a.code, COUNT(*) AS legs"
    );
    assert!(n.aggregation().is_none());
    // Omitted, HEAD and AS CURRENTLY STATED all mean the frontier at run time.
    for text in [
        "MATCH (a:Account) RETURN a.code",
        "MATCH (a:Account) RETURN a.code AS KNOWN AT HEAD",
        "MATCH (a:Account) AS CURRENTLY STATED RETURN a.code",
    ] {
        let (p, n) = native(text);
        assert_eq!(p.known_at, KnownAt::Head, "{text}");
        assert_eq!(
            n.statement(3),
            "MATCH (a:Account) FOR SYSTEM_TIME AS OF SEQ 3 RETURN a.code"
        );
    }
    let (p, _) = native("MATCH (a:Account) RETURN a.code AS KNOWN AT '2026-02-01T00:00:00Z'");
    assert_eq!(p.known_at, KnownAt::Instant("2026-02-01T00:00:00Z".into()));
    // A selector written first, or inside a WHERE, leaves no gap behind.
    for text in [
        "AS KNOWN AT 3 MATCH (a:Account) WHERE a.code = '1000' RETURN a.code",
        "MATCH (a:Account) WHERE a.code = '1000'   AS KNOWN AT 3\n RETURN a.code",
    ] {
        let (_, n) = native(text);
        assert_eq!(
            n.statement(3),
            "MATCH (a:Account) FOR SYSTEM_TIME AS OF SEQ 3 WHERE a.code = '1000' RETURN a.code",
            "{text}"
        );
    }
    // The clause lands before the first WHERE, even after a second pattern.
    let (_, n) = native("MATCH (a:Account) MATCH (l:Leg) WHERE a.code = '1000' RETURN l");
    assert_eq!(
        n.statement(2),
        "MATCH (a:Account) MATCH (l:Leg) FOR SYSTEM_TIME AS OF SEQ 2 WHERE a.code = '1000' RETURN l"
    );
}

#[test]
fn one_coordinate_and_the_profile_owns_it() {
    let r = refused("MATCH (a:Account) AS CURRENTLY STATED RETURN a.code AS KNOWN AT 3");
    assert_eq!(r.law, Law::Profile);
    assert!(r.message.contains("one known-at"), "{r:?}");
    let r = refused("MATCH (a:Account) FOR SYSTEM_TIME AS OF SEQ 3 RETURN a.code");
    assert!(r.fix.contains("AS KNOWN AT"), "{r:?}");
    for bad in [
        "AS KNOWN AT soon",
        "AS KNOWN AT -1",
        "AS KNOWN AT 99999999999999999999999",
    ] {
        let r = refused(&format!("MATCH (a:Account) RETURN a.code {bad}"));
        assert_eq!(r.law, Law::Profile, "{bad}");
    }
}

#[test]
fn for_period_joins_the_entrys_resolved_period() {
    let (p, n) = native(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) FOR PERIOD 'FY2026-P03' RETURN a.code, COUNT(*) AS legs",
    );
    assert_eq!(p.period.as_deref(), Some("FY2026-P03"));
    assert_eq!(
        n.statement(9),
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account), (__fa_entry:Entry)-[:HAS_LEG]->(l), (__fa_entry)-[:IN_PERIOD]->(__fa_period:Period) FOR SYSTEM_TIME AS OF SEQ 9 WHERE __fa_period.code = 'FY2026-P03' RETURN a.code, COUNT(*) AS legs"
    );
    // An unquoted code, and a WHERE the filter is conjoined with.
    let (_, n) = native(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) WHERE a.code = '1000' OR a.code = '2000' RETURN l FOR PERIOD FY2026-P03",
    );
    assert!(
        n.statement(1).ends_with(
            "FOR SYSTEM_TIME AS OF SEQ 1 WHERE __fa_period.code = 'FY2026-P03' AND (a.code = '1000' OR a.code = '2000') RETURN l"
        ),
        "{}",
        n.statement(1)
    );
    // With no leg, one entry.
    let (_, n) = native("MATCH (e:Entry) FOR PERIOD 'FY2026-P01' RETURN COUNT(*) AS entries");
    assert_eq!(
        n.statement(4),
        "MATCH (e:Entry), (e)-[:IN_PERIOD]->(__fa_period:Period) FOR SYSTEM_TIME AS OF SEQ 4 WHERE __fa_period.code = 'FY2026-P01' RETURN COUNT(*) AS entries"
    );
    for (text, says) in [
        (
            "MATCH (a:Leg), (b:Leg) FOR PERIOD 'P' RETURN a, b",
            "exactly one leg",
        ),
        (
            "MATCH (a:Account) FOR PERIOD 'P' RETURN a",
            "exactly one leg",
        ),
        (
            "MATCH (:Leg)-[:POSTS_TO]->(a:Account) FOR PERIOD 'P' RETURN a",
            "exactly one leg",
        ),
        // A range compiles (fa-5c1); a range of one period is that period.
        ("MATCH (l:Leg) RETURN l FOR PERIOD 'A'..'A'", "range"),
        (
            "MATCH (l:Leg) RETURN l FOR PERIOD 'P' FOR PERIOD 'Q'",
            "one FOR PERIOD",
        ),
        (
            "MATCH (l:Leg) RETURN l FOR PERIOD 'P?'",
            "not a period code",
        ),
        (
            "MATCH (l:Leg) RETURN l UNION MATCH (m:Leg) RETURN m FOR PERIOD 'P'",
            "UNION",
        ),
    ] {
        let r = refused(text);
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
}

#[test]
fn effective_at_selects_every_leg_effective_on_or_before_its_day() {
    let day = DateDay::parse("2026-03-31").unwrap();
    let (p, n) = native(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs EFFECTIVE AT '2026-03-31'",
    );
    assert_eq!(p.effective, Some(fa_time::EffectiveSelector::AsOf(day)));
    assert_eq!(
        n.statement(4),
        format!(
            "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) FOR SYSTEM_TIME AS OF SEQ 4 WHERE l._fa_effective_day <= {} RETURN a.code, COUNT(*) AS legs",
            day.0
        )
    );
    // BETWEEN is the half-open range through the day after its last day; its
    // native text is what it always compiled to (certificates bind it).
    let (p, _) = native(
        "MATCH (l:Leg) RETURN COUNT(*) AS legs EFFECTIVE BETWEEN '2026-01-01' AND '2026-03-31'",
    );
    assert_eq!(
        p.effective,
        Some(fa_time::EffectiveSelector::Range {
            start: DateDay::parse("2026-01-01").unwrap(),
            end: DateDay::parse("2026-04-01").unwrap(),
        })
    );
    let (p, _) = native("MATCH (a:Account) RETURN a.code");
    assert_eq!(p.effective, None);
    for (text, says) in [
        (
            "MATCH (l:Leg) RETURN l EFFECTIVE AT '2026-02-30'",
            "one civil date",
        ),
        (
            "MATCH (l:Leg) RETURN l EFFECTIVE AT '2026-03-31' EFFECTIVE BETWEEN '2026-01-01' AND '2026-01-31'",
            "one EFFECTIVE selector",
        ),
        (
            "MATCH (l:Leg) RETURN l EFFECTIVE SOON",
            "EFFECTIVE AT <date> or EFFECTIVE BETWEEN",
        ),
        (
            "MATCH (e:Entry) RETURN e EFFECTIVE AT '2026-03-31'",
            "exactly one leg",
        ),
        (
            "CALL fa.trial_balance EFFECTIVE AT '2026-03-31'",
            "not by an EFFECTIVE selector",
        ),
    ] {
        let r = refused(text);
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
}

#[test]
fn effective_between_bounds_the_legs_effective_day() {
    let (_, n) = native(
        "MATCH (l:Leg) EFFECTIVE BETWEEN '2026-01-01' AND 2026-01-31 RETURN COUNT(*) AS legs",
    );
    let from = DateDay::parse("2026-01-01").unwrap().0;
    let through = DateDay::parse("2026-01-31").unwrap().0;
    assert_eq!(
        n.statement(5),
        format!(
            "MATCH (l:Leg) FOR SYSTEM_TIME AS OF SEQ 5 WHERE l._fa_effective_day >= {from} AND l._fa_effective_day <= {through} RETURN COUNT(*) AS legs"
        )
    );
    for (text, says) in [
        // EFFECTIVE AT a date compiles (below); a relationship's valid time
        // does not.
        (
            "MATCH (l:Leg) EFFECTIVE AT l.effective_day RETURN l",
            "valid time",
        ),
        (
            "MATCH (l:Leg) EFFECTIVE BETWEEN '2026-02-01' AND '2026-01-01' RETURN l",
            "ends before",
        ),
        (
            "MATCH (l:Leg) EFFECTIVE BETWEEN 'soon' AND '2026-01-01' RETURN l",
            "two civil dates",
        ),
        (
            "MATCH (e:Entry) EFFECTIVE BETWEEN '2026-01-01' AND '2026-01-31' RETURN e",
            "exactly one leg",
        ),
    ] {
        let r = refused(text);
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
}

#[test]
fn names_that_spell_a_selector_word_stay_names() {
    // Aliases and properties are not selectors.
    let (p, n) = native("MATCH (l:Leg) RETURN l.side AS effective, COUNT(*) AS known");
    assert_eq!(p.known_at, KnownAt::Head);
    assert_eq!(
        n.statement(1),
        "MATCH (l:Leg) FOR SYSTEM_TIME AS OF SEQ 1 RETURN l.side AS effective, COUNT(*) AS known"
    );
    native("MATCH (n:Entry) RETURN n.delete");
    // Quotes and comments follow the substrate's lexical rules.
    let (_, n) = native(
        "MATCH (a:Account) // AS KNOWN AT 1\nWHERE a.name = 'it''s RETURN /* not */ here' RETURN a.code /* trailing */",
    );
    assert!(
        n.statement(2).contains("'it''s RETURN /* not */ here'"),
        "{}",
        n.statement(2)
    );
    assert!(
        refused("MATCH (a:Account) WHERE a.name = 'open RETURN a")
            .message
            .contains("never closed")
    );
    assert!(
        refused("MATCH (a:Account) /* RETURN a")
            .message
            .contains("never closed")
    );
}

#[test]
fn branches_procedures_and_certificates() {
    native("MATCH (a:Account) AT BRANCH trunk RETURN a.code");
    // EXPLAIN (CERTIFICATE) leads the statement and certifies its result;
    // the native read is the same statement's.
    let (explained, n) = native(
        "EXPLAIN (CERTIFICATE) MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs AS KNOWN AT 7",
    );
    assert!(explained.certify);
    assert_eq!(explained.known_at, KnownAt::Seq(7));
    assert_eq!(
        n.statement(7),
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) FOR SYSTEM_TIME AS OF SEQ 7 RETURN a.code, COUNT(*) AS legs"
    );
    assert!(!native("MATCH (a:Account) RETURN a.code").0.certify);
    assert!(
        rewrite("EXPLAIN (CERTIFICATE) CALL fa.trial_balance FOR PERIOD 'FY2026-P03'")
            .expect("a certified trial balance")
            .certify
    );
    assert!(
        refused("EXPLAIN (CERTIFICATE)")
            .message
            .contains("only selectors")
    );
    assert!(
        refused("MATCH (a:Account) AT BRANCH 'what-if' RETURN a.code")
            .fix
            .contains("AT BRANCH 'scenario:<name>'")
    );
    // A scenario's replay, read at its head: the native read is the same
    // statement, and the caller reads it on the scenario's materialization.
    let (on_scenario, n) = native("MATCH (a:Account) AT BRANCH 'scenario:but-for' RETURN a.code");
    assert_eq!(on_scenario.branch.as_deref(), Some("scenario:but-for"));
    let (on_draft, _) = native("MATCH (a:Account) AT BRANCH 'draft:march' RETURN a.code");
    assert_eq!(on_draft.branch.as_deref(), Some("draft:march"));
    assert_eq!(on_scenario.known_at, KnownAt::Head);
    assert_eq!(
        n.statement(3),
        "MATCH (a:Account) FOR SYSTEM_TIME AS OF SEQ 3 RETURN a.code"
    );
    assert!(
        native("MATCH (a:Account) AT BRANCH trunk RETURN a.code")
            .0
            .branch
            .is_none()
    );
    native("MATCH (a:Account) RETURN a.code AT BRANCH 'scenario:x' AS KNOWN AT HEAD");
    for (text, says) in [
        (
            "MATCH (a:Account) AT BRANCH 'scenario:' RETURN a.code",
            "trunk, one scenario or one draft",
        ),
        (
            "MATCH (a:Account) AT BRANCH 'draft:' RETURN a.code",
            "trunk, one scenario or one draft",
        ),
        (
            "MATCH (a:Account) AT BRANCH scenario RETURN a.code",
            "trunk, one scenario or one draft",
        ),
        (
            "MATCH (a:Account) AT BRANCH 'draft:march' RETURN a.code AS KNOWN AT 7",
            "replay's head",
        ),
        (
            "MATCH (a:Account) AT BRANCH trunk AT BRANCH 'scenario:x' RETURN a.code",
            "one AT BRANCH",
        ),
        (
            "MATCH (a:Account) AT BRANCH 'scenario:x' RETURN a.code AS KNOWN AT 7",
            "replay's head",
        ),
        (
            "EXPLAIN (CERTIFICATE) MATCH (a:Account) AT BRANCH 'scenario:x' RETURN a.code",
            "not certified",
        ),
    ] {
        let r = refused(text);
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
    let p = rewrite("CALL fa.trial_balance FOR PERIOD 'FY2026-P03' AS KNOWN AT 12").unwrap();
    assert_eq!(p.selection, Selection::TrialBalance);
    assert_eq!(p.period.as_deref(), Some("FY2026-P03"));
    assert_eq!(p.known_at, KnownAt::Seq(12));
    assert_eq!(
        rewrite("CALL fa.trial_balance()").unwrap().selection,
        Selection::TrialBalance
    );
    // The other registered reads, each with its own selection law.
    let explained =
        rewrite("CALL fa.explain_balance('6000') FOR PERIOD 'FY2026-P03' AS KNOWN AT 12").unwrap();
    assert_eq!(
        explained.selection,
        Selection::ExplainBalance {
            account: "6000".into()
        }
    );
    assert_eq!(explained.known_at, KnownAt::Seq(12));
    assert_eq!(
        rewrite("CALL fa.explain_balance('6000') FOR PERIOD 'FY2026-P03' AS ORIGINALLY REPORTED")
            .unwrap()
            .known_at,
        KnownAt::Reported(Reported::Originally)
    );
    // CALL fa.statement is `fa statement <definition> --for`, with the
    // statement's known-at or view.
    let stated =
        rewrite("CALL fa.statement('income-statement') FOR PERIOD 'FY2026-P03' AS KNOWN AT 9")
            .unwrap();
    assert_eq!(
        stated.selection,
        Selection::Statement {
            definition: "income-statement".into()
        }
    );
    assert_eq!(stated.period.as_deref(), Some("FY2026-P03"));
    assert_eq!(stated.known_at, KnownAt::Seq(9));
    for (text, account) in [
        ("CALL fa.open_items", None),
        ("CALL fa.open_items() AS KNOWN AT 4", None),
        ("CALL fa.open_items('1200')", Some("1200".to_string())),
        // The list form the docs and the CALL fix hint name.
        ("CALL fa.open_items(['1200'])", Some("1200".to_string())),
    ] {
        assert_eq!(
            rewrite(text).unwrap().selection,
            Selection::OpenItems { account },
            "{text}"
        );
    }
    for (text, says) in [
        ("CALL fa.trial_balance('1000')", "takes no argument"),
        (
            "CALL fa.explain_balance FOR PERIOD 'FY2026-P03'",
            "takes the account code",
        ),
        ("CALL fa.explain_balance('6000')", "names no FOR PERIOD"),
        (
            "CALL fa.explain_balance('6000', '6100') FOR PERIOD 'FY2026-P03'",
            "stands alone",
        ),
        (
            "CALL fa.open_items('1200') FOR PERIOD 'FY2026-P03'",
            "not for a period",
        ),
        ("CALL fa.open_items(['1200', '1300'])", "stands alone"),
        (
            "CALL fa.open_items EFFECTIVE BETWEEN '2026-01-01' AND '2026-01-31'",
            "by period and known-at",
        ),
        (
            "CALL fa.statement FOR PERIOD 'FY2026-P03'",
            "takes the statement it reads",
        ),
        ("CALL fa.statement('balance-sheet')", "names no FOR PERIOD"),
        (
            "CALL fa.statement('diff') FOR PERIOD 'FY2026-P03'",
            "is the `fa statement diff` workflow",
        ),
        (
            "CALL fa.statement('balance-sheet') FOR PERIOD 'FY2026-P03'..'FY2026-P04'",
            "not a period range",
        ),
    ] {
        let r = refused(text);
        assert_eq!(r.law, Law::Profile, "{text}");
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
    for (text, says) in [
        ("CALL fa.open_amount(l)", "not a profile procedure"),
        ("CALL db.labels()", "not a profile procedure"),
        ("CALL fa.trial_balance YIELD rows", "stands alone"),
        (
            "CALL fa.trial_balance EFFECTIVE BETWEEN '2026-01-01' AND '2026-01-31'",
            "by period",
        ),
        (
            "MATCH (l:Leg) CALL fa.open_amount(l) RETURN l",
            "a pipeline CALL",
        ),
        ("EXPLAIN MATCH (a:Account) RETURN a", "EXPLAIN takes"),
        (
            "MATCH (a:Account) EXPLAIN (CERTIFICATE) RETURN a",
            "leads the statement",
        ),
        (
            "MATCH (a:Account) RETURN a AS ORIGINALLY REPORTED",
            "names no FOR PERIOD",
        ),
        (
            "MATCH (a:Account) RETURN a AS REPORTED IN 'C:00'",
            "names no FOR PERIOD",
        ),
    ] {
        let r = refused(text);
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
}

#[test]
fn per_row_open_amount_keeps_the_source_and_native_continuation_at_one_prefix() {
    let (profile, native) = native(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account {code:'1200'}) \
         CALL fa.open_amount(l) YIELD open, age_days \
         WHERE age_days > 90 RETURN a.code AS account, open, age_days \
         ORDER BY age_days DESC LIMIT 20 \
         FOR PERIOD 'FY2026-P03' EFFECTIVE AT '2026-03-31' AS KNOWN AT 42",
    );
    assert_eq!(profile.known_at, KnownAt::Seq(42));
    let call = native.open_amount().unwrap();
    assert_eq!(
        call.effective_through(),
        DateDay::parse("2026-03-31").unwrap()
    );
    assert_eq!(call.input_columns(), 2);
    assert_eq!(call.columns(), ["account", "open", "age_days"]);
    assert_eq!(call.parameter(), "__fa_rows");
    assert!(
        native
            .statement(42)
            .contains("FOR SYSTEM_TIME AS OF SEQ 42")
    );
    assert!(
        native
            .statement(42)
            .contains("__fa_period.code = 'FY2026-P03'")
    );
    assert!(native.statement(42).contains("l._fa_effective_day <="));
    assert!(
        native
            .statement(42)
            .ends_with("RETURN l AS __fa_c0, a.code AS __fa_c1")
    );
    assert!(!native.statement(42).contains("age_days >"));
    assert_eq!(
        call.statement(42),
        "UNWIND $__fa_rows AS __fa_row FOR SYSTEM_TIME AS OF SEQ 42 WITH __fa_row.c0 AS __fa_c0, __fa_row.c1 AS __fa_c1, __fa_row.open AS open, __fa_row.age_days AS age_days WHERE age_days > 90 RETURN __fa_c1 AS account, open, age_days ORDER BY age_days DESC LIMIT 20"
    );
    let (_, ranged) = native_for_open_amount_range();
    let bound = ranged.bind_period_range(100, 200);
    assert_eq!(ranged.open_amount(), bound.open_amount());
    assert!(!bound.period_range());
}

fn native_for_open_amount_range() -> (Profiled, Native) {
    native(
        "MATCH (l:Leg) CALL fa.open_amount(l) YIELD open, age_days RETURN open FOR PERIOD 'A'..'B' EFFECTIVE AT '2026-03-31'",
    )
}

#[test]
fn yielded_open_amount_keeps_its_unit_and_exact_aggregation_contract() {
    let (_, query) = native(
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) \
         CALL fa.open_amount(l) YIELD open, age_days WHERE age_days > 30 \
         RETURN u.code AS unit, SUM(open) AS exposure, AVG(open) AS average \
         ORDER BY unit EFFECTIVE AT '2026-03-31'",
    );
    let aggregation = query.aggregation().unwrap();
    assert_eq!(
        aggregation
            .columns
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        ["unit", "exposure", "average"]
    );
    assert!(matches!(
        aggregation.columns[1].value,
        Value::Aggregate {
            function: Function::Sum,
            amount: true,
            ..
        }
    ));
    assert!(matches!(
        aggregation.columns[2].value,
        Value::Aggregate {
            function: Function::Avg,
            amount: true,
            ..
        }
    ));
    assert!(!query.open_amount().unwrap().statement(3).contains("SUM("));
    for suffix in [
        "RETURN SUM(open)",
        "WHERE open > 0 RETURN open",
        "RETURN open ORDER BY open",
        "RETURN u.code, SUM(open) AS total ORDER BY total",
    ] {
        let text = format!(
            "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) CALL fa.open_amount(l) YIELD open, age_days {suffix} EFFECTIVE AT '2026-03-31'"
        );
        assert_eq!(refused(&text).law, Law::Amount, "{text}");
    }
    let (_, pinned) = native(
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit {code:'USD'}) CALL fa.open_amount(l) YIELD open, age_days RETURN SUM(open) AS exposure ORDER BY exposure EFFECTIVE AT '2026-03-31'",
    );
    assert!(pinned.aggregation().is_some());
    let (_, nullable) = native(
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) CALL fa.open_amount(l) YIELD open, age_days WHERE open IS NOT NULL RETURN u.code, SUM(open) EFFECTIVE AT '2026-03-31'",
    );
    assert!(nullable.aggregation().is_some());
}

#[test]
fn a_pipeline_refuses_unbound_calls_ambiguous_names_and_unsupported_shapes() {
    let good = "MATCH (l:Leg) CALL fa.open_amount(l) YIELD open, age_days RETURN open EFFECTIVE AT '2026-03-31'";
    for text in [
        good.replace("EFFECTIVE AT '2026-03-31'", ""),
        good.replace(
            "EFFECTIVE AT '2026-03-31'",
            "EFFECTIVE BETWEEN '2026-03-01' AND '2026-03-31'",
        ),
        good.replace("fa.open_amount(l)", "fa.open_amount(m)"),
        good.replace("(l:Leg)", "(l:Account)"),
        good.replace("fa.open_amount(l)", "fa.lineage_net(l)"),
        good.replace("YIELD open, age_days", "YIELD open AS amount, age_days"),
        good.replace("RETURN open", "WITH open RETURN open"),
        good.replace("RETURN open", "MATCH (x:Account) RETURN open"),
        good.replace(
            "RETURN open",
            "CALL fa.open_amount(l) YIELD open, age_days RETURN open",
        ),
        good.replace("RETURN open", "RETURN *"),
        good.replace("RETURN open", "RETURN open AS l ORDER BY l"),
        good.replace("RETURN open", "RETURN l.amount AS open"),
        good.replace("RETURN open", "RETURN l.amount AS `open`"),
        good.replace("MATCH (l:Leg)", "MATCH (l:Leg), (open:Account)"),
        format!("EXPLAIN (CERTIFICATE) {good} AT BRANCH 'scenario:forecast'"),
    ] {
        assert_eq!(refused(&text).law, Law::Profile, "{text}");
    }
    let (profile, certified) = native(&format!("EXPLAIN (CERTIFICATE) {good}"));
    let (_, plain) = native(good);
    assert!(profile.certify);
    assert_eq!(
        certified, plain,
        "certification retains the same two stages"
    );
}

/// Plan §7.4: a restatement view is a known-at selector of one period's
/// report. It compiles to the one system-time clause, the sequence the
/// caller resolves, and refuses without a period, beside another known-at
/// or on a branch.
#[test]
fn restatement_views_select_the_period_as_it_was_reported() {
    for (text, view) in [
        (
            "MATCH (e:Entry) FOR PERIOD 'FY2026-P03' RETURN COUNT(*) AS entries AS ORIGINALLY REPORTED",
            Reported::Originally,
        ),
        (
            "MATCH (e:Entry) FOR PERIOD 'FY2026-P03' AS ISSUED TO 'board' RETURN COUNT(*) AS entries",
            Reported::IssuedTo("board".into()),
        ),
        (
            "AS REPORTED IN 'C:ab' MATCH (e:Entry) FOR PERIOD 'FY2026-P03' RETURN COUNT(*) AS entries",
            Reported::In("C:ab".into()),
        ),
    ] {
        let (p, n) = native(text);
        assert_eq!(p.known_at, KnownAt::Reported(view), "{text}");
        assert_eq!(p.period.as_deref(), Some("FY2026-P03"), "{text}");
        assert_eq!(
            n.statement(9),
            "MATCH (e:Entry), (e)-[:IN_PERIOD]->(__fa_period:Period) FOR SYSTEM_TIME AS OF SEQ 9 WHERE __fa_period.code = 'FY2026-P03' RETURN COUNT(*) AS entries",
            "{text}"
        );
    }
    let tb = rewrite("CALL fa.trial_balance FOR PERIOD 'FY2026-P03' AS ORIGINALLY REPORTED")
        .expect("the trial balance as originally reported");
    assert_eq!(tb.selection, Selection::TrialBalance);
    assert_eq!(tb.known_at, KnownAt::Reported(Reported::Originally));
    // An alias that spells a view word stays a name.
    let (p, _) = native("MATCH (e:Entry) FOR PERIOD 'FY2026-P03' RETURN e AS originally");
    assert_eq!(p.known_at, KnownAt::Head);
    for (text, says) in [
        (
            "CALL fa.trial_balance AS ORIGINALLY REPORTED",
            "names no FOR PERIOD",
        ),
        (
            "MATCH (e:Entry) FOR PERIOD 'FY2026-P03' RETURN e AS ORIGINALLY REPORTED AS KNOWN AT 3",
            "one known-at",
        ),
        (
            "MATCH (e:Entry) FOR PERIOD 'FY2026-P03' RETURN e AS ISSUED TO board",
            "quoted audience",
        ),
        (
            "MATCH (e:Entry) FOR PERIOD 'FY2026-P03' RETURN e AS REPORTED IN C",
            "quoted statement certificate",
        ),
        (
            "MATCH (e:Entry) FOR PERIOD 'FY2026-P03' AT BRANCH 'scenario:x' RETURN e AS ORIGINALLY REPORTED",
            "replay's head",
        ),
    ] {
        let r = refused(text);
        assert_eq!(r.law, Law::Profile, "{text}");
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
}

#[test]
fn a_query_only_reads() {
    for (text, says) in [
        ("MATCH (a:Account) SET a.name = 'x' RETURN a", "read-only"),
        ("MATCH (a:Account) DETACH DELETE a", "read-only"),
        ("CREATE (a:Account)", "read-only"),
        (
            "MATCH (a:Account) WHERE a.code = $code RETURN a",
            "no parameters",
        ),
        ("MATCH (r:Register) RETURN r", "register cache"),
        ("MATCH (r:Leg|RegisterState) RETURN r", "register cache"),
        ("MATCH (r:RegisterCheckpoint) RETURN r", "register cache"),
        (
            "MATCH (r:Leg|RegisterCheckpoint) RETURN r",
            "register cache",
        ),
        (
            "MATCH (r:Entry&RegisterCheckpoint) RETURN r",
            "register cache",
        ),
        ("MATCH (__fa_entry:Entry) RETURN __fa_entry", "__fa_"),
        ("OPTIONAL MATCH (a:Account) RETURN a", "begins with MATCH"),
        ("MATCH (a:Account)", "returns nothing"),
        ("AS KNOWN AT 3", "only selectors"),
        ("", "bytes of text"),
    ] {
        let r = refused(text);
        assert_eq!(r.law, Law::Profile, "{text}");
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
}

#[test]
fn an_aggregate_over_amounts_is_confined_to_one_unit() {
    for text in [
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) RETURN u.code, SUM(l.amount) AS total",
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) RETURN u, l.side, SUM(l.amount) AS total",
        "MATCH (u:Unit)<-[:IN_UNIT]-(l:Leg) RETURN u.unit_id, AVG(l.amount) AS mean",
        "MATCH (l:Leg) RETURN l.unit_id, SUM(l.amount) AS total",
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit {code: 'USD'}) RETURN SUM(l.amount) AS total",
        "MATCH (l:Leg) WHERE l.unit_id = 1 RETURN MAX(l.amount) AS largest",
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) WHERE u.code = 'USD' AND l.side = 0 RETURN SUM(l.amount) AS debits",
    ] {
        let (_, n) = native(text);
        assert!(n.aggregation().is_some(), "{text}");
    }
    for text in [
        "MATCH (l:Leg) RETURN SUM(l.amount) AS total",
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, SUM(l.amount) AS total",
        // An account code is not a unit.
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) WHERE a.code = '1000' RETURN SUM(l.amount) AS total",
        // A pin under OR pins nothing.
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) WHERE u.code = 'USD' OR u.code = 'EUR' RETURN SUM(l.amount) AS total",
        // A negated pin pins nothing.
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) WHERE NOT u.code = 'USD' RETURN SUM(l.amount) AS total",
        "MATCH (l:Leg) RETURN COLLECT(l.amount) AS amounts",
        // The unit key must be its own item, outside the aggregate.
        "MATCH (l:Leg) RETURN SUM(l.amount + l.unit_id) AS total",
    ] {
        let r = refused(text);
        assert_eq!(r.law, Law::Amount, "{text}: {r:?}");
        assert!(
            r.fix.contains("per unit") || r.fix.contains("pin one unit"),
            "{text}: {r:?}"
        );
    }
}

#[test]
fn an_amount_compares_only_within_one_unit_and_never_with_a_literal() {
    for text in [
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit {code: 'USD'}) RETURN l ORDER BY l.amount DESC",
        "MATCH (a:Leg)-[:IN_UNIT]->(u:Unit {code: 'USD'}), (b:Leg)-[:IN_UNIT]->(v:Unit {code: 'USD'}) WHERE a.amount = b.amount RETURN a, b",
        "MATCH (l:Leg) RETURN l.amount, l.unit_id",
        "MATCH (l:Leg) WHERE l.amount IS NULL RETURN COUNT(*) AS unmirrored",
        "MATCH (l:Leg) RETURN COUNT(l.amount) AS mirrored",
    ] {
        native(text);
    }
    for (text, says) in [
        ("MATCH (l:Leg) RETURN l ORDER BY l.amount", "across units"),
        (
            "MATCH (l:Leg) WHERE l.unit_id = 1 AND l.amount > 100 RETURN l",
            "literal",
        ),
        ("MATCH (l:Leg) WHERE 100 <= l.amount RETURN l", "literal"),
        ("MATCH (l:Leg {amount: 5}) RETURN l", "literal"),
        ("MATCH (l:Leg) WHERE l.amount > 0.5 RETURN l", "float"),
        (
            "MATCH (a:Leg), (b:Leg) RETURN a.amount + b.amount AS both",
            "not pinned to one unit",
        ),
        (
            "MATCH (a:Leg)-[:IN_UNIT]->(u:Unit {code: 'USD'}), (b:Leg)-[:IN_UNIT]->(v:Unit {code: 'EUR'}) WHERE a.amount > b.amount RETURN a",
            "different units",
        ),
        // An aggregate's alias carries its unit: grouped is not pinned.
        (
            "MATCH (l:Leg) WITH l.unit_id AS unit, SUM(l.amount) AS total RETURN unit, total ORDER BY total",
            "across units",
        ),
    ] {
        let r = refused(text);
        assert_eq!(r.law, Law::Amount, "{text}: {r:?}");
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
}

#[test]
fn an_amount_aggregate_returns_its_keys_and_arguments_for_exact_aggregation() {
    let (_, n) = native(
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit {code: 'USD'}) WHERE l.side = 0 RETURN u.code AS unit, COUNT(*) AS legs, SUM(l.amount) AS total, MAX(l.amount) ORDER BY total DESC, unit LIMIT 5 FOR PERIOD 'FY2026-P03'",
    );
    assert_eq!(
        n.statement(4),
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit {code: 'USD'}), (__fa_entry:Entry)-[:HAS_LEG]->(l), (__fa_entry)-[:IN_PERIOD]->(__fa_period:Period) FOR SYSTEM_TIME AS OF SEQ 4 WHERE __fa_period.code = 'FY2026-P03' AND (l.side = 0) RETURN u.code AS __fa_c0, l.amount AS __fa_c1, l.amount AS __fa_c2"
    );
    let plan = n.aggregation().expect("an aggregation");
    let names: Vec<&str> = plan.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["unit", "legs", "total", "MAX(l.amount)"]);
    assert_eq!(plan.columns[0].value, Value::Key(0));
    assert_eq!(
        plan.columns[1].value,
        Value::Aggregate {
            function: Function::Count,
            native: None,
            amount: false
        }
    );
    assert_eq!(
        plan.columns[2].value,
        Value::Aggregate {
            function: Function::Sum,
            native: Some(1),
            amount: true
        }
    );
    assert_eq!(plan.order, [(2, true), (0, false)]);
    assert_eq!((plan.skip, plan.limit), (0, Some(5)));
    for (text, says) in [
        (
            "MATCH (l:Leg) WHERE l.unit_id = 2 WITH SUM(l.amount) AS total RETURN total",
            "before the final RETURN",
        ),
        (
            "MATCH (l:Leg) RETURN DISTINCT l.unit_id, SUM(l.amount) AS total",
            "DISTINCT",
        ),
        (
            "MATCH (l:Leg) RETURN l.unit_id, SUM(l.amount) + 1 AS total",
            "inside an expression",
        ),
        (
            "MATCH (l:Leg) RETURN l.unit_id, SUM(l.amount * 2) AS total",
            "one binding or property",
        ),
        (
            "MATCH (l:Leg) RETURN l.unit_id, SUM(l.amount) AS total ORDER BY l.side",
            "names no RETURN column",
        ),
        (
            "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit {code: 'USD'}) RETURN l.side, AVG(l.amount) AS mean ORDER BY mean",
            "average",
        ),
        (
            "MATCH (l:Leg) RETURN l.unit_id AS u, SUM(l.amount) AS total UNION MATCH (m:Leg) RETURN m.unit_id AS u, SUM(m.amount) AS total",
            "UNION",
        ),
    ] {
        let r = refused(text);
        assert_eq!(r.law, Law::Profile, "{text}: {r:?}");
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
    // Grouping by unit keeps each total within its unit, but ordering the
    // groups by their totals compares one unit's total with another's.
    let r =
        refused("MATCH (l:Leg) RETURN l.unit_id AS unit, SUM(l.amount) AS total ORDER BY total");
    assert_eq!(r.law, Law::Amount, "{r:?}");
    assert!(r.message.contains("across units"), "{r:?}");
}

/// fa-2zf5: an amount aggregate is admitted only when its unit is proved in
/// scope. An item that only mentions a unit key groups nothing; a pin from
/// an `OPTIONAL MATCH` null-extends instead of dropping rows; a `WITH` passes
/// on only the bindings it projects; and a `UNION` arm proves nothing about
/// the other. Each refused form summed or ordered amounts of several units.
#[test]
fn cross_unit_aggregates_are_refused_whatever_the_grouping_or_pin_scope() {
    for (text, says) in [
        (
            "MATCH (l:Leg) RETURN l.unit_id * 0 AS k, SUM(l.amount) AS total",
            "adds amounts of every unit",
        ),
        (
            "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) RETURN size(u.code) AS n, SUM(l.amount) AS total",
            "adds amounts of every unit",
        ),
        (
            "MATCH (l:Leg) OPTIONAL MATCH (l)-[:IN_UNIT]->(u:Unit) WHERE u.code = 'USD' RETURN SUM(l.amount) AS total",
            "adds amounts of every unit",
        ),
        (
            "MATCH (l:Leg) OPTIONAL MATCH (l)-[:IN_UNIT]->(u:Unit {code: 'USD'}) RETURN SUM(l.amount) AS total",
            "adds amounts of every unit",
        ),
        (
            "MATCH (l:Leg) OPTIONAL MATCH (l)-[:IN_UNIT]->(u:Unit) RETURN u.code AS unit, SUM(l.amount) AS total",
            "adds amounts of every unit",
        ),
        (
            "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit {code: 'USD'}) WITH COUNT(*) AS n MATCH (l:Leg) RETURN n, SUM(l.amount) AS total",
            "adds amounts of every unit",
        ),
        (
            "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) WITH l MATCH (u:Unit) RETURN u.code AS unit, SUM(l.amount) AS total",
            "adds amounts of every unit",
        ),
        (
            "MATCH (l:Leg) WHERE l.unit_id = 1 RETURN l UNION MATCH (l:Leg) RETURN l ORDER BY l.amount",
            "across units",
        ),
    ] {
        let r = refused(text);
        assert_eq!(r.law, Law::Amount, "{text}: {r:?}");
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
    // A unit key itself, or a binding a WITH projects unchanged, still proves
    // the unit.
    for text in [
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) RETURN u.code AS unit, SUM(l.amount) AS total",
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) RETURN u, SUM(l.amount) AS total",
        "MATCH (l:Leg) RETURN l.unit_id AS unit, SUM(l.amount) AS total",
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit {code: 'USD'}) WITH l MATCH (l)-[:POSTS_TO]->(a:Account) RETURN a.code AS account, SUM(l.amount) AS total",
        "MATCH (l:Leg) WHERE l.unit_id = 1 WITH l AS m RETURN SUM(m.amount) AS total",
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) WITH l, u RETURN u.code AS unit, SUM(l.amount) AS total",
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) WITH * RETURN u.code AS unit, SUM(l.amount) AS total",
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) WITH l, u WHERE u.code = 'USD' RETURN SUM(l.amount) AS total",
    ] {
        let (_, n) = native(text);
        assert!(n.aggregation().is_some(), "{text}");
    }
}

/// fa-2zf5: an aggregate over a `WITH` alias of an amount is an amount
/// aggregate. It ran natively, where `MAX` skips a null mirror; the profile
/// now computes it exactly, as it does `MAX(l.amount)`, refusing a null.
#[test]
fn an_aggregate_over_an_amount_alias_is_computed_exactly() {
    let (_, n) = native(
        "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit {code: 'USD'}) WITH l.amount AS x RETURN MAX(x) AS top",
    );
    let plan = n.aggregation().expect("an exact aggregation");
    assert_eq!(
        plan.columns[0].value,
        Value::Aggregate {
            function: Function::Max,
            native: Some(0),
            amount: true
        }
    );
    // Unpinned, the alias adds every unit, as its source would.
    let r = refused("MATCH (l:Leg) WITH l.amount AS x RETURN MAX(x) AS top");
    assert_eq!(r.law, Law::Amount, "{r:?}");
    assert!(r.message.contains("adds amounts of every unit"), "{r:?}");
}

/// fa-5c1, the runtime graph: `CALL fa.access_log` is the AccessEvent read
/// itself, at trunk's head, optionally one reader's; every coordinate it
/// cannot honour is refused with the admissible form, never ignored.
#[test]
fn a_lantern_procedure_call_runs_the_registered_procedure() {
    let call = rewrite(
        "CALL fa.trace('libr', {account: '1000', source: 'E:ab12', round_power: 2}) EFFECTIVE AT '2026-03-31' AS KNOWN AT 7",
    )
    .unwrap();
    assert_eq!(
        call.selection,
        Selection::Procedure {
            id: "trace.libr".into(),
            arguments: vec![
                ("account".into(), ProcedureArgument::Text("1000".into())),
                ("source".into(), ProcedureArgument::Text("E:ab12".into())),
                ("round_power".into(), ProcedureArgument::Integer("2".into())),
            ],
        }
    );
    assert_eq!(call.known_at, KnownAt::Seq(7));
    assert_eq!(
        call.effective,
        Some(fa_time::EffectiveSelector::AsOf(
            DateDay::parse("2026-03-31").unwrap()
        ))
    );
    assert_eq!(
        rewrite("CALL fa.jet('round_amounts')").unwrap().selection,
        Selection::Procedure {
            id: "jet.round_amounts".into(),
            arguments: Vec::new(),
        }
    );
    for (text, says) in [
        (
            "CALL fa.jet('round_amounts') FOR PERIOD 'FY2026-P03'",
            "not for a period",
        ),
        (
            "CALL fa.jet('round_amounts') EFFECTIVE BETWEEN '2026-01-01' AND '2026-01-31'",
            "not BETWEEN",
        ),
        (
            "EXPLAIN (CERTIFICATE) CALL fa.jet('round_amounts') AT BRANCH 'scenario:forecast'",
            "not certified",
        ),
        ("CALL fa.jet('Round-Amounts')", "lowercase letters"),
        (
            "CALL fa.trace('libr', {round_power: high})",
            "quoted text or an integer",
        ),
        (
            "CALL fa.trace('libr', {round_power: 1, round_power: 2})",
            "named twice",
        ),
        ("CALL fa.trace('libr', 'x')", "one map"),
        (
            "CALL fa.jet('round_amounts') YIELD findings",
            "stands alone",
        ),
        (
            "CALL fa.jet('round_amounts') AS KNOWN AT '2026-03-15T00:00:00Z'",
            "recorded sequence",
        ),
    ] {
        let r = refused(text);
        assert_eq!(r.law, Law::Profile, "{text}");
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
}

#[test]
fn constant_procedure_certification_preserves_versions_arguments_and_coordinates() {
    for (selector, version, cutoff) in [
        ("round_amounts", None, true),
        ("round_amounts@1", Some(1), false),
        ("round_amounts@2", Some(2), true),
    ] {
        let text = format!(
            "CALL fa.jet('{selector}', {{round_power: 2, budget: 1000}}) AS KNOWN AT 7{}",
            if cutoff {
                " EFFECTIVE AT '2026-03-31'"
            } else {
                ""
            }
        );
        let plain = rewrite(&text).unwrap();
        let certified = rewrite(&format!("EXPLAIN (CERTIFICATE) {text}")).unwrap();
        assert!(!plain.certify);
        assert!(certified.certify);
        assert_eq!(plain.selection, certified.selection);
        assert_eq!(certified.known_at, KnownAt::Seq(7));
        assert_eq!(
            certified.effective,
            cutoff.then(|| EffectiveSelector::AsOf(DateDay::parse("2026-03-31").unwrap()))
        );
        assert_eq!(
            certified.selection,
            Selection::Procedure {
                id: version.map_or_else(
                    || "jet.round_amounts".into(),
                    |version| format!("jet.round_amounts@{version}"),
                ),
                arguments: vec![
                    ("round_power".into(), ProcedureArgument::Integer("2".into())),
                    ("budget".into(), ProcedureArgument::Integer("1000".into())),
                ],
            }
        );
    }
    for version in ["", "0", "01", "-1", "+1", "65536", "1@2", "one"] {
        let text = format!("EXPLAIN (CERTIFICATE) CALL fa.jet('round_amounts@{version}')");
        let refusal = refused(&text);
        assert_eq!(refusal.law, Law::Profile, "{text}");
        assert!(
            refusal.message.contains("canonical positive u16"),
            "{refusal:?}"
        );
    }
    // Registry availability is the direct procedure runner's decision. The
    // pure rewriter preserves a syntactically valid requested version exactly.
    assert!(matches!(
        rewrite("CALL fa.jet('round_amounts@65535')").unwrap().selection,
        Selection::Procedure { id, .. } if id == "jet.round_amounts@65535"
    ));
}

#[test]
fn the_access_log_procedure_reads_the_runtime_graph_at_the_head() {
    assert!(PROCEDURES.contains(&"fa.access_log"));
    let all = rewrite("CALL fa.access_log").expect("the whole log");
    assert_eq!(all.selection, Selection::AccessLog { reader: None });
    assert_eq!(all.known_at, KnownAt::Head);
    let one = rewrite("CALL fa.access_log('auditor-7') AS KNOWN AT HEAD").expect("one reader");
    assert_eq!(
        one.selection,
        Selection::AccessLog {
            reader: Some("auditor-7".into())
        }
    );
    for text in [
        "CALL fa.access_log FOR PERIOD 'FY2026-P03'",
        "CALL fa.access_log AS KNOWN AT 7",
        "CALL fa.access_log AT BRANCH 'scenario:x'",
        "EXPLAIN (CERTIFICATE) CALL fa.access_log",
    ] {
        let r = refused(text);
        assert!(r.message.contains("fa.access_log"), "{text}: {r:?}");
        assert!(r.fix.contains("fa access log --since"), "{text}: {r:?}");
    }
    assert!(
        refused("CALL fa.access_log('a') YIELD x")
            .message
            .contains("stands alone")
    );
}

/// fa-5c1, plan §7.4: `FOR PERIOD '<from>'..'<through>'` selects every
/// period lying between its ends. The native filter waits for the days the
/// caller resolves at the statement's sequence; a single period stays a code
/// filter with nothing to bind. A CALL and a restatement view read one
/// period, so a range is refused there, with the admissible form.
#[test]
fn a_period_range_selects_every_period_between_its_ends() {
    let (profiled, n) = native(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs FOR PERIOD 'FY2026-P01'..'FY2026-P03'",
    );
    assert_eq!(profiled.period.as_deref(), Some("FY2026-P01..FY2026-P03"));
    assert!(n.period_range());
    let bound = n.bind_period_range(20454, 20544);
    assert!(!bound.period_range());
    let text = bound.statement(9);
    assert!(
        text.contains("__fa_period.period_start >= 20454 AND __fa_period.period_end <= 20544"),
        "{text}"
    );
    assert!(text.contains("FOR SYSTEM_TIME AS OF SEQ 9"), "{text}");
    // A certificate's native read names its bounds; only the exact bound
    // statement at its sequence gives them back.
    assert_eq!(n.bound_period_range(&text, 9), Some((20454, 20544)));
    assert_eq!(n.bound_period_range(&text, 8), None);
    assert_eq!(n.bound_period_range(&n.statement(9), 9), None);
    assert_eq!(
        n.bound_period_range(&text.replace(">= 20454", ">= 020454"), 9),
        None
    );
    assert_eq!(
        n.bound_period_range(&text.replace("COUNT(*)", "COUNT(l)"), 9),
        None
    );
    // A quoted text spelling a placeholder is the statement's own.
    let (_, quoted) = native(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) WHERE a.name = '__fa_period_range_start__' RETURN a.code FOR PERIOD 'FY2026-P01'..'FY2026-P03'",
    );
    let text = quoted.bind_period_range(-3, 7).statement(4);
    assert!(
        text.contains(
            ">= -3 AND __fa_period.period_end <= 7 AND (a.name = '__fa_period_range_start__')"
        ),
        "{text}"
    );
    assert_eq!(quoted.bound_period_range(&text, 4), Some((-3, 7)));
    let (_, single) = native("MATCH (l:Leg) RETURN COUNT(*) AS legs FOR PERIOD 'FY2026-P03'");
    assert!(!single.period_range());
    assert!(
        single
            .statement(1)
            .contains("__fa_period.code = 'FY2026-P03'")
    );
    assert_eq!(single.bound_period_range(&single.statement(1), 1), None);
    assert_eq!(single.bind_period_range(1, 2), single);
    for (text, says) in [
        (
            "MATCH (l:Leg) RETURN COUNT(*) AS legs FOR PERIOD 'FY2026-P01'..",
            "names its last period",
        ),
        (
            "MATCH (l:Leg) RETURN COUNT(*) AS legs FOR PERIOD 'FY2026-P01'..'FY2026-P01'",
            "range of one period",
        ),
        (
            "MATCH (l:Leg) RETURN COUNT(*) AS legs FOR PERIOD 'FY2026-P01'..'not a code'",
            "is not a period code",
        ),
        (
            "CALL fa.trial_balance FOR PERIOD 'FY2026-P01'..'FY2026-P03'",
            "not a period range",
        ),
        (
            "CALL fa.explain_balance('1000') FOR PERIOD 'FY2026-P01'..'FY2026-P03'",
            "not a period range",
        ),
        (
            "MATCH (l:Leg) RETURN COUNT(*) AS legs FOR PERIOD 'FY2026-P01'..'FY2026-P03' AS ORIGINALLY REPORTED",
            "not a period range",
        ),
    ] {
        let r = refused(text);
        assert!(r.message.contains(says), "{text}: {r:?}");
    }
}

/// A `//` comment ending the text before an inserted clause used to comment
/// out `FOR SYSTEM_TIME AS OF SEQ` and the line after it: the read ran at the
/// frontier over every account while reporting known-at 4. Comments are
/// blanked before the native statement is cut, so nothing they precede is lost.
#[test]
fn a_line_comment_never_swallows_an_inserted_clause() {
    let (p, n) = native(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) // cash only\nWHERE a.code = '1000'\nRETURN COUNT(*) AS legs AS KNOWN AT 4",
    );
    assert_eq!(p.known_at, KnownAt::Seq(4));
    let statement = n.statement(4);
    assert!(!statement.contains("//"), "{statement}");
    assert!(
        statement.starts_with(
            "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) FOR SYSTEM_TIME AS OF SEQ 4 WHERE a.code = '1000'"
        ),
        "{statement}"
    );
    assert!(
        statement.ends_with("RETURN COUNT(*) AS legs"),
        "{statement}"
    );
    // A block comment is blanked too; a statement without comments is unchanged.
    let (_, n) = native(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) /* cash */ WHERE a.code = '1000' RETURN COUNT(*) AS legs",
    );
    assert!(!n.statement(4).contains("cash"), "{}", n.statement(4));
}

/// The substrate reads a backtick-quoted name as the plain word, but the
/// profile's checks read names as words: `` l.`amount` `` ordered or took the
/// max across units, and `` (r:`RegisterState`) `` read the derived cache, past
/// the checks that refuse the same queries spelled plainly. A backtick name is
/// refused instead.
#[test]
fn a_backtick_quoted_name_is_refused_rather_than_read_unchecked() {
    for text in [
        "MATCH (l:Leg) RETURN l ORDER BY l.`amount` DESC LIMIT 10",
        "MATCH (l:Leg) RETURN MAX(l.`amount`) AS top",
        "MATCH (r:`RegisterState`) RETURN r",
    ] {
        let refusal = refused(text);
        assert!(
            format!("{refusal:?}").contains("backtick-quoted name"),
            "{text}: {refusal:?}"
        );
    }
    // A backtick inside a quoted string is just a character.
    native("MATCH (a:Account) WHERE a.code = 'a`b' RETURN a.code");
}
