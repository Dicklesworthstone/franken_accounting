use super::*;

fn native(text: &str) -> (Profiled, Native) {
    let profiled = rewrite(text).map_err(|r| format!("{r:?}")).expect(text);
    let native = match &profiled.selection {
        Selection::Native(native) => Some(native.clone()),
        Selection::TrialBalance => None,
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
        ("MATCH (l:Leg) RETURN l FOR PERIOD 'A'..'B'", "range"),
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
        (
            "MATCH (l:Leg) EFFECTIVE AT '2026-01-01' RETURN l",
            "EFFECTIVE BETWEEN",
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
            "CALL stands alone",
        ),
        ("EXPLAIN MATCH (a:Account) RETURN a", "EXPLAIN takes"),
        (
            "MATCH (a:Account) EXPLAIN (CERTIFICATE) RETURN a",
            "leads the statement",
        ),
        (
            "MATCH (a:Account) RETURN a AS ORIGINALLY REPORTED",
            "restatement views",
        ),
        (
            "MATCH (a:Account) RETURN a AS REPORTED IN 'C:00'",
            "restatement views",
        ),
    ] {
        let r = refused(text);
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
