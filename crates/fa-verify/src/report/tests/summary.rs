//! Independent summary fixtures. The journal, selectors, expected groups and
//! wire bytes are hand-authored; no producer or summary replay builds them.
use super::statements::{closure, registries};
use super::*;
use crate::report::summary as implementation;

fn declaration(w: &mut Writer, code: &str, name: &str, typ: u8, leaf: bool, parent: Option<&str>) {
    let policy: i64 = if code == "1090" {
        -1
    } else if code == "9999" {
        -2
    } else {
        1
    };
    w.bytes(code.as_bytes())
        .bytes(name.as_bytes())
        .u8(typ)
        .u8(u8::from(matches!(typ, 2..=4)))
        .u8(u8::from(leaf))
        .fixed(&policy.to_le_bytes())
        .u8(u8::from(parent.is_some()));
    if let Some(parent) = parent {
        w.bytes(parent.as_bytes());
    }
}

fn history() -> Vec<Record> {
    let mut chart = Writer::default();
    chart.count(9);
    // Child-first declarations deliberately differ from forest/output order.
    for (code, name, typ, leaf, parent) in [
        ("1000", "Cash", 1, true, Some("100")),
        ("1090", "Dormant", 1, true, Some("10")),
        ("100", "Cash branch", 1, false, Some("10")),
        ("10", "Assets", 1, false, None),
        ("3000", "Equity", 3, true, Some("30")),
        ("30", "Capital", 3, false, None),
        ("900", "Empty child", 6, false, Some("90")),
        ("90", "Empty root", 6, false, None),
        ("9999", "Uncovered", 1, true, None),
    ] {
        declaration(&mut chart, code, name, typ, leaf, parent);
    }
    chart
        .count(1)
        .bytes(b"1090")
        .u8(1)
        .i128(0)
        .u8(1)
        .i128(10_000)
        .count(1)
        .bytes(b"1090");
    let mut records = schema();
    records[0] = record(17, 1, 0, b"chart", 0, Some((1, &chart.buf)), None, None);
    records
}

fn displayed(code: &str) -> VerifiedReportAccount {
    let (name, typ, leaf) = match code {
        "10" => ("Assets", 1, false),
        "100" => ("Cash branch", 1, false),
        "1000" => ("Cash", 1, true),
        "1001" => ("New cash leaf", 1, true),
        "1090" => ("Dormant", 1, true),
        "30" => ("Capital", 3, false),
        "3000" => ("Equity", 3, true),
        "6000" => ("Memo", 6, true),
        "8000" => ("Statistical", 8, true),
        "90" => ("Empty root", 6, false),
        "900" => ("Empty child", 6, false),
        "9999" => ("Uncovered", 1, true),
        _ => panic!("unknown fixture account"),
    };
    VerifiedReportAccount {
        account: account_id(code),
        code: code.into(),
        name: name.into(),
        account_type: typ,
        normal_balance: u8::from(matches!(typ, 2..=4)),
        is_leaf: leaf,
        unit_policy: match code {
            "1090" => OpenItemUnitPolicy::AnyCurrency,
            "9999" => OpenItemUnitPolicy::AnyUnit,
            _ => OpenItemUnitPolicy::Single(1),
        },
        limit: (code == "1090").then_some(OpenItemBalanceLimit {
            lower: Some(0),
            upper: Some(10_000),
            period_scoped: true,
        }),
        created_at: 1,
    }
}

fn displayed_row(code: &str, unit: u32, values: [i128; 4]) -> ReportRow {
    let account = displayed(code);
    ReportRow {
        account: account.account,
        code: account.code,
        name: account.name,
        account_type: account.account_type,
        unit,
        debits: values[0],
        credits: values[1],
        debits_pending: values[2],
        credits_pending: values[3],
    }
}

fn selected(codes: &[&str]) -> SummaryScope {
    let mut ids: Vec<_> = codes.iter().map(|code| account_id(code)).collect();
    ids.sort_unstable();
    SummaryScope::Selected(ids)
}

fn expected(scope: SummaryScope, posted: i128, pending: i128) -> VerifiedSummaryTrialBalance {
    let roots = match &scope {
        SummaryScope::AllRoots => vec!["10", "30", "90", "9999"],
        SummaryScope::Selected(ids) => ["10", "100", "1000", "30", "3000", "90", "900", "9999"]
            .into_iter()
            .filter(|code| ids.contains(&account_id(code)))
            .collect(),
    };
    let mut covered = BTreeSet::new();
    let mut groups = Vec::new();
    let mut amounts = [0; 4];
    for root in roots {
        let (leaves, values) = match root {
            "10" => (vec!["1000", "1090"], [posted, 0, pending, 0]),
            "100" | "1000" => (vec!["1000"], [posted, 0, pending, 0]),
            "30" | "3000" => (vec!["3000"], [0, posted, 0, pending]),
            "9999" => (vec!["9999"], [0; 4]),
            "90" | "900" => (vec![], [0; 4]),
            _ => unreachable!(),
        };
        covered.extend(leaves.iter().copied());
        for (sum, value) in amounts.iter_mut().zip(values) {
            *sum += value;
        }
        groups.push(VerifiedSummaryGroup {
            account: displayed(root),
            leaves: leaves.into_iter().map(displayed).collect(),
            rows: if values == [0; 4] {
                vec![]
            } else {
                vec![displayed_row(root, 1, values)]
            },
        });
    }
    VerifiedSummaryTrialBalance {
        book_id: BOOK,
        known_at: 0,
        source_certificate_digest: [0; 32],
        scope,
        groups,
        uncovered_leaves: ["1000", "1090", "3000", "9999"]
            .into_iter()
            .filter(|code| !covered.contains(code))
            .map(displayed)
            .collect(),
        unit_totals: if amounts == [0; 4] {
            BTreeMap::new()
        } else {
            BTreeMap::from([(1, (amounts[0], amounts[1]))])
        },
        pending_unit_totals: if amounts == [0; 4] {
            BTreeMap::new()
        } else {
            BTreeMap::from([(1, (amounts[2], amounts[3]))])
        },
    }
}

fn write_account(w: &mut Writer, account: &VerifiedReportAccount) {
    w.u128(account.account)
        .bytes(account.code.as_bytes())
        .bytes(account.name.as_bytes())
        .u8(account.account_type)
        .u8(account.normal_balance)
        .u8(u8::from(account.is_leaf));
    match account.unit_policy {
        OpenItemUnitPolicy::Single(unit) => {
            w.u8(0).u32(unit);
        }
        OpenItemUnitPolicy::AnyCurrency => {
            w.u8(1);
        }
        OpenItemUnitPolicy::AnyUnit => {
            w.u8(2);
        }
    }
    w.u8(u8::from(account.limit.is_some()));
    if let Some(limit) = &account.limit {
        for value in [limit.lower, limit.upper] {
            w.u8(u8::from(value.is_some()));
            if let Some(value) = value {
                w.i128(value);
            }
        }
        w.u8(u8::from(limit.period_scoped));
    }
    w.u64(account.created_at);
}

fn expected_bytes(expected: &VerifiedSummaryTrialBalance, native_output: &[u8]) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"fa:summary-trial-balance:v1")
        .fixed(&BOOK)
        .bytes(native_output)
        .count(expected.groups.len());
    for group in &expected.groups {
        write_account(&mut w, &group.account);
        w.count(group.leaves.len());
        for leaf in &group.leaves {
            write_account(&mut w, leaf);
        }
        w.count(group.rows.len());
        for row in &group.rows {
            w.u128(row.account)
                .bytes(row.code.as_bytes())
                .bytes(row.name.as_bytes())
                .u8(row.account_type)
                .u32(row.unit)
                .i128(row.debits)
                .i128(row.credits)
                .i128(row.debits_pending)
                .i128(row.credits_pending);
        }
    }
    w.count(expected.uncovered_leaves.len());
    for account in &expected.uncovered_leaves {
        write_account(&mut w, account);
    }
    for totals in [&expected.unit_totals, &expected.pending_unit_totals] {
        w.count(totals.len());
        for (unit, (debits, credits)) in totals {
            w.u32(*unit).i128(*debits).i128(*credits);
        }
    }
    w.buf
}

struct Fixture {
    source: Vec<u8>,
    rest: Vec<u8>,
    anchor: SignedCheckpoint,
}

fn fixture(records: &[Record], known_at: u64, selection: Selection, rows: &[ReportRow]) -> Fixture {
    let (base, anchor) = bundle(records, known_at, selection.clone(), &[]);
    let mut r = Reader::new(&base);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    let original_source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap();
    let original = certificate(original_source).unwrap();
    let source_header = original_source.len() - 32;
    let mut reader = Reader::new(&original_source[..source_header]);
    reader.fixed::<24>("format").unwrap();
    for _ in 0..3 {
        reader.bytes(64, "profile").unwrap();
    }
    reader.fixed::<16>("book").unwrap();
    reader.fixed::<16>("branch").unwrap();
    reader.u64("known_at").unwrap();
    let selector = reader.u8("selector").unwrap();
    if selector == 1 {
        reader.i32("day").unwrap();
    } else {
        let count = reader.count(65_536, 4, "periods").unwrap();
        for _ in 0..count {
            reader.bytes(128, "period").unwrap();
        }
    }
    let registry_offset = source_header - reader.remaining();
    let mut native = original_source[..registry_offset].to_vec();
    let docs = registries();
    native.extend_from_slice(&closure(&docs));
    // Reuse independently authenticated prefix coordinates, never report sums.
    let mut w = Writer { buf: native };
    w.fixed(&original.journal_root)
        .u64(original.leaves)
        .count(7);
    for _ in 0..7 {
        w.bytes(b"opaque native attestation");
    }
    let (periods, cutoff, activity) = match selection {
        Selection::AsOf(day) => (
            if day < 31 {
                vec!["P1".into()]
            } else {
                vec!["P1".into(), "P2".into()]
            },
            Some(day),
            false,
        ),
        Selection::Periods(periods) => {
            let cutoff = if periods.last().unwrap() == "P1" {
                30
            } else {
                58
            };
            (periods, Some(cutoff), false)
        }
        Selection::Activity(periods) => (periods, None, true),
        _ => unreachable!(),
    };
    let mut totals = BTreeMap::new();
    for row in rows.iter().filter(|row| row.account_type <= 5) {
        let sum = totals.entry(row.unit).or_insert([0i128; 4]);
        for (slot, value) in sum.iter_mut().zip([
            row.debits,
            row.credits,
            row.debits_pending,
            row.credits_pending,
        ]) {
            *slot += value;
        }
    }
    let output = output(&periods, known_at, cutoff, activity, rows, &totals);
    w.bytes(&output)
        .fixed(&hash_parts(b"fa:report-output:v1", &[&output]));
    let digest = hash_parts(CERTIFICATE_FORMAT, &[&w.buf]);
    w.fixed(&digest);
    let mut rest = Writer {
        buf: base[base.len() - r.remaining()..].to_vec(),
    };
    rest.count(docs.len());
    for (name, document) in docs {
        rest.bytes(name.as_bytes()).bytes(&document);
    }
    Fixture {
        source: w.buf,
        rest: rest.buf,
        anchor,
    }
}

fn outer(source: &[u8], scope: &SummaryScope, output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    w.bytes(b"fa:summary-certificate:v1").bytes(source);
    match scope {
        SummaryScope::AllRoots => {
            w.u8(0);
        }
        SummaryScope::Selected(roots) => {
            w.u8(1).count(roots.len());
            for root in roots {
                w.u128(*root);
            }
        }
    }
    w.bytes(output);
    let pin = hash_parts(
        b"fa:summary-certificate-digest:v1",
        &[&(w.buf.len() as u32).to_le_bytes(), &w.buf],
    );
    w.fixed(&pin);
    (w.buf, pin)
}

fn pack(fixture: &Fixture, certificate: &[u8], major: u16) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(REPORT_BUNDLE_FORMAT)
        .u16(major)
        .u16(0)
        .bytes(certificate)
        .fixed(&fixture.rest);
    w.buf
}

fn verify(
    fixture: &Fixture,
    expected: &VerifiedSummaryTrialBalance,
) -> Result<VerifiedReport, ReportError> {
    let source = certificate(&fixture.source).unwrap();
    let output = expected_bytes(expected, source.output);
    let (outer, pin) = outer(&fixture.source, &expected.scope, &output);
    verify_report_with(
        &pack(fixture, &outer, 2),
        &[],
        None,
        None,
        Some(&pin),
        |_, _| Ok(fixture.anchor.clone()),
    )
}

#[test]
fn summary_recomputes_nested_groups_complete_zero_leaf_coverage_and_empty_selections() {
    let mut records = history();
    records.push(record(1, 3, 10, b"post", 100, None, None, None));
    records.push(record(2, 4, 10, b"hold", 25, None, None, None));
    records.push(record(1, 5, 10, b"later-backdate", 999, None, None, None));
    let mut opened = Writer::default();
    declaration(&mut opened, "1001", "New cash leaf", 1, true, Some("100"));
    opened.u8(0).i32(0).u8(0);
    records.push(record(
        17,
        6,
        0,
        b"later-account",
        0,
        Some((2, &opened.buf)),
        None,
        None,
    ));
    let fixture = fixture(&records, 4, Selection::AsOf(20), &rows(100, 25));
    for scope in [
        SummaryScope::AllRoots,
        selected(&["10", "30"]),
        selected(&["1000"]),
        selected(&[]),
    ] {
        let mut expected = expected(scope, 100, 25);
        expected.known_at = 4;
        expected.source_certificate_digest = certificate(&fixture.source).unwrap().digest;
        let verified = verify(&fixture, &expected).unwrap();
        assert_eq!(
            verified.rows,
            rows(100, 25),
            "every summary retains its full source"
        );
        assert_eq!(verified.summary.as_ref(), Some(&expected));
        assert_eq!(verified.checked_records, 6);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        let summary = verified.summary.unwrap();
        assert_eq!(
            summary.is_complete(),
            summary.scope == SummaryScope::AllRoots
        );
        if summary.scope == selected(&["10", "30"]) {
            assert_eq!(summary.unit_totals[&1], (100, 100));
            assert_eq!(summary.uncovered_leaves, vec![displayed("9999")]);
        }
        if let Some(empty) = summary.groups.iter().find(|g| g.account.code == "90") {
            assert!(empty.leaves.is_empty() && empty.rows.is_empty());
        }
    }
}

#[test]
fn summary_uses_native_stock_activity_cutoff_and_pending_resolution_laws() {
    let mut records = history();
    records.push(record(1, 3, 10, b"early", 100, None, None, None));
    records.push(record(1, 4, 40, b"late", 200, None, None, None));
    records.push(record(2, 5, 10, b"hold", 25, None, None, None));
    let info =
        metadata::entry_info(&records[4].bytes[..records[4].len], &records[4].envelope).unwrap();
    let target = (info.identity, records[4].envelope.record_digest);
    records.push(record(3, 6, 50, b"void", 0, None, Some(target), None));
    for (at, selector, posted, pending, activity) in [
        (5, Selection::AsOf(20), 100, 25, false),
        (6, Selection::AsOf(20), 100, 0, false),
        (5, Selection::Periods(vec!["P2".into()]), 300, 25, false),
        (5, Selection::Activity(vec!["P2".into()]), 200, 0, true),
        (3, Selection::AsOf(58), 100, 0, false),
    ] {
        let fixture = fixture(&records, at, selector, &rows(posted, pending));
        let verified = verify(&fixture, &expected(selected(&["10"]), posted, pending)).unwrap();
        assert_eq!(verified.known_at, at);
        assert_eq!(verified.activity, activity);
        assert_eq!(verified.summary.unwrap().groups[0].rows[0].debits, posted);
    }
}

#[test]
fn summary_attributes_promoted_source_balances_without_inventing_posting_leaves() {
    let mut records = history();
    records.push(record(1, 3, 10, b"post", 100, None, None, None));
    let mut promote = Writer::default();
    promote.bytes(b"1000").i32(20);
    records.push(record(
        17,
        4,
        20,
        b"promote",
        0,
        Some((4, &promote.buf)),
        None,
        None,
    ));
    let mut opened = Writer::default();
    declaration(&mut opened, "1001", "New cash leaf", 1, true, Some("1000"));
    opened.u8(0).i32(20).u8(0);
    records.push(record(
        17,
        5,
        20,
        b"child",
        0,
        Some((2, &opened.buf)),
        None,
        None,
    ));
    let old = fixture(&records, 3, Selection::AsOf(30), &rows(100, 0));
    verify(&old, &expected(selected(&["10"]), 100, 0)).unwrap();
    let fixture = fixture(&records, 5, Selection::AsOf(30), &rows(100, 0));
    let mut leaf = displayed("1001");
    leaf.created_at = 5;
    for root in ["10", "1000"] {
        let mut expected = expected(selected(&[root]), 100, 0);
        expected.groups[0].leaves = if root == "10" {
            vec![leaf.clone(), displayed("1090")]
        } else {
            vec![leaf.clone()]
        };
        if root == "1000" {
            expected.groups[0].account.is_leaf = false;
            expected.groups[0].account.created_at = 4;
        }
        let verified = verify(&fixture, &expected).unwrap();
        let summary = verified.summary.unwrap();
        assert_eq!(summary.groups[0].rows[0].debits, 100);
        assert!(
            summary.groups[0]
                .leaves
                .iter()
                .all(|account| account.code != "1000")
        );
    }
    let mut child_only = expected(selected(&[]), 0, 0);
    child_only.scope = selected(&["1001"]);
    child_only.groups = vec![VerifiedSummaryGroup {
        account: leaf.clone(),
        leaves: vec![leaf],
        rows: vec![],
    }];
    child_only.uncovered_leaves = vec![displayed("1090"), displayed("3000"), displayed("9999")];
    assert!(
        verify(&fixture, &child_only)
            .unwrap()
            .summary
            .unwrap()
            .unit_totals
            .is_empty()
    );
}

#[test]
fn summary_rejects_resealed_false_amounts_metadata_membership_and_source_output() {
    let mut records = history();
    records.push(record(1, 3, 10, b"post", 100, None, None, None));
    let fixture = fixture(&records, 3, Selection::AsOf(20), &rows(100, 0));
    let correct = expected(selected(&["10", "30"]), 100, 0);
    for mutation in 0..6 {
        let mut forged = correct.clone();
        match mutation {
            0 => forged.groups[0].rows[0].debits += 1,
            1 => forged.groups[0].leaves[1].name.push_str(" forged"),
            2 => {
                forged.groups[0].leaves.pop();
            }
            3 => forged.uncovered_leaves.clear(),
            4 => {
                forged.unit_totals.insert(1, (99, 99));
            }
            5 => {
                forged.groups[0].leaves[1]
                    .limit
                    .as_mut()
                    .unwrap()
                    .period_scoped = false
            }
            _ => unreachable!(),
        }
        assert_eq!(
            verify(&fixture, &forged).unwrap_err().predicate,
            "report_recomputation"
        );
    }
    // A false native source is resealed too. The outer digest cannot bless it.
    let false_fixture = self::fixture(&records, 3, Selection::AsOf(20), &rows(99, 0));
    assert_eq!(
        verify(&false_fixture, &expected(selected(&["10", "30"]), 99, 0))
            .unwrap_err()
            .predicate,
        "report_recomputation"
    );
}

#[test]
fn summary_requires_major_two_and_recipient_binding_to_the_outer_selection() {
    let mut records = history();
    records.push(record(1, 3, 10, b"post", 100, None, None, None));
    let fixture = fixture(&records, 3, Selection::AsOf(20), &rows(100, 0));
    let source = certificate(&fixture.source).unwrap();
    let full = expected(SummaryScope::AllRoots, 100, 0);
    let partial = expected(selected(&["10", "30"]), 100, 0);
    let (full_cert, full_pin) = outer(
        &fixture.source,
        &full.scope,
        &expected_bytes(&full, source.output),
    );
    let (partial_cert, partial_pin) = outer(
        &fixture.source,
        &partial.scope,
        &expected_bytes(&partial, source.output),
    );
    assert_ne!(full_pin, partial_pin);
    for pin in [source.digest, full_pin] {
        let error = verify_report_with(
            &pack(&fixture, &partial_cert, 2),
            &[],
            None,
            None,
            Some(&pin),
            |_, _| Ok(fixture.anchor.clone()),
        )
        .unwrap_err();
        assert_eq!(error.predicate, "recipient_certificate");
    }
    assert_eq!(
        verify_report_with(
            &pack(&fixture, &full_cert, 2),
            &[],
            None,
            None,
            None,
            |_, _| Ok(fixture.anchor.clone())
        )
        .unwrap_err()
        .predicate,
        "report_input_authority"
    );
    assert_eq!(
        verify_report_with(
            &pack(&fixture, &full_cert, 1),
            &[],
            None,
            None,
            Some(&full_pin),
            |_, _| Ok(fixture.anchor.clone())
        )
        .unwrap_err()
        .predicate,
        "registry_closure"
    );
    assert_eq!(
        verify_report_with(
            &pack(&fixture, &full_cert, 2),
            &[],
            None,
            Some(b"invalid receipt"),
            Some(&full_pin),
            |_, _| Ok(fixture.anchor.clone())
        )
        .unwrap_err()
        .predicate,
        "production_receipt"
    );
    verify(&fixture, &partial).unwrap();
}

#[test]
fn summary_refuses_unknown_duplicate_unsorted_and_overlapping_even_empty_roots() {
    let records = history();
    let fixture = fixture(&records, 2, Selection::AsOf(20), &[]);
    for scope in [
        selected(&["10", "100"]),
        selected(&["90", "900"]),
        selected(&["absent"]),
    ] {
        let mut expected = expected(selected(&[]), 0, 0);
        expected.scope = scope;
        assert_eq!(
            verify(&fixture, &expected).unwrap_err().predicate,
            "summary_selection"
        );
    }
    for roots in [vec![5, 5], vec![6, 5]] {
        let (raw, _) = outer(
            &fixture.source,
            &SummaryScope::Selected(roots),
            b"fa:summary-trial-balance:v1",
        );
        assert_eq!(
            implementation::decode(&raw).unwrap_err().predicate,
            "summary_selection"
        );
    }
}

#[test]
fn summary_refuses_missing_parents_leaf_parents_and_cycles_even_outside_selection() {
    for declarations in [
        vec![("1000", true, Some("absent")), ("3000", true, None)],
        vec![("1000", true, Some("3000")), ("3000", true, None)],
        vec![("1000", false, Some("3000")), ("3000", false, Some("1000"))],
    ] {
        let mut chart = Writer::default();
        chart.count(declarations.len());
        for (code, leaf, parent) in declarations {
            declaration(&mut chart, code, code, 1, leaf, parent);
        }
        let mut records = schema();
        records[0] = record(17, 1, 0, b"bad-chart", 0, Some((1, &chart.buf)), None, None);
        let fixture = fixture(&records, 2, Selection::AsOf(20), &[]);
        assert_eq!(
            verify(&fixture, &expected(selected(&[]), 0, 0))
                .unwrap_err()
                .predicate,
            "summary_chart"
        );
    }
}

#[test]
fn summary_decoder_bounds_root_counts_and_refuses_every_truncation_and_trailing_bytes() {
    let records = history();
    let fixture = fixture(&records, 2, Selection::AsOf(20), &[]);
    let expected = expected(selected(&["10"]), 0, 0);
    let output = expected_bytes(&expected, certificate(&fixture.source).unwrap().output);
    let (valid, _) = outer(&fixture.source, &expected.scope, &output);
    for end in 0..valid.len() {
        assert!(implementation::decode(&valid[..end]).is_err());
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(
        implementation::decode(&trailing).unwrap_err().predicate,
        "canonical_encoding"
    );
    let mut altered = valid.clone();
    let selector_at = 4 + b"fa:summary-certificate:v1".len() + 4 + fixture.source.len();
    altered[selector_at] = 7;
    assert_eq!(
        implementation::decode(&altered).unwrap_err().predicate,
        "summary_selection"
    );
    let mut unbounded = valid.clone();
    unbounded[selector_at + 1..selector_at + 5].copy_from_slice(&65_537u32.to_le_bytes());
    assert_eq!(
        implementation::decode(&unbounded).unwrap_err().predicate,
        "canonical_encoding"
    );
    let last = valid.len() - 1;
    let mut tampered = valid;
    tampered[last] ^= 1;
    assert_eq!(
        implementation::decode(&tampered).unwrap_err().predicate,
        "certificate_digest"
    );
}

#[test]
fn summary_replays_deep_forests_without_recursive_or_repeated_ancestry_walks() {
    let codes: Vec<_> = (0..4096).map(|index| format!("node{index:04}")).collect();
    let mut chart = Writer::default();
    chart.count(codes.len());
    for (index, code) in codes.iter().enumerate() {
        declaration(
            &mut chart,
            code,
            code,
            1,
            index == codes.len() - 1,
            index.checked_sub(1).map(|parent| codes[parent].as_str()),
        );
    }
    let mut records = schema();
    records[0] = record(
        17,
        1,
        0,
        b"deep-chart",
        0,
        Some((1, &chart.buf)),
        None,
        None,
    );
    let fixture = fixture(&records, 2, Selection::AsOf(20), &[]);
    let account = |index: usize| VerifiedReportAccount {
        account: account_id(&codes[index]),
        code: codes[index].clone(),
        name: codes[index].clone(),
        account_type: 1,
        normal_balance: 0,
        is_leaf: index == codes.len() - 1,
        unit_policy: OpenItemUnitPolicy::Single(1),
        limit: None,
        created_at: 1,
    };
    let mut expected = expected(SummaryScope::AllRoots, 0, 0);
    expected.groups = vec![VerifiedSummaryGroup {
        account: account(0),
        leaves: vec![account(codes.len() - 1)],
        rows: vec![],
    }];
    let result = verify(&fixture, &expected).unwrap();
    assert!(result.summary.unwrap().is_complete());
    expected.scope = selected(&[&codes[0], &codes[codes.len() - 1]]);
    assert_eq!(
        verify(&fixture, &expected).unwrap_err().predicate,
        "summary_selection"
    );
}

#[test]
fn summary_refuses_instant_branch_functional_dimension_open_item_and_recursive_sources() {
    let records = history();
    let fixture = fixture(&records, 2, Selection::AsOf(20), &[]);
    let source = certificate(&fixture.source).unwrap();
    let expected = expected(SummaryScope::AllRoots, 0, 0);
    let output = expected_bytes(&expected, source.output);
    let mut sources = Vec::new();
    let (recursive, _) = outer(&fixture.source, &expected.scope, &output);
    sources.push(recursive);
    for (format, output_format, family) in [
        (CERTIFICATE_FORMAT.as_slice(), OUTPUT_FORMAT.as_slice(), 0),
        (
            INSTANT_CERTIFICATE_FORMAT.as_slice(),
            OUTPUT_FORMAT.as_slice(),
            1,
        ),
        (
            FUNCTIONAL_CERTIFICATE_FORMAT.as_slice(),
            b"fa:functional-trial-balance:v1".as_slice(),
            2,
        ),
        (
            DIMENSION_CERTIFICATE_FORMAT.as_slice(),
            DIMENSION_OUTPUT_FORMAT,
            3,
        ),
        (
            OPEN_ITEMS_CERTIFICATE_FORMAT.as_slice(),
            b"fa:open-items:v1".as_slice(),
            4,
        ),
    ] {
        let mut w = Writer::default();
        w.fixed(format)
            .bytes(b"fa-fold-over-prefix")
            .bytes(b"embedded-owner")
            .bytes(output_format)
            .fixed(&BOOK)
            .fixed(&if family == 0 { [1; 16] } else { [0; 16] })
            .u64(2);
        match family {
            2 => {
                w.u8(8).u8(1).i32(20);
            }
            3 => {
                w.u8(6)
                    .u8(1)
                    .i32(20)
                    .bytes(b"department")
                    .bytes(b"operations");
            }
            4 => {
                w.u8(1).u8(0);
            }
            _ => {
                w.u8(1).i32(20);
            }
        }
        let inputs = if matches!(family, 2 | 3) { 8 } else { 7 };
        w.fixed(&source.registry_digest)
            .fixed(&source.journal_root)
            .u64(source.leaves)
            .count(inputs);
        for _ in 0..inputs {
            w.bytes(b"opaque attestation");
        }
        w.bytes(source.output).fixed(&source.output_digest);
        if family == 1 {
            w.u64(0)
                .u64(2)
                .u64(2)
                .u64(2)
                .u64(0)
                .u8(0)
                .u8(0)
                .u8(0)
                .u128(0)
                .u8(0);
        } else if family >= 2 {
            w.u8(0);
        }
        let digest = hash_parts(format, &[&w.buf]);
        w.fixed(&digest);
        certificate(&w.buf).unwrap();
        sources.push(w.buf);
    }
    for source in sources {
        let (outer, pin) = outer(&source, &expected.scope, &output);
        let result = verify_report_with(
            &pack(&fixture, &outer, 2),
            &[],
            None,
            None,
            Some(&pin),
            |_, _| panic!("unsupported source must be refused before authentication"),
        );
        assert_eq!(result.unwrap_err().predicate, "supported_report");
    }
}

#[path = "summary_edge_cases.rs"]
mod edge_cases;
