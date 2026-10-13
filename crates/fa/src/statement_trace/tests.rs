use super::*;
use fa_statements::{Account, AccountBalance, ColumnInput, StatementDefinition, StatementInput};

fn input(at: u64, sales: i128, expense: i128) -> StatementInput {
    let account = |id, code: &str, account_type| Account {
        id, code: code.into(), name: format!("{code} name"), account_type, is_leaf: true,
    };
    let balances = |unit_id, revenue, cost| vec![
        AccountBalance { account_id: 1, unit_id, debits: 100 + revenue - cost, credits: 0 },
        AccountBalance { account_id: 2, unit_id, debits: 0, credits: 100 },
        AccountBalance { account_id: 3, unit_id, debits: 0, credits: revenue },
        AccountBalance { account_id: 4, unit_id, debits: cost, credits: 0 },
    ];
    let mut current = balances(1, sales, expense);
    current.extend(balances(2, 0, 10));
    StatementInput {
        book_id: Id128([1; 16]), branch_id: Id128::TRUNK, known_at: at,
        accounts: vec![account(1, "cash", 1), account(2, "capital", 3),
            account(3, "sales", 4), account(4, "expense", 5)],
        units: vec![1, 2],
        columns: vec![
            ColumnInput { label: "current".into(), periods: vec!["FY2026-P03".into()],
                effective_from: None, effective_through: DateDay(100), balances: current },
            ColumnInput { label: "comparative".into(), periods: vec!["FY2025-P03".into()],
                effective_from: None, effective_through: DateDay(-265), balances: balances(1, 0, 0) },
        ],
    }
}

fn statement(input: &StatementInput) -> Statement {
    fa_statements::evaluate(&StatementDefinition::embedded("balance-sheet").unwrap(), input).unwrap()
}

fn link(seq: u64, id: u128) -> StatementEntryLink {
    StatementEntryLink {
        event: StatementEntryEvent::Recorded,
        entry_ref: EntryRef { vid: VId(id), entry_digest: [id as u8; 32] },
        class: EntryClass::ORIGINAL, recorded_at: CommitSeq(seq), posting_date: Some(DateDay(10)),
        principal: VId(7), references: Vec::new(), migration_run: None,
    }
}

#[test]
fn cancelling_publications_remain_visible_despite_a_zero_net_bridge() {
    let first = statement(&input(10, 20, 0));
    let mut builder = Builder::new(first, CommitSeq(13)).unwrap();
    builder.push(statement(&input(11, 35, 0)), vec![link(11, 1)]).unwrap();
    builder.push(statement(&input(12, 20, 0)), vec![link(12, 2)]).unwrap();
    builder.push(statement(&input(13, 20, 0)), Vec::new()).unwrap();
    let trace = builder.finish().unwrap();
    assert!(trace.summary().is_unchanged());
    assert!(trace.had_changes());
    assert_eq!(trace.publications().len(), 3);
    for (step, expected) in trace.publications().iter().zip([15, -15, 0]) {
        let actual = step.changes.iter().find(|row| row.code == "assets" && row.unit_id == 1)
            .map_or(vec![0, 0], |row| row.delta.clone());
        assert_eq!(actual, vec![expected, 0]);
        assert!(step.changes.iter().all(|row| row.unit_id == 1));
    }
    assert!(trace.publications()[2].is_unchanged());
    for pair in trace.publications().windows(2) {
        assert_eq!(pair[0].after_source_digest, pair[1].before_source_digest);
    }
    assert_eq!(trace.canonical_bytes().unwrap().len(), trace.encoded_len().unwrap());
}

#[test]
fn chart_only_changes_and_empty_publications_are_kept_in_the_chain() {
    let original = input(20, 10, 0);
    let mut changed = original.clone();
    changed.known_at = 21;
    changed.accounts.push(Account { id: 9, code: "zero".into(), name: "zero < & | \"".into(), account_type: 4, is_leaf: true });
    let mut builder = Builder::new(statement(&original), CommitSeq(22)).unwrap();
    builder.push(statement(&changed), Vec::new()).unwrap();
    changed.known_at = 22;
    builder.push(statement(&changed), Vec::new()).unwrap();
    let trace = builder.finish().unwrap();
    assert!(!trace.summary().amounts_changed());
    assert!(trace.had_changes());
    assert!(trace.publications()[0].changes.is_empty());
    assert_eq!(trace.publications()[0].mapping_changes[0].account_id, 9);
    assert!(trace.publications()[1].is_unchanged());
    assert_eq!(trace.canonical_bytes().unwrap().len(), trace.encoded_len().unwrap());
}

#[test]
fn skipped_duplicated_reordered_or_incomplete_frontiers_are_refused() {
    let first = statement(&input(10, 0, 0));
    for next in [9, 10, 12, 13] {
        let mut builder = Builder::new(first.clone(), CommitSeq(12)).unwrap();
        assert!(builder.push(statement(&input(next, 0, 0)), Vec::new()).is_err());
    }
    let builder = Builder::new(first.clone(), CommitSeq(11)).unwrap();
    assert!(builder.finish().is_err());
    assert!(Builder::new(first.clone(), CommitSeq(9)).is_err());
    assert!(Builder::new(first, CommitSeq(267)).is_err());
}

#[test]
fn entry_link_events_and_reference_sets_cannot_rewrite_creation_time() {
    let first = statement(&input(10, 0, 0));
    let next = statement(&input(11, 0, 0));
    let mut stale = link(10, 1);
    let mut activation = stale.clone();
    activation.event = StatementEntryEvent::BecameVisible;
    let mut repeated = link(11, 1);
    repeated.references = vec![repeated.entry_ref; 2];
    for links in [vec![stale.clone()], vec![activation.clone()], vec![link(11, 2), link(11, 1)],
        vec![link(11, 1), link(11, 1)], vec![repeated]] {
        let mut builder = Builder::new(first.clone(), CommitSeq(11)).unwrap();
        assert!(builder.push(next.clone(), links).is_err());
    }
    stale.event = StatementEntryEvent::BecameVisible;
    stale.class = EntryClass::MIGRATION;
    stale.migration_run = Some(VId(99));
    stale.references = vec![EntryRef { vid: VId(5), entry_digest: [5; 32] }];
    let mut builder = Builder::new(first, CommitSeq(11)).unwrap();
    builder.push(next, vec![stale]).unwrap();
    let trace = builder.finish().unwrap();
    assert_eq!(trace.publications()[0].entries[0].recorded_at, CommitSeq(10));
    assert_eq!(trace.publications()[0].recorded_at, CommitSeq(11));
    assert_eq!(trace.canonical_bytes().unwrap().len(), trace.encoded_len().unwrap());
}

#[test]
fn zero_length_at_max_sequence_and_exact_integers_above_float_range() {
    let empty = Builder::new(statement(&input(u64::MAX, 0, 0)), CommitSeq(u64::MAX)).unwrap().finish().unwrap();
    assert!(empty.publications().is_empty());
    assert!(!empty.had_changes());
    let exact = (1i128 << 100) + 7;
    let mut builder = Builder::new(statement(&input(10, 0, 0)), CommitSeq(11)).unwrap();
    builder.push(statement(&input(11, exact, 0)), Vec::new()).unwrap();
    let trace = builder.finish().unwrap();
    assert_eq!(trace.publications()[0].changes.iter().find(|line| line.code == "assets").unwrap().delta, vec![exact, 0]);
    assert!(trace.canonical_bytes().unwrap().windows(16).any(|bytes| bytes == exact.to_le_bytes()));
}

#[test]
fn changing_the_statement_question_is_refused_at_an_intermediate_frontier() {
    let first = statement(&input(10, 0, 0));
    let next = statement(&input(11, 0, 0));
    let mut foreign = next.clone(); foreign.book_id = Id128([2; 16]);
    let mut period = next.clone(); period.columns[0].periods = vec!["FY2026-P04".into()];
    let mut malformed = next; malformed.lines.pop();
    for changed in [foreign, period, malformed] {
        let mut builder = Builder::new(first.clone(), CommitSeq(11)).unwrap();
        assert!(builder.push(changed, Vec::new()).is_err());
    }
}

#[test]
fn output_size_accounting_matches_every_optional_link_field_and_bounds_overflow() {
    for date in [None, Some(DateDay(1))] {
        for run in [None, Some(VId(4))] {
            let mut entry = link(11, 1);
            entry.posting_date = date;
            entry.migration_run = run;
            entry.references = vec![EntryRef { vid: VId(2), entry_digest: [2; 32] }];
            let mut builder = Builder::new(statement(&input(10, 0, 0)), CommitSeq(11)).unwrap();
            builder.push(statement(&input(11, 0, 0)), vec![entry]).unwrap();
            let trace = builder.finish().unwrap();
            assert_eq!(trace.canonical_bytes().unwrap().len(), trace.encoded_len().unwrap());
        }
    }
    assert!(size([MAX_STATEMENT_TRACE_BYTES, 1]).is_err());
    assert!(size([usize::MAX, 1]).is_err());
}
