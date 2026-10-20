//! Differential: the engine's read-scope judgment (`Book::read_scope`,
//! `ReadScope::admit_*`, fa-0x0) against the literal model in
//! `fa_reference::read_scope`, over generated scopes, reads and frontiers.
//! Every case must reach the same verdict, and a refusal must name the
//! same caveat (FA-REF-011, exit 7). Seeds are deterministic; set
//! `FA_READ_SCOPE_CASES` for a longer run.

use std::collections::BTreeSet;

use fa::{
    Book, BookKeys, Capability, Entropy, ReportSelection, StatementDefinition, StatementSelection,
    TrialBalanceSelection,
};
use fa_journal::BookSpec;
use fa_model::{Id128, account_vid};
use fa_money::UnitRegistry;
use fa_reference::read_scope::{self, Read, Scope};
use fa_statements::Basis;
use fa_time::{DateDay, FiscalCalendar};
use fgdb_types::{CommitSeq, VId};

const PRINCIPAL: VId = VId(1);

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn pick(rng: &mut u64, n: usize) -> usize {
    usize::try_from(splitmix64(rng) % n as u64).expect("small")
}

/// One to three codes drawn from `pool`, repeats allowed.
fn some_codes(rng: &mut u64, pool: &[String]) -> Vec<String> {
    (0..=pick(rng, 3).min(2))
        .map(|_| pool[pick(rng, pool.len())].clone())
        .collect()
}

/// The refusing caveat a refusal message names: "the capability's `x`
/// caveat does not admit ...".
fn caveat(message: &str) -> &str {
    message
        .split('`')
        .nth(1)
        .unwrap_or_else(|| panic!("no caveat named in {message:?}"))
}

#[test]
fn the_engine_judges_every_scoped_read_as_the_literal_model_does() {
    let cases: usize = std::env::var("FA_READ_SCOPE_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4000);
    let units = UnitRegistry::embedded().unwrap();
    let calendar = FiscalCalendar::monthly("cal-monthly", 1, 0).unwrap();
    let periods = calendar.periods_for_year(2026).unwrap();
    let book = Book::create_memory(
        BookKeys::for_development(7),
        BookSpec {
            book_id: Id128([7; 16]),
            name: "Read scope oracle".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar,
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(7),
    )
    .unwrap();
    let book_id = book.context().book_id;
    // A code the calendar does not have bounds nothing.
    let mut pool: Vec<String> = periods.iter().map(|p| p.code.clone()).collect();
    pool.push("FY2026-P99".into());
    let last_day = |code: &str| {
        periods
            .iter()
            .find(|p| p.code == code)
            .map(fa_time::PeriodDef::last_day)
    };
    let first = periods[0].start;
    let span = u64::try_from(periods[11].last_day().0 - first.0 + 40).unwrap();
    let mut rng = 0xFA00_0F0C_0000_0000_u64;
    let day =
        |rng: &mut u64| DateDay(first.0 - 20 + i32::try_from(splitmix64(rng) % span).unwrap());
    let (mut admitted, mut refused) = (0, 0);
    for case in 0..cases {
        let mut scope = Scope::default();
        let mut capability = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
        if pick(&mut rng, 2) == 0 {
            let held: BTreeSet<String> = some_codes(&mut rng, &pool).into_iter().collect();
            let codes: Vec<&str> = held.iter().map(String::as_str).collect();
            capability = capability.for_periods(&codes).unwrap();
            scope.periods = Some(held);
        }
        if pick(&mut rng, 2) == 0 {
            let bound = day(&mut rng);
            capability = capability.effective_through(bound);
            scope.effective_through = Some(bound);
        }
        if pick(&mut rng, 2) == 0 {
            let pin = 1 + splitmix64(&mut rng) % 12;
            capability = capability.known_at_most(CommitSeq(pin));
            scope.known_at_most = Some(pin);
        }
        let at = 1 + splitmix64(&mut rng) % 12;
        let (selection, read) = match pick(&mut rng, 6) {
            0 => {
                let codes = some_codes(&mut rng, &pool);
                (
                    TrialBalanceSelection::Periods(codes.clone()).into(),
                    Read::Stock(codes),
                )
            }
            1 => {
                let codes = some_codes(&mut rng, &pool);
                (
                    TrialBalanceSelection::Activity(codes.clone()).into(),
                    Read::Activity(codes),
                )
            }
            2 => {
                let as_of = day(&mut rng);
                (TrialBalanceSelection::AsOf(as_of).into(), Read::AsOf(as_of))
            }
            3 => {
                let period = pool[pick(&mut rng, pool.len())].clone();
                (
                    ReportSelection::ExplainBalance {
                        account: account_vid(book_id, "1000"),
                        period: period.clone(),
                    },
                    Read::Activity(vec![period]),
                )
            }
            4 => (
                ReportSelection::OpenItems { account: None },
                Read::WholeBook,
            ),
            _ => {
                let name = ["balance-sheet", "income-statement"][pick(&mut rng, 2)];
                let definition = StatementDefinition::embedded(name).unwrap();
                let current = vec![pool[pick(&mut rng, pool.len())].clone()];
                let comparative: Vec<String> = if pick(&mut rng, 2) == 0 {
                    Vec::new()
                } else {
                    vec![pool[pick(&mut rng, pool.len())].clone()]
                };
                let mut columns = current.clone();
                columns.extend(comparative.iter().cloned());
                let read = match definition.basis() {
                    Basis::Stock => Read::Stock(columns),
                    Basis::Activity => Read::Activity(columns),
                };
                (
                    StatementSelection {
                        definition,
                        periods: current,
                        comparative,
                    }
                    .into(),
                    read,
                )
            }
        };
        let expected = read_scope::judge(&scope, &read, at, last_day);
        let judged = book
            .read_scope(PRINCIPAL, &capability)
            .unwrap()
            .unwrap()
            .admit_report(&selection, Some(CommitSeq(at)))
            .unwrap();
        match (&judged, &expected) {
            (Ok(seq), Ok(())) => {
                assert_eq!(*seq, CommitSeq(at), "case {case}");
                admitted += 1;
            }
            (Err(refusal), Err(model)) => {
                assert_eq!(refusal.code, "FA-REF-011", "case {case}: {refusal:?}");
                assert_eq!(refusal.exit, 7, "case {case}: {refusal:?}");
                assert_eq!(
                    caveat(&refusal.message),
                    *model,
                    "case {case}: {scope:?} {read:?} at {at}: {}",
                    refusal.message
                );
                refused += 1;
            }
            _ => panic!(
                "case {case}: the engine says {judged:?}, the model {expected:?} for {scope:?} {read:?} at {at}"
            ),
        }
    }
    // Both verdicts occur often enough for the agreement to mean something.
    assert!(
        admitted * 10 >= cases && refused * 10 >= cases,
        "{admitted} admitted, {refused} refused of {cases}"
    );
}
