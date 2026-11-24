use super::super::{
    TraceContext, TraceEntryFacts, VerifiedProcedure, VerifiedProcedureParameters,
    recompute_version,
};
use super::*;
use crate::blake3::hash_parts;

struct Population {
    entries: Vec<Entry>,
    registry: Registry,
}

impl Population {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            registry: Registry {
                unit_scales: BTreeMap::from([(1, 2), (2, 0)]),
                unit_currencies: BTreeMap::new(),
                account_types: BTreeMap::from([(1, 1), (2, 3), (3, 5), (4, 1), (5, 2)]),
                account_codes: BTreeMap::new(),
                account_roles: BTreeMap::from([
                    (1, BTreeSet::from(["cash".into()])),
                    (4, BTreeSet::from(["investor_transfer".into()])),
                    (5, BTreeSet::from(["investor_capital".into()])),
                ]),
                leg_parties: BTreeMap::new(),
                entry_facts: BTreeMap::new(),
                trace: Some(TraceContext {
                    account_normal_balances: BTreeMap::new(),
                    entries: BTreeMap::new(),
                    investors: Some(Context {
                        codes: BTreeMap::from([
                            (10, "A".into()),
                            (20, "B".into()),
                            (30, "VENDOR".into()),
                        ]),
                        aliases: BTreeMap::from([(110, 10), (120, 20), (130, 30)]),
                        legs: BTreeMap::new(),
                    }),
                }),
                open_items: None,
                policy_oid: [7; 32],
            },
        }
    }

    // Each tuple supplies independently selected account, side, amount and
    // literal party dimensions; it is not a retained procedure result.
    fn add(&mut self, id: u128, day: i32, legs: &[(u128, bool, i128, &[u128])]) {
        self.entries.push(Entry {
            identity: id,
            digest: hash_parts(b"ponzi-test-entry", &[&id.to_le_bytes()]),
            recorded_at: id as u64,
            effective: Some(day),
            class: 1,
            legs: legs.iter().map(|leg| (1, leg.2)).collect(),
            leg_accounts: legs.iter().map(|leg| (leg.0, leg.1)).collect(),
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: None,
            transition: None,
        });
        let context = self.registry.trace.as_mut().unwrap();
        context.entries.insert(
            id,
            TraceEntryFacts {
                entities: vec![Vec::new(); legs.len()],
                evidence: BTreeSet::new(),
            },
        );
        context
            .investors
            .as_mut()
            .unwrap()
            .legs
            .insert(id, legs.iter().map(|leg| leg.3.to_vec()).collect());
    }

    fn run(
        &self,
        through: Option<i32>,
        cohort: u32,
    ) -> Result<(VerifiedProcedure, Vec<u8>), ReportError> {
        recompute_version(
            [1; 16],
            100_000,
            5,
            through,
            VerifiedProcedureParameters::PonziNetInvestment {
                cohort_window_days: cohort,
            },
            self.entries.clone(),
            &self.registry,
        )
    }

    fn reverse(&mut self, id: u128, day: i32, target: u128) {
        let mut reversal = self
            .entries
            .iter()
            .find(|entry| entry.identity == target)
            .unwrap()
            .clone();
        let digest = reversal.digest;
        reversal.identity = id;
        reversal.digest = hash_parts(b"ponzi-test-entry", &[&id.to_le_bytes()]);
        reversal.recorded_at = id as u64;
        reversal.effective = Some(day);
        reversal.class = 4;
        reversal.supersession = vec![(target, digest, 1)];
        for (_, debit) in &mut reversal.leg_accounts {
            *debit = !*debit;
        }
        self.entries.push(reversal);
    }
}

fn principal(report: &VerifiedProcedure, who: u128) -> (&VerifiedProcedureFinding, i128, bool) {
    report
        .findings
        .iter()
        .find_map(|finding| {
            if let VerifiedProcedureStatistic::InvestorPrincipal {
                party,
                amount,
                net_winner,
                ..
            } = finding.statistic
            {
                (party == who).then_some((finding, amount, net_winner))
            } else {
                None
            }
        })
        .unwrap()
}

#[test]
fn ponzi_posted_transfers_and_external_payouts_reconstruct_exact_principal() {
    let mut p = Population::new();
    p.add(1, 0, &[(1, true, 100, &[]), (2, false, 100, &[110])]);
    p.add(2, 5, &[(2, true, 40, &[10]), (2, false, 40, &[120])]);
    p.add(3, 6, &[(2, true, 10, &[20]), (4, false, 10, &[])]);
    p.add(4, 7, &[(4, true, 10, &[]), (5, false, 10, &[10])]);
    p.add(5, 8, &[(1, false, 110, &[10]), (3, true, 110, &[])]);
    p.add(6, 9, &[(1, true, 7, &[]), (3, false, 7, &[130])]);
    p.add(7, 10, &[(2, true, 5, &[10]), (3, false, 5, &[])]);
    let (report, bytes) = p.run(None, 5).unwrap();
    assert_eq!(
        report.findings.len(),
        2,
        "a vendor refund never establishes an investor"
    );
    assert_eq!(
        (report.live_entries, report.live_legs, report.comparisons),
        (7, 14, 10)
    );
    let (a, amount, winner) = principal(&report, 10);
    assert_eq!((amount, winner, a.severity, a.population), (40, true, 3, 7));
    assert_eq!(
        amount, 40,
        "an unmarked fee cannot imply a transfer of principal"
    );
    assert_eq!(
        a.narrative,
        "investor A (cohort 1, status=net_winner): cash_in=100, cash_out=110, transfer_in=10, transfer_out=40, fictitious_profit_clawback=40, principal_rule=posted_principal_transfer_v1, attribution=complete"
    );
    let (b, amount, winner) = principal(&report, 20);
    assert_eq!(
        (amount, winner, b.severity, b.population),
        (30, false, 2, 7)
    );
    assert!(
        b.narrative.contains("cohort 2"),
        "a transfer-in begins the recipient's cohort"
    );
    p.entries.reverse();
    assert_eq!(
        p.run(None, 5).unwrap().1,
        bytes,
        "input enumeration cannot change the canonical result"
    );
}

#[test]
fn ponzi_ambiguous_mixed_funding_is_disclosed_without_invented_allocation() {
    let mut p = Population::new();
    p.add(1, 0, &[(1, true, 100, &[]), (2, false, 100, &[10])]);
    p.add(
        2,
        1,
        &[
            (1, true, 50, &[]),
            (3, true, 100, &[]),
            (2, false, 100, &[10]),
            (2, false, 50, &[20]),
        ],
    );
    let (report, _) = p.run(None, 90).unwrap();
    assert_eq!(report.findings.len(), 2);
    let (a, amount, _) = principal(&report, 10);
    assert_eq!(amount, 100, "do not proportionally split unidentified cash");
    assert!(a.narrative.ends_with("attribution=incomplete"));
    let unresolved = report
        .findings
        .iter()
        .find(|finding| finding.statistic.name() == "unresolved_attribution")
        .unwrap();
    assert_eq!(unresolved.statistic.value(), 50);
    assert_eq!(
        unresolved.narrative,
        "unresolved attribution: 50 of cash in 1 entries is not accounted for by any one party's own legs (parties named: [A, B]); the net investment of each investor named is incomplete"
    );
    // Only A's own tagged receipt supports additional principal, up to its
    // counter-leg margin. The other party still receives nothing.
    p.registry
        .trace
        .as_mut()
        .unwrap()
        .investors
        .as_mut()
        .unwrap()
        .legs
        .get_mut(&2)
        .unwrap()[0] = vec![10, 110];
    let (identified, _) = p.run(None, 90).unwrap();
    assert_eq!(identified.findings.len(), 1);
    assert_eq!(principal(&identified, 10).1, 150);
    p.registry
        .trace
        .as_mut()
        .unwrap()
        .investors
        .as_mut()
        .unwrap()
        .legs
        .get_mut(&2)
        .unwrap()[0] = vec![10, 20];
    assert_eq!(
        p.run(None, 90).unwrap().0.findings,
        report.findings,
        "a leg naming different investors is ambiguous"
    );
}

#[test]
fn ponzi_cutoff_precedes_reversal_parity_and_handles_full_date_domain() {
    let mut p = Population::new();
    p.add(1, i32::MIN, &[(1, true, 100, &[]), (2, false, 100, &[10])]);
    p.add(
        2,
        i32::MAX - 2,
        &[(1, true, 10, &[]), (2, false, 10, &[20])],
    );
    p.reverse(3, i32::MAX - 1, 1);
    p.reverse(4, i32::MAX, 3);
    let before = p.run(Some(i32::MAX - 2), 1).unwrap().0;
    assert_eq!(principal(&before, 10).1, 100);
    assert!(
        principal(&before, 20)
            .0
            .narrative
            .contains("cohort 4294967294")
    );
    let undone = p.run(Some(i32::MAX - 1), 1).unwrap().0;
    assert_eq!(undone.findings.len(), 1);
    assert!(principal(&undone, 20).0.narrative.contains("cohort 1"));
    assert_eq!(
        p.run(Some(i32::MAX), 1).unwrap().0.findings,
        before.findings
    );
}

#[test]
fn ponzi_units_and_legal_entities_cannot_cross_fund_attribution() {
    let mut p = Population::new();
    p.add(1, 0, &[(1, true, 100, &[]), (2, false, 100, &[10])]);
    // A balanced entry globally, with cash and investor principal in different
    // legal entities, supplies no same-entity cash attribution.
    p.registry
        .trace
        .as_mut()
        .unwrap()
        .entries
        .get_mut(&1)
        .unwrap()
        .entities = vec![vec![1], vec![2]];
    assert!(
        p.run(None, 90).is_err(),
        "unbalanced cash-free principal partition must be refused"
    );
    p.registry
        .trace
        .as_mut()
        .unwrap()
        .entries
        .get_mut(&1)
        .unwrap()
        .entities = vec![vec![1], vec![1]];
    p.add(2, 1, &[(1, false, 200, &[]), (2, true, 200, &[10])]);
    for leg in &mut p.entries[1].legs {
        leg.0 = 2;
    }
    p.registry
        .trace
        .as_mut()
        .unwrap()
        .entries
        .get_mut(&2)
        .unwrap()
        .entities = vec![vec![2], vec![2]];
    let report = p.run(None, 90).unwrap().0;
    assert_eq!(report.findings.len(), 2);
    assert!(report.findings.iter().any(|f| matches!(
        f.statistic,
        VerifiedProcedureStatistic::InvestorPrincipal {
            unit: 1,
            amount: 100,
            scale: 2,
            net_winner: false,
            ..
        }
    )));
    assert!(report.findings.iter().any(|f| matches!(
        f.statistic,
        VerifiedProcedureStatistic::InvestorPrincipal {
            unit: 2,
            amount: 200,
            scale: 0,
            net_winner: true,
            ..
        }
    )));
    p.registry
        .trace
        .as_mut()
        .unwrap()
        .entries
        .get_mut(&2)
        .unwrap()
        .entities[0]
        .clear();
    assert_eq!(p.run(None, 90).unwrap_err().predicate, "procedure_profile");
}

#[test]
fn ponzi_refuses_mixed_transfers_incomplete_sources_and_exact_overflow() {
    let mut mixed = Population::new();
    mixed.add(
        1,
        0,
        &[
            (2, true, 100, &[10]),
            (2, false, 50, &[20]),
            (1, false, 50, &[]),
        ],
    );
    assert_eq!(
        mixed.run(None, 90).unwrap_err().predicate,
        "procedure_profile"
    );
    let mut marked = Population::new();
    marked.add(1, 0, &[(4, true, 100, &[10]), (2, false, 100, &[20])]);
    assert_eq!(
        marked.run(None, 90).unwrap_err().predicate,
        "procedure_profile",
        "marked clearing cannot conceal another party"
    );
    marked
        .registry
        .trace
        .as_mut()
        .unwrap()
        .investors
        .as_mut()
        .unwrap()
        .legs
        .get_mut(&1)
        .unwrap()[0]
        .clear();
    assert_eq!(principal(&marked.run(None, 90).unwrap().0, 20).1, 100);
    marked
        .registry
        .account_roles
        .get_mut(&4)
        .unwrap()
        .insert("cash".into());
    assert!(marked.run(None, 90).is_err());
    let mut overflow = Population::new();
    overflow.add(
        1,
        0,
        &[(1, true, i128::MAX, &[]), (2, false, i128::MAX, &[10])],
    );
    overflow.add(2, 1, &[(1, true, 1, &[]), (2, false, 1, &[10])]);
    assert_eq!(
        overflow.run(None, 90).unwrap_err().predicate,
        "procedure_arithmetic"
    );
    overflow.entries[0].legs[0].1 = i128::MIN;
    assert_eq!(
        overflow.run(None, 90).unwrap_err().predicate,
        "procedure_arithmetic"
    );
    let mut missing = Population::new();
    missing.add(1, 0, &[(1, true, 10, &[]), (2, false, 10, &[10])]);
    missing
        .registry
        .trace
        .as_mut()
        .unwrap()
        .investors
        .as_mut()
        .unwrap()
        .legs
        .clear();
    assert_eq!(
        missing.run(None, 90).unwrap_err().predicate,
        "procedure_profile"
    );
}

#[test]
fn ponzi_supporting_citation_limit_does_not_truncate_principal_or_work() {
    let mut p = Population::new();
    for id in 1..=4097 {
        p.add(id, 1, &[(1, true, 1, &[]), (2, false, 1, &[10])]);
    }
    let report = p.run(None, 90).unwrap().0;
    let (finding, amount, _) = principal(&report, 10);
    assert_eq!(
        (
            amount,
            finding.population,
            report.live_entries,
            report.live_legs,
            report.comparisons
        ),
        (4097, 4097, 4097, 8194, 4098)
    );
    let VerifiedProcedureStatistic::InvestorPrincipal {
        accounts, entries, ..
    } = &finding.statistic
    else {
        unreachable!()
    };
    assert_eq!(accounts, &[1, 2]);
    assert_eq!(entries.len(), MAX_CITES - 2);
    assert_eq!(entries.first(), Some(&1));
    assert_eq!(entries.last(), Some(&4094));
}
