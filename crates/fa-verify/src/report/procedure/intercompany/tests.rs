use super::*;
use super::super::{
    Certificate, VerifiedProcedureParameters, recompute_with_intercompany, replay_intercompany,
};
use crate::codec::{Reader, Writer};

fn registry() -> Registry {
    Registry {
        unit_scales: [(0, 2)].into(),
        unit_currencies: BTreeMap::new(),
        account_types: BTreeMap::new(),
        account_codes: BTreeMap::new(),
        account_roles: BTreeMap::new(),
        leg_parties: BTreeMap::new(),
        entry_facts: BTreeMap::new(),
        trace: None,
        open_items: None,
        policy_oid: [7; 32],
    }
}

fn declaration(key: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(1).count(1).bytes(key.as_bytes()).u16(1).u16(2);
    w.buf
}

fn posting(id: u128, day: i32, paired: bool) -> (Entry, Facts) {
    let accounts = if paired {
        vec![(10, true), (11, false), (20, true), (21, false)]
    } else {
        vec![(11, true), (10, false)]
    };
    let details = accounts.iter().enumerate().map(|(index, _)| LegDetails {
        base_amount: None,
        dimensions: if paired { vec![(1, if index < 2 { 100 } else { 200 })] } else { Vec::new() },
        settlements: Vec::new(),
    }).collect();
    let entry = Entry {
        identity: id,
        digest: [id as u8; 32],
        recorded_at: id as u64,
        effective: Some(day),
        class: 1,
        legs: vec![(0, 500); accounts.len()],
        leg_accounts: accounts,
        supersession: Vec::new(),
        settlements: Vec::new(),
        period: None,
        transition: None,
    };
    let facts = Facts {
        declaration: paired.then(|| declaration("pair-a")),
        details,
        period: "FY2026-P01".into(),
        period_declared: true,
    };
    (entry, facts)
}

fn reversal(id: u128, day: i32, target: &Entry, facts: &Facts) -> (Entry, Facts) {
    let mut entry = target.clone();
    entry.identity = id;
    entry.digest = [id as u8; 32];
    entry.recorded_at = id as u64;
    entry.effective = Some(day);
    entry.class = 4;
    entry.supersession = vec![(target.identity, target.digest, 1)];
    for (_, debit) in &mut entry.leg_accounts {
        *debit = !*debit;
    }
    (entry, facts.clone())
}

fn context(rows: &[(Entry, Facts)]) -> Context {
    Context {
        entries: rows.iter().map(|(entry, facts)| (entry.identity, facts.clone())).collect(),
    }
}

fn selected(entries: &[Entry], cutoff: Option<i32>) -> Vec<&Entry> {
    let live = liveness(entries, cutoff).unwrap();
    entries.iter().filter(|entry| {
        !entry.legs.is_empty() && !matches!(entry.class, 2 | 4)
            && live.get(&entry.identity).copied().unwrap_or(false)
    }).collect()
}

#[test]
fn declared_pairs_and_both_roles_form_one_positive_leg_population() {
    let row = posting(1, 10, true);
    let entries = vec![row.0.clone()];
    let ctx = context(&[row]);
    let mut definitions = registry();
    let (findings, visits, legs, comparisons) =
        replay(&entries, &selected(&entries, None), None, &definitions, &ctx).unwrap();
    assert!(findings.is_empty(), "declared pairs need no account-role guess");
    assert_eq!((visits, legs, comparisons), (1, 4, 8));

    definitions.account_roles = [
        (11, ["intercompany".into()].into()),
        (21, ["intercompany_activity".into()].into()),
    ].into();
    let (findings, visits, legs, comparisons) =
        replay(&entries, &selected(&entries, None), None, &definitions, &ctx).unwrap();
    assert_eq!((visits, legs, comparisons), (1, 4, 8));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, 4);
    assert_eq!(findings[0].population, 3, "covered role leg counts only once");
    assert_eq!(findings[0].statistic, VerifiedProcedureStatistic::IntercompanyUndeclared {
        account: 21, ordinal: 3, unit: 0, amount: 500, scale: 2,
        period: Some("FY2026-P01".into()),
    });
    assert_eq!(findings[0].narrative,
        "intercompany leg 3 in entry 00000000000000000000000000000001 on account 00000000000000000000000000000015 in period FY2026-P01 unit 0 has no declared reciprocal pair");
}

#[test]
fn unrelated_opposing_role_legs_cannot_cancel_or_truncate_full_width_amounts() {
    let (mut first, first_facts) = posting(1, 10, false);
    let (mut second, second_facts) = posting(2, 11, false);
    for (_, amount) in first.legs.iter_mut().chain(&mut second.legs) {
        *amount = i128::MAX;
    }
    for (_, debit) in &mut second.leg_accounts {
        *debit = !*debit;
    }
    let rows = vec![(first, first_facts), (second, second_facts)];
    let entries: Vec<_> = rows.iter().map(|(entry, _)| entry.clone()).collect();
    let ctx = context(&rows);
    let mut definitions = registry();
    assert!(replay(&entries, &selected(&entries, None), None, &definitions, &ctx).is_err());
    definitions.account_roles.insert(11, ["intercompany".into()].into());
    let (findings, visits, legs, comparisons) =
        replay(&entries, &selected(&entries, None), None, &definitions, &ctx).unwrap();
    assert_eq!((visits, legs, comparisons), (2, 4, 6));
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|finding| {
        finding.population == 2 && finding.statistic.value() == i128::MAX
            && finding.statistic.scale() == 2 && finding.severity == 4
    }));
    let cutoff = Some(10);
    let (findings, _, _, comparisons) =
        replay(&entries, &selected(&entries, cutoff), cutoff, &definitions, &ctx).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].population, 1);
    assert_eq!(comparisons, 4, "future rows remain in entry/leg work, not live scan work");
}

#[test]
fn cutoff_precedes_reversal_parity_and_full_history_stays_metered() {
    let first = posting(1, 10, true);
    let second = reversal(2, 20, &first.0, &first.1);
    let third = reversal(3, 30, &second.0, &second.1);
    let rows = vec![first, second, third];
    let entries: Vec<_> = rows.iter().map(|(entry, _)| entry.clone()).collect();
    let ctx = context(&rows);
    let definitions = registry();
    for (through, comparisons) in [(10, 24), (20, 20), (30, 24)] {
        let cutoff = Some(through);
        let (findings, visits, legs, work) =
            replay(&entries, &selected(&entries, cutoff), cutoff, &definitions, &ctx).unwrap();
        assert!(findings.is_empty());
        assert_eq!((visits, legs, work), (3, 12, comparisons));
    }
    assert!(replay(&entries, &selected(&entries, Some(9)), Some(9), &definitions, &ctx).is_err());
    // A fully reversed declared history remains a meaningful empty selection.
    let rows = &rows[..2];
    let entries: Vec<_> = rows.iter().map(|(entry, _)| entry.clone()).collect();
    assert!(replay(&entries, &selected(&entries, None), None, &definitions, &context(rows))
        .unwrap().0.is_empty());
}

#[test]
fn all_known_declarations_are_checked_even_when_future_or_reversed() {
    let first = posting(1, 10, true);
    let duplicate = posting(2, 40, true);
    let rows = vec![first.clone(), duplicate];
    let entries: Vec<_> = rows.iter().map(|(entry, _)| entry.clone()).collect();
    assert!(replay(&entries, &selected(&entries, Some(10)), Some(10), &registry(), &context(&rows)).is_err());

    let reversed = reversal(2, 20, &first.0, &first.1);
    let rows = vec![first, reversed];
    let entries: Vec<_> = rows.iter().map(|(entry, _)| entry.clone()).collect();
    let ctx = context(&rows);
    for mutation in 0..6 {
        let mut changed = ctx.clone();
        let facts = changed.entries.get_mut(&2).unwrap();
        match mutation {
            0 => facts.declaration = None,
            1 => facts.declaration = Some(declaration("different-key")),
            2 => facts.details[0].dimensions.push((12, 999)),
            3 => facts.details[0].base_amount = Some((0, 500)),
            4 => facts.details[0].dimensions[0].1 = 200,
            _ => facts.details[0].dimensions.push((1, 300)),
        }
        assert!(replay(&entries, &selected(&entries, Some(10)), Some(10), &registry(), &changed).is_err(),
            "future reversal mutation {mutation} must be refused");
    }
    for mutation in 0..4 {
        let mut changed = entries.clone();
        match mutation {
            0 => changed[1].legs[0].1 = -1,
            1 => changed[1].leg_accounts[0].1 = !changed[1].leg_accounts[0].1,
            2 => changed[1].supersession[0].1[0] ^= 1,
            _ => changed[1].recorded_at = 0,
        }
        assert!(replay(&changed, &[], Some(10), &registry(), &ctx).is_err());
    }
}

#[test]
fn malformed_counterlegs_keys_and_cycles_cannot_hide_behind_clean_coverage() {
    let base = posting(1, 10, true);
    for mutation in 0..5 {
        let mut row = base.clone();
        match mutation {
            0 => row.0.legs[0].1 = 501,
            1 => row.0.legs[0].0 = 99,
            2 => row.1.details[0].dimensions.clear(),
            3 => row.0.class = 2,
            _ => row.1.declaration.as_mut().unwrap().push(0),
        }
        let entries = vec![row.0.clone()];
        let ctx = context(&[row]);
        assert!(replay(&entries, &[], Some(-1), &registry(), &ctx).is_err());
    }
    let mut cycle = reversal(2, 20, &base.0, &base.1);
    cycle.0.recorded_at = 1;
    let mut first = base;
    first.0.class = 4;
    first.0.supersession = vec![(cycle.0.identity, cycle.0.digest, 1)];
    let rows = vec![first, cycle];
    let entries: Vec<_> = rows.iter().map(|(entry, _)| entry.clone()).collect();
    assert!(replay(&entries, &[], Some(-1), &registry(), &context(&rows)).is_err());
}

#[test]
fn original_ordinals_define_the_complete_native_citation_order_and_bytes() {
    let (mut entry, mut facts) = posting(1, 10, false);
    entry.legs = vec![(0, 7); 258];
    entry.leg_accounts = (0..258).map(|i| {
        (if i == 1 || i == 256 { 11 } else { 10 }, i % 2 == 0)
    }).collect();
    facts.details = vec![LegDetails {
        base_amount: None, dimensions: Vec::new(), settlements: Vec::new(),
    }; 258];
    let entries = vec![entry.clone()];
    let ctx = context(&[(entry, facts)]);
    let mut definitions = registry();
    definitions.account_roles.insert(11, ["intercompany".into()].into());
    let (verified, output) = recompute_with_intercompany(
        [1; 16], 1, 3, None, VerifiedProcedureParameters::IntercompanyCoverage,
        entries.clone(), &definitions, Some(&ctx),
    ).unwrap();
    assert_eq!((verified.live_entries, verified.live_legs, verified.comparisons), (1, 258, 259));
    let ordinals: Vec<_> = verified.findings.iter().map(|finding| match &finding.statistic {
        VerifiedProcedureStatistic::IntercompanyUndeclared { ordinal, .. } => *ordinal,
        _ => unreachable!(),
    }).collect();
    assert_eq!(ordinals, [256, 1], "canonical little-endian cite bytes, not numeric ordinals");
    let mut w = Writer::default();
    super::super::finding(&mut w, &verified.findings[0], VerifiedProcedureParameters::IntercompanyCoverage, 3).unwrap();
    let mut r = Reader::new(&w.buf);
    assert_eq!(r.bytes(128, "id").unwrap(), b"recon.intercompany");
    assert_eq!(r.u16("version").unwrap(), 3);
    assert_eq!(r.u8("severity").unwrap(), 4);
    assert_eq!(r.bytes(128, "statistic").unwrap(), b"intercompany_undeclared");
    assert_eq!(r.i128("amount").unwrap(), 7);
    assert_eq!(r.u8("scale").unwrap(), 2);
    assert_eq!(r.u64("population").unwrap(), 2);
    assert_eq!(r.u32("cites").unwrap(), 4);
    assert_eq!((r.u8("tag").unwrap(), r.u128("entry").unwrap()), (1, 1));
    assert_eq!((r.u8("tag").unwrap(), r.u128("entry").unwrap(), r.u16("ordinal").unwrap()), (2, 1, 256));
    assert_eq!((r.u8("tag").unwrap(), r.u128("account").unwrap()), (3, 11));
    assert_eq!(r.u8("tag").unwrap(), 4);
    assert_eq!(r.bytes(128, "period").unwrap(), b"FY2026-P01");
    assert_eq!(r.bytes(4096, "narrative").unwrap(), verified.findings[0].narrative.as_bytes());
    r.finish("finding").unwrap();
    let request = Certificate {
        source: &[], registry_digest: [0; 32], output: &output, digest: [0; 32],
        parameters: VerifiedProcedureParameters::IntercompanyCoverage,
        version: 3, book: [1; 16], known_at: 1, effective_through: None,
    };
    assert_eq!(replay_intercompany(&request, [1; 16], 1, entries.clone(), &definitions, &ctx)
        .unwrap().0, verified);
    let mut damaged = output.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    let forged = Certificate { output: &damaged, ..request };
    assert_eq!(replay_intercompany(&forged, [1; 16], 1, entries, &definitions, &ctx)
        .unwrap_err().predicate, "procedure_recomputation");
}
