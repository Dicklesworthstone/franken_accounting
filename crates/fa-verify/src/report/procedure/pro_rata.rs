//! Independent proportional tracing over the authenticated one-account stream.
//!
//! Withdrawals consume the two held pools under LargestRemainder: the source
//! pool is index zero and wins an exact remainder tie. A binary quotient and
//! remainder recurrence evaluates the full product without using the producer's
//! allocation library or imposing a narrower intermediate amount range.

use std::collections::BTreeSet;

use super::{
    Entry, MAX_CITES, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, libr, text,
};

pub(super) const DEFAULTS: [(&str, u32); 1] = [("intraday_order", 0)];

fn profile(message: &str) -> ReportError {
    failed("procedure_profile", message)
}

fn arithmetic() -> ReportError {
    failed(
        "procedure_arithmetic",
        "pro-rata tracing movement or balance exceeds exact i128 arithmetic",
    )
}

pub(super) fn decode(reader: &mut Reader<'_>) -> Result<VerifiedProcedureParameters, ReportError> {
    if reader.count(1, 20, "procedure.parameters")? != 1
        || text(reader, 64, "procedure.parameter")? != "intraday_order"
    {
        return Err(profile(
            "pro-rata tracing requires only the explicit intraday_order parameter",
        ));
    }
    let intraday_order = u32::try_from(reader.i128("procedure.parameter_value")?)
        .map_err(|_| profile("tracing order is outside its unsigned range"))?;
    if !matches!(intraday_order, 0 | 2 | 3) {
        return Err(profile("tracing supports intraday_order 0, 2 or 3"));
    }
    let [account, source] = libr::decode_inputs(reader)?;
    Ok(VerifiedProcedureParameters::TraceProRata {
        intraday_order,
        account,
        source,
    })
}

/// Divide `amount * weight` exactly into quotient and remainder. All inputs
/// are at most i128::MAX, `weight <= total`, and `amount <= total`. At each
/// bit, `quotient * total + remainder` equals the processed prefix times
/// weight. Splitting the doubling and addition keeps every remainder below
/// twice the divisor, which fits u128 even at the maximum signed amount.
fn weighted_division(amount: u128, weight: u128, total: u128) -> Option<(u128, u128)> {
    if total == 0 || total > i128::MAX as u128 || amount > total || weight > total {
        return None;
    }
    let mut quotient = 0u128;
    let mut remainder = 0u128;
    for bit in (0..128).rev() {
        quotient = quotient.checked_mul(2)?;
        remainder = remainder.checked_mul(2)?;
        if remainder >= total {
            remainder = remainder.checked_sub(total)?;
            quotient = quotient.checked_add(1)?;
        }
        if (amount >> bit) & 1 != 0 {
            remainder = remainder.checked_add(weight)?;
            if remainder >= total {
                remainder = remainder.checked_sub(total)?;
                quotient = quotient.checked_add(1)?;
            }
        }
    }
    Some((quotient, remainder))
}

fn withdrawal(tainted: i128, clean: i128, magnitude: i128) -> Result<(i128, i128), ReportError> {
    if tainted < 0 || clean < 0 || magnitude < 0 {
        return Err(arithmetic());
    }
    let pool = tainted.checked_add(clean).ok_or_else(arithmetic)?;
    let drawn = magnitude.min(pool);
    if drawn == 0 {
        return Ok((0, 0));
    }
    let total = pool as u128;
    let (mut share, remainder) =
        weighted_division(drawn as u128, tainted as u128, total).ok_or_else(arithmetic)?;
    // The two floor shares omit exactly one unit iff this remainder is
    // nonzero. The other remainder is then total - remainder; index zero
    // receives that unit when its remainder is greater or tied.
    if remainder != 0 && remainder >= total.checked_sub(remainder).ok_or_else(arithmetic)? {
        share = share.checked_add(1).ok_or_else(arithmetic)?;
    }
    let tainted_draw = i128::try_from(share).map_err(|_| arithmetic())?;
    let clean_draw = drawn.checked_sub(tainted_draw).ok_or_else(arithmetic)?;
    if tainted_draw > tainted || clean_draw > clean {
        return Err(arithmetic());
    }
    Ok((tainted_draw, clean_draw))
}

pub(super) fn replay(
    selection: VerifiedProcedureParameters,
    claim: Option<i32>,
    live: &[&Entry],
    registry: &Registry,
) -> Result<(VerifiedProcedureFinding, u64, u64), ReportError> {
    let VerifiedProcedureParameters::TraceProRata {
        intraday_order,
        account,
        source,
    } = selection
    else {
        return Err(profile("expected the pro-rata tracing profile"));
    };
    let claim = claim.ok_or_else(|| profile("tracing requires an effective claim date"))?;
    let stream = libr::stream(account, source, claim, intraday_order, live, registry)?;
    let mut opening = 0i128;
    for movement in &stream.movements[..stream.source_at] {
        opening = if movement.inflow {
            opening.checked_add(movement.magnitude)
        } else {
            opening.checked_sub(movement.magnitude)
        }
        .ok_or_else(arithmetic)?;
    }
    let deposit = stream.movements[stream.source_at].magnitude;
    let mut balance = opening.checked_add(deposit).ok_or_else(arithmetic)?;
    let mut traced = deposit.min(balance.max(0));
    let mut clean = opening.max(0);
    let mut lowest = balance;
    let mut lowest_entry = None;
    let mut carriers = BTreeSet::new();
    let mut carried = 0i128;
    for movement in &stream.movements[stream.source_at + 1..] {
        if movement.inflow {
            let before = balance.max(0);
            balance = balance
                .checked_add(movement.magnitude)
                .ok_or_else(arithmetic)?;
            let held = balance.max(0).checked_sub(before).ok_or_else(arithmetic)?;
            clean = clean.checked_add(held).ok_or_else(arithmetic)?;
            continue;
        }
        balance = balance
            .checked_sub(movement.magnitude)
            .ok_or_else(arithmetic)?;
        if balance < lowest {
            lowest = balance;
            lowest_entry = Some(movement.identity);
        }
        let (tainted_draw, clean_draw) = withdrawal(traced, clean, movement.magnitude)?;
        traced = traced.checked_sub(tainted_draw).ok_or_else(arithmetic)?;
        clean = clean.checked_sub(clean_draw).ok_or_else(arithmetic)?;
        if tainted_draw > 0 {
            carriers.insert(movement.identity);
            carried = carried.checked_add(tainted_draw).ok_or_else(arithmetic)?;
        }
    }
    let carrier_count = carriers.len();
    if let Some(identity) = lowest_entry {
        carriers.insert(identity);
    }
    let mut citations = vec![source];
    citations.extend(
        carriers
            .into_iter()
            .filter(|id| *id != source)
            .take(MAX_CITES - 2),
    );
    let scale = registry
        .unit_scales
        .get(&stream.unit)
        .copied()
        .ok_or_else(|| failed("procedure_units", "the traced source unit is unregistered"))?;
    let count = stream.movements.len() as u64;
    let source_date = crate::bundle::civil(stream.movements[stream.source_at].day);
    let claim_date = crate::bundle::civil(claim);
    let entity_text = stream.entity.map_or_else(
        || "implicit book entity".to_string(),
        |entity| format!("entity {entity:032x}"),
    );
    let finding = VerifiedProcedureFinding {
        entry: None,
        severity: 0,
        statistic: VerifiedProcedureStatistic::TracedAmount {
            account,
            unit: stream.unit,
            mantissa: traced,
            scale,
            entries: citations,
        },
        population: count,
        narrative: format!(
            "pro rata: {deposit} (mantissa) deposited {source_date}; {} later movement(s) through {claim_date}; lowest balance after the deposit {lowest}; {carrier_count} withdrawal(s) carried {carried} tainted; traced {traced}; {entity_text}",
            count - stream.source_at as u64 - 1,
        ),
    };
    Ok((finding, count - 1, stream.comparisons))
}

#[cfg(test)]
mod tests {
    use super::super::{
        TraceContext, TraceEntryFacts, decode as decode_certificate, framed_hash,
        recompute_version, replay as replay_certificate,
    };
    use super::*;
    use crate::blake3::hash_parts;
    use crate::codec::Writer;
    use std::collections::BTreeMap;

    fn selection(order: u32) -> VerifiedProcedureParameters {
        VerifiedProcedureParameters::TraceProRata {
            intraday_order: order,
            account: 7,
            source: 2,
        }
    }

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
                    account_types: BTreeMap::new(),
                    trace: Some(TraceContext {
                        account_normal_balances: BTreeMap::from([(7, 0), (99, 1)]),
                        entries: BTreeMap::new(),
                    }),
                    policy_oid: [7; 32],
                },
            }
        }

        fn add(&mut self, id: u128, day: i32, recorded: u64, amount: i128, inflow: bool) {
            self.entries.push(Entry {
                identity: id,
                digest: hash_parts(b"pro-rata-test-entry", &[&id.to_le_bytes()]),
                recorded_at: recorded,
                effective: Some(day),
                class: 1,
                legs: vec![(1, amount), (1, amount)],
                leg_accounts: vec![(7, inflow), (99, !inflow)],
                supersession: Vec::new(),
                settlements: Vec::new(),
                period: None,
                transition: None,
            });
            self.registry.trace.as_mut().unwrap().entries.insert(
                id,
                TraceEntryFacts {
                    entities: vec![Vec::new(), Vec::new()],
                    evidence: BTreeSet::new(),
                },
            );
        }

        fn run(&self, order: u32, claim: i32) -> (VerifiedProcedureFinding, u64, u64) {
            replay(
                selection(order),
                Some(claim),
                &self.entries.iter().collect::<Vec<_>>(),
                &self.registry,
            )
            .unwrap()
        }
    }

    fn amount(finding: &VerifiedProcedureFinding) -> i128 {
        finding.statistic.value()
    }

    fn citations(finding: &VerifiedProcedureFinding) -> &[u128] {
        let VerifiedProcedureStatistic::TracedAmount { entries, .. } = &finding.statistic else {
            panic!("pro-rata tracing amount expected");
        };
        entries
    }

    #[test]
    fn proportional_withdrawal_matches_exhaustive_small_largest_remainders() {
        for tainted in 0..=32i128 {
            for clean in 0..=32i128 {
                for magnitude in 0..=70i128 {
                    let pool = tainted + clean;
                    let drawn = magnitude.min(pool);
                    let (mut expected_tainted, mut expected_clean) = (0, 0);
                    if pool != 0 {
                        expected_tainted = drawn * tainted / pool;
                        expected_clean = drawn * clean / pool;
                        if expected_tainted + expected_clean < drawn {
                            if (drawn * tainted) % pool >= (drawn * clean) % pool {
                                expected_tainted += 1;
                            } else {
                                expected_clean += 1;
                            }
                        }
                    }
                    assert_eq!(
                        withdrawal(tainted, clean, magnitude).unwrap(),
                        (expected_tainted, expected_clean),
                        "tainted={tainted}, clean={clean}, magnitude={magnitude}"
                    );
                }
            }
        }
    }

    #[test]
    fn proportional_withdrawal_preserves_full_width_products_and_source_ties() {
        let max = i128::MAX;
        assert_eq!(withdrawal(max, 0, max).unwrap(), (max, 0));
        assert_eq!(withdrawal(0, max, max).unwrap(), (0, max));
        assert_eq!(
            withdrawal(max / 2, max - max / 2, max).unwrap(),
            (max / 2, max - max / 2)
        );
        assert_eq!(
            withdrawal(max / 2, max - max / 2, max - 1).unwrap(),
            (max / 2, max / 2)
        );
        assert_eq!(withdrawal(1, 1, 1).unwrap(), (1, 0));
        assert_eq!(withdrawal(1, 2, 1).unwrap(), (0, 1));
        assert_eq!(withdrawal(2, 1, 1).unwrap(), (1, 0));
        assert_eq!(
            weighted_division(max as u128, max as u128, max as u128),
            Some((max as u128, 0))
        );
        assert_eq!(weighted_division(10, 3, 7), None);
        assert_eq!(weighted_division(1, 1, 0), None);
        assert!(withdrawal(-1, 3, 1).is_err());
        assert!(withdrawal(1, -3, 1).is_err());
        assert!(withdrawal(1, 3, -1).is_err());
        assert!(withdrawal(max, 1, 1).is_err());
    }

    #[test]
    fn pro_rata_replays_exact_carriers_lowest_citations_and_work() {
        let mut population = Population::new();
        for (id, amount, inflow) in [
            (1, 60, true),
            (2, 40, true),
            (3, 25, false),
            (4, 20, true),
            (5, 15, false),
        ] {
            population.add(id, id as i32, id as u64, amount, inflow);
        }
        let (finding, work, comparisons) = population.run(0, 5);
        assert_eq!(amount(&finding), 25);
        assert_eq!(citations(&finding), [2, 3, 5]);
        assert_eq!((finding.population, work, comparisons), (5, 4, 10));
        assert_eq!(finding.statistic.scale(), 2);
        assert_eq!(
            finding.narrative,
            "pro rata: 40 (mantissa) deposited 1970-01-03; 3 later movement(s) through 1970-01-06; lowest balance after the deposit 75; 2 withdrawal(s) carried 15 tainted; traced 25; implicit book entity"
        );
        population.entries.reverse();
        assert_eq!(population.run(0, 5), (finding, work, comparisons));
    }

    #[test]
    fn pro_rata_intraday_laws_produce_different_exact_schedules() {
        let mut population = Population::new();
        population.add(1, 0, 1, 20, true);
        population.add(2, 1, 2, 100, true);
        population.add(3, 1, 3, 90, false);
        population.add(4, 1, 4, 70, true);
        assert_eq!(amount(&population.run(0, 1).0), 25);
        assert_eq!(amount(&population.run(2, 1).0), 30);
        assert_eq!(amount(&population.run(3, 1).0), 53);
        assert_eq!(citations(&population.run(2, 1).0), [2]);
    }

    #[test]
    fn pro_rata_overdrafts_and_later_deposits_never_replenish_source_money() {
        let mut population = Population::new();
        population.add(1, 0, 1, 100, false);
        population.add(2, 1, 2, 200, true);
        population.add(3, 2, 3, 120, false);
        population.add(4, 3, 4, 250, true);
        for facts in population
            .registry
            .trace
            .as_mut()
            .unwrap()
            .entries
            .values_mut()
        {
            facts.evidence.insert([1; 32]);
        }
        let result = population.run(0, 3).0;
        assert_eq!(amount(&result), 0);
        assert_eq!(citations(&result), [2, 3]);
        assert!(
            result
                .narrative
                .contains("lowest balance after the deposit -20")
        );
        assert!(
            result
                .narrative
                .contains("1 withdrawal(s) carried 100 tainted")
        );

        // The opening debt can be i128::MIN although no single leg can be.
        let mut minimum = Population::new();
        minimum.add(1, 0, 1, i128::MAX, false);
        minimum.add(5, 0, 2, 1, false);
        minimum.add(2, 1, 3, i128::MAX, true);
        minimum.add(3, 2, 4, i128::MAX, true);
        minimum.add(4, 3, 5, i128::MAX, false);
        assert_eq!(amount(&minimum.run(0, 3).0), 0);
    }

    #[test]
    fn pro_rata_replays_full_width_exposure_without_product_overflow() {
        let mut population = Population::new();
        let half = i128::MAX / 2;
        population.add(1, 0, 1, half + 1, true);
        population.add(2, 1, 2, half, true);
        population.add(3, 2, 3, i128::MAX - 1, false);
        let finding = population.run(0, 2).0;
        assert_eq!(amount(&finding), 0);
        assert!(
            finding
                .narrative
                .contains(&format!("carried {half} tainted"))
        );
    }

    #[test]
    fn pro_rata_refuses_missing_scope_metadata_and_unrepresented_claims() {
        let mut population = Population::new();
        population.add(2, 1, 1, 100, true);
        let live = population.entries.iter().collect::<Vec<_>>();
        assert!(replay(selection(0), None, &live, &population.registry).is_err());
        assert!(replay(selection(1), Some(1), &live, &population.registry).is_err());
        assert!(replay(selection(0), Some(0), &live, &population.registry).is_err());
        let context = population.registry.trace.take();
        assert!(replay(selection(0), Some(1), &live, &population.registry).is_err());
        population.registry.trace = context;
        population
            .registry
            .trace
            .as_mut()
            .unwrap()
            .entries
            .get_mut(&2)
            .unwrap()
            .entities[0] = vec![11, 22];
        assert!(replay(selection(0), Some(1), &live, &population.registry).is_err());
        population
            .registry
            .trace
            .as_mut()
            .unwrap()
            .entries
            .get_mut(&2)
            .unwrap()
            .entities[0]
            .clear();
        population.registry.unit_scales.clear();
        assert!(replay(selection(0), Some(1), &live, &population.registry).is_err());
    }

    #[test]
    fn pro_rata_decoder_requires_the_exact_law_and_canonical_handles() {
        fn parameters(order: i128, name: &str, account: &str) -> Vec<u8> {
            let mut w = Writer::default();
            w.u32(1);
            w.bytes(name.as_bytes());
            w.i128(order);
            w.u32(2);
            w.bytes(b"account");
            w.bytes(account.as_bytes());
            w.bytes(b"source");
            w.bytes(format!("{:032x}", 2).as_bytes());
            w.buf
        }
        let account = format!("{:032x}", 7);
        for order in [0, 2, 3] {
            assert_eq!(
                decode(&mut Reader::new(&parameters(
                    order,
                    "intraday_order",
                    &account
                )))
                .unwrap(),
                selection(order as u32)
            );
        }
        for order in [-1, 1, 4, i128::MAX] {
            assert!(
                decode(&mut Reader::new(&parameters(
                    order,
                    "intraday_order",
                    &account
                )))
                .is_err()
            );
        }
        assert!(decode(&mut Reader::new(&parameters(0, "replenishment", &account))).is_err());
        assert!(decode(&mut Reader::new(&parameters(0, "intraday_order", "7"))).is_err());
    }

    #[test]
    fn pro_rata_refuses_rehashed_false_amounts_and_missing_clean_money() {
        fn encoded(output: &[u8]) -> Vec<u8> {
            let mut certificate = Writer::default();
            certificate
                .bytes(super::super::FORMAT)
                .bytes(&[])
                .bytes(&[])
                .fixed(&[0; 32])
                .u128(1)
                .fixed(&[0; 32])
                .bytes(output);
            let digest = framed_hash(super::super::DIGEST_DOMAIN, &certificate.buf);
            certificate.fixed(&digest);
            certificate.buf
        }
        let mut population = Population::new();
        for (id, value, inflow) in [
            (1, 60, true),
            (2, 40, true),
            (3, 25, false),
            (4, 20, true),
            (5, 15, false),
        ] {
            population.add(id, id as i32, id as u64, value, inflow);
        }
        let (expected, output) = recompute_version(
            [1; 16],
            10,
            2,
            Some(5),
            selection(0),
            population.entries.clone(),
            &population.registry,
        )
        .unwrap();
        let original = encoded(&output);
        let request = decode_certificate(&original).unwrap();
        assert_eq!(
            replay_certificate(
                &request,
                [1; 16],
                10,
                population.entries.clone(),
                &population.registry,
            )
            .unwrap()
            .0,
            expected
        );

        let mut statistic_label = Writer::default();
        statistic_label.bytes(b"traced_mantissa");
        let offset = output
            .windows(statistic_label.buf.len())
            .position(|window| window == statistic_label.buf)
            .unwrap()
            + statistic_label.buf.len();
        let mut forged_output = output.clone();
        forged_output[offset..offset + 16].copy_from_slice(&26i128.to_le_bytes());
        let forged_bytes = encoded(&forged_output);
        let forged = decode_certificate(&forged_bytes).unwrap();
        assert_eq!(
            replay_certificate(
                &forged,
                [1; 16],
                10,
                population.entries.clone(),
                &population.registry,
            )
            .unwrap_err()
            .predicate,
            "procedure_recomputation"
        );

        // Clean deposits do not need finding citations, but remain part of
        // the authenticated pool and the full population commitment.
        assert!(!citations(&expected.findings[0]).contains(&4));
        let mut missing = population.entries.clone();
        missing.retain(|entry| entry.identity != 4);
        assert_eq!(
            replay_certificate(&request, [1; 16], 10, missing, &population.registry)
                .unwrap_err()
                .predicate,
            "procedure_recomputation"
        );
    }
}
