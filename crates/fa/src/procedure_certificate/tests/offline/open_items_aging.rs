//! A portable aging result must be rederived from complete source applications
//! at both historical coordinates, including payments undone after the cutoff.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn request(f: &Fixture, through: u8) -> ProcedureRequest {
    let mut request =
        ProcedureRequest::new("aging.open_items", catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request.effective_through = Some(day(through));
    request.parameters = request
        .parameters
        .set("bucket_1", 1)
        .unwrap()
        .set("bucket_2", 3)
        .unwrap()
        .set("bucket_3", 5)
        .unwrap();
    request
}

fn apply(f: &mut Fixture, source: VId, key: &[u8], date: u8, amount: i128) -> VId {
    let (entry, _) = f.book.read_entry(&f.cx(), source).unwrap().unwrap();
    let ordinal = entry
        .proposal
        .legs
        .iter()
        .position(|leg| leg.account_ref == f.id("1000") && leg.side == Side::Debit)
        .unwrap();
    let mut proposal = template(f, source, key, date);
    proposal.legs = vec![
        LegPayload::simple(Side::Credit, f.id("1000"), Amount::new(f.unit, amount)),
        LegPayload::simple(Side::Debit, f.id("1010"), Amount::new(f.unit, amount)),
    ];
    proposal.legs[0].settles.push(fa_model::Settlement {
        target: fa_model::EntryRef {
            vid: source,
            entry_digest: entry.entry_digest,
        },
        ordinal: u16::try_from(ordinal).unwrap(),
        amount: Amount::new(f.unit, amount),
    });
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    post(f, proposal)
}

#[test]
fn open_item_aging_exports_historical_applications_without_netting_sides() {
    let mut f = Fixture::new(251);
    let account = f.id("1000").0;
    let (source, _) = f.post(1, "3000", "1000", 10_000, false);
    f.post(2, "1000", "3000", 3_000, false);
    let early_payment = apply(&mut f, source, b"aging-first-application", 5, 4_000);
    let historical = f.certify(&request(&f, 10));
    let frontier = f.head();
    apply(&mut f, source, b"aging-future-application", 20, 2_000);
    reverse(&mut f, early_payment, b"aging-later-payment-reversal", 25);
    let same_day_later_knowledge = f.certify(&request(&f, 10));
    assert_eq!(
        historical.report.findings,
        same_day_later_knowledge.report.findings
    );
    let current = f.certify(&request(&f, 30));
    assert_ne!(historical.report.findings, current.report.findings);
    let key = f.book.checkpoint_public_key();
    let artifacts: Vec<_> = [historical, same_day_later_knowledge, current]
        .into_iter()
        .map(|certified| {
            certified.certificate.check_offline_profile().unwrap();
            let produced = produce(&mut f, &certified.certificate);
            (certified, produced)
        })
        .collect();
    drop(f);
    for (index, (certified, produced)) in artifacts.into_iter().enumerate() {
        let verified = verify(&produced, &certified.certificate, key);
        assert!(verified.checkpoint.checkpoint.through_seq > frontier.0);
        let procedure = verified.procedure.unwrap();
        assert_eq!(
            procedure.parameters,
            VerifiedProcedureParameters::OpenItemsAging { edges: [1, 3, 5] }
        );
        assert_eq!(procedure.live_entries, 0);
        assert_eq!(procedure.comparisons, 0);
        assert_eq!(procedure.live_legs, certified.report.work.legs);
        let mut sides = BTreeMap::new();
        for finding in procedure.findings {
            let VerifiedProcedureStatistic::AgedOpenAmount {
                account: found,
                debit,
                totals,
                ..
            } = finding.statistic
            else {
                panic!("aging finding");
            };
            if found == account {
                sides.insert(debit, totals);
            }
        }
        assert_eq!(
            sides.get(&true),
            Some(&[0, 0, 0, if index == 2 { 8_000 } else { 6_000 }])
        );
        assert_eq!(sides.get(&false), Some(&[0, 0, 0, 3_000]));
    }
}

#[test]
fn open_item_aging_exports_full_width_amounts_empty_results_and_exact_json() {
    let mut f = Fixture::new(252);
    let empty = f.certify(&request(&f, 10));
    assert!(empty.report.findings.is_empty());
    assert_eq!(empty.report.work, Work::default());
    let amount = i128::from(i64::MAX) + 1;
    f.post(1, "3000", "1000", amount, false);
    let certified = f.certify(&request(&f, 10));
    let empty_bundle = produce(&mut f, &empty.certificate);
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    drop(f);
    verify(&empty_bundle, &empty.certificate, key);
    let verified = verify(&produced, &certified.certificate, key);
    assert_eq!(verified.procedure.unwrap().findings.len(), 2);
    let result = fa_verify::cli::run(
        &[
            "report".into(),
            "aging.fab".into(),
            "--key".into(),
            key.iter().map(|byte| format!("{byte:02x}")).collect(),
            "--receipt".into(),
            "aging.receipt".into(),
            "--json".into(),
        ],
        &|path| match path {
            "aging.fab" => Ok(produced.bundle.bytes.clone()),
            "aging.receipt" => Ok(produced.receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unexpected input",
            )),
        },
    );
    assert_eq!(result.exit, 0, "{}", result.stdout);
    for expected in [
        "\"statistic\":\"open_past_5_days\"",
        "\"value\":\"9223372036854775808\"",
        "\"buckets\":[\"0\",\"0\",\"0\",\"9223372036854775808\"]",
        "\"side\":\"debit\"",
        "\"side\":\"credit\"",
    ] {
        assert!(
            result.stdout.contains(expected),
            "{expected}: {}",
            result.stdout
        );
    }
}

#[test]
fn open_item_aging_rejects_resealed_amounts_citations_cutoffs_and_work() {
    let mut f = Fixture::new(253);
    let (source, _) = f.post(1, "3000", "1000", 10_000, false);
    apply(&mut f, source, b"aging-attack-application", 5, 4_000);
    let certified = f.certify(&request(&f, 10));
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    for variant in [
        "amount",
        "population",
        "severity",
        "account",
        "ordinal",
        "narrative",
        "omitted",
        "work",
        "cutoff",
        "buckets",
    ] {
        let mut forged = certified.certificate.clone();
        let report = &mut forged.report;
        match variant {
            "amount" => report.findings[0].statistic.value += 1,
            "population" => report.findings[0].statistic.population += 1,
            "severity" => report.findings[0].severity = Severity::Info,
            "account" => report.findings[0].cites[0] = Cite::Account(f.id("1010")),
            "ordinal" => {
                let Cite::Leg { ordinal, .. } = &mut report.findings[0].cites[1] else {
                    panic!("oldest leg");
                };
                *ordinal += 1;
            }
            "narrative" => report.findings[0].narrative.push_str(" altered"),
            "omitted" => {
                report.findings.pop();
            }
            "work" => report.work.legs += 1,
            "cutoff" => report.coordinate.effective_through = Some(day(6)),
            "buckets" => report.parameters[2].1 = 8,
            _ => unreachable!(),
        }
        reseal(&mut forged);
        let bytes = replace_certificate(&produced.bundle.bytes, &forged);
        assert!(
            verify_report_expected(&bytes, &[key], None, None, Some(forged.digest())).is_err(),
            "resealed {variant}"
        );
    }
}
