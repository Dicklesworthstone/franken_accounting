//! Real journal authors, registered Canon output, and correction histories
//! must cross the standalone boundary without their source book. Repaired
//! hashes cannot substitute the producer's frequencies, lineage, or work.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

#[path = "jet/rules.rs"]
mod rules;

fn request(f: &Fixture, id: &str, parameters: &[(&str, i128)]) -> ProcedureRequest {
    let mut request = ProcedureRequest::new(id, catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    for &(name, value) in parameters {
        request.parameters = request.parameters.set(name, value).unwrap();
    }
    request
}

fn post_as(f: &mut Fixture, mut proposal: EntryPayload, principal: VId) -> VId {
    proposal.principal_ref = principal;
    let cx = f.cx();
    f.runtime
        .block_on(f.book.post(
            &cx,
            PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: Capability::embedded(principal, &["post"]).unwrap(),
            },
        ))
        .unwrap()
        .unwrap()
        .entry_ref()
        .vid
}

fn artifact(
    f: &mut Fixture,
    certified: CertifiedProcedure,
) -> (CertifiedProcedure, crate::ProducedBundle) {
    assert_eq!(
        certified.certificate.format(),
        EXTENDED_PROCEDURE_CERTIFICATE_FORMAT
    );
    assert_eq!(certified.certificate.supplemental_inputs().len(), 6);
    certified.certificate.check_offline_profile().unwrap();
    assert_eq!(
        f.book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certified.certificate)
            .unwrap()
            .unwrap(),
        certified.report
    );
    let produced = produce(f, &certified.certificate);
    (certified, produced)
}

fn check_cli(produced: &crate::ProducedBundle, key: [u8; 32], expected: &[&str]) {
    let command = fa_verify::cli::run(
        &[
            "report".into(),
            "jet.fab".into(),
            "--key".into(),
            key.iter().map(|byte| format!("{byte:02x}")).collect(),
            "--receipt".into(),
            "jet.receipt".into(),
            "--json".into(),
        ],
        &|path| match path {
            "jet.fab" => Ok(produced.bundle.bytes.clone()),
            "jet.receipt" => Ok(produced.receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unexpected input",
            )),
        },
    );
    assert_eq!(command.exit, 0, "{}", command.stdout);
    for expected in expected {
        assert!(
            command.stdout.contains(expected),
            "{expected}: {}",
            command.stdout
        );
    }
}

fn reject_resealed(f: &mut Fixture, certified: &CertifiedProcedure) {
    let produced = produce(f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    for variant in [
        "value",
        "population",
        "severity",
        "citation",
        "narrative",
        "omitted",
        "invented",
        "comparisons",
        "legs",
        "entries",
        "threshold",
    ] {
        let mut forged = certified.certificate.clone();
        let report = &mut forged.report;
        match variant {
            "value" => report.findings[0].statistic.value += 1,
            "population" => report.findings[0].statistic.population += 1,
            "severity" => report.findings[0].severity = Severity::Info,
            "citation" => report.findings[0].cites[1] = Cite::Account(f.id("1020")),
            "narrative" => report.findings[0].narrative.push_str(" changed"),
            "omitted" => {
                report.findings.pop();
            }
            "invented" => {
                report.findings.push(report.findings[0].clone());
            }
            "comparisons" => report.work.comparisons += 1,
            "legs" => report.work.legs += 1,
            "entries" => report.work.entries += 1,
            "threshold" => match report.procedure.as_str() {
                "jet.unusual_preparers" => report.parameters[0].1 = 0,
                "jet.manual_vs_rule" => report.parameters[1].1 = 10_000,
                "jet.large_round_reversals" => report.parameters[1].1 = 0,
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
        reseal(&mut forged);
        let changed = replace_certificate(&produced.bundle.bytes, &forged);
        assert_eq!(
            verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
                .unwrap_err()
                .predicate,
            "procedure_recomputation",
            "{}: {variant}",
            report_id(certified)
        );
    }
    for variant in [
        "version",
        "cutoff",
        "handle",
        "missing parameter",
        "negative",
        "overflow",
    ] {
        let mut forged = certified.certificate.clone();
        match variant {
            "version" => change_report_version(&mut forged, 2),
            "cutoff" => forged.report.coordinate.effective_through = Some(day(31)),
            "handle" => forged.report.inputs.push(("account".into(), "1000".into())),
            "missing parameter" => {
                forged.report.parameters.pop();
            }
            "negative" => forged.report.parameters[0].1 = -1,
            "overflow" => forged.report.parameters[1].1 = i128::from(u32::MAX) + 1,
            _ => unreachable!(),
        }
        assert_eq!(
            forged.check_offline_profile().unwrap_err().code,
            fa_notary::code::SCOPE_UNSUPPORTED,
            "{variant}"
        );
        reseal(&mut forged);
        let changed = replace_certificate(&produced.bundle.bytes, &forged);
        let error = verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
            .unwrap_err();
        assert!(
            matches!(error.predicate, "procedure_profile" | "canonical_encoding"),
            "{variant}: {error}"
        );
    }
    assert!(verify_report_expected(&produced.bundle.bytes, &[key], None, None, None).is_err());
    assert!(
        verify_report_expected(
            &produced.bundle.bytes,
            &[],
            None,
            None,
            Some(certified.certificate.digest())
        )
        .is_err()
    );
}

fn report_id(certified: &CertifiedProcedure) -> &str {
    &certified.report.procedure
}

#[test]
fn unusual_preparers_exports_author_frequency_split_legs_and_reversal_parity() {
    let mut f = Fixture::new(177);
    let (first, _) = f.post(2, "3000", "1000", 100, false);
    f.post(3, "3000", "1000", 100, false);
    let mut split = template(&f, first, b"jet-rare-author", 4);
    split.legs = vec![
        LegPayload::simple(Side::Debit, f.id("1000"), Amount::new(f.unit, 30)),
        LegPayload::simple(Side::Debit, f.id("1000"), Amount::new(f.unit, 70)),
        LegPayload::simple(Side::Credit, f.id("3000"), Amount::new(f.unit, 100)),
    ];
    split.unit_totals = EntryPayload::fold_unit_totals(&split.legs).unwrap();
    let rare = post_as(&mut f, split, VId(99));
    let account = f.id("1000").0.min(f.id("3000").0);
    let historical = f.certify(&request(&f, "jet.unusual_preparers", &[]));
    assert_eq!(historical.report.findings.len(), 1);
    assert_eq!(
        historical.report.findings[0].cites,
        [Cite::Entry(rare), Cite::Account(VId(account))]
    );
    assert_eq!(
        (
            historical.report.work.entries,
            historical.report.work.legs,
            historical.report.work.comparisons
        ),
        (3, 7, 3)
    );
    let undo_proposal = reversal(&f, rare, b"jet-rare-undo", 5);
    let undo = post_as(&mut f, undo_proposal, PRINCIPAL);
    let canceled = f.certify(&request(
        &f,
        "jet.unusual_preparers",
        &[("min_account_entries", 0)],
    ));
    assert!(canceled.report.findings.is_empty());
    reverse(&mut f, undo, b"jet-rare-restore", 6);
    let restored = f.certify(&request(&f, "jet.unusual_preparers", &[]));
    assert_eq!(restored.report.findings, historical.report.findings);
    let insufficient = f.certify(&request(
        &f,
        "jet.unusual_preparers",
        &[("min_account_entries", 4)],
    ));
    assert!(insufficient.report.findings.is_empty());
    reject_resealed(&mut f, &historical);
    let key = f.book.checkpoint_public_key();
    let artifacts: Vec<_> = [historical, canceled, restored, insufficient]
        .into_iter()
        .map(|certified| artifact(&mut f, certified))
        .collect();
    drop(f);
    for (certified, produced) in artifacts {
        let result = verify(&produced, &certified.certificate, key)
            .procedure
            .unwrap();
        assert_eq!(
            (result.live_entries, result.live_legs, result.comparisons),
            (
                certified.report.work.entries,
                certified.report.work.legs,
                certified.report.work.comparisons
            )
        );
        if let Some(finding) = result.findings.first() {
            assert_eq!(
                finding.statistic,
                VerifiedProcedureStatistic::PreparerAccountPostings { account, count: 1 }
            );
            assert_eq!(finding.population, 3);
            assert_eq!(finding.entry, Some(rare.0));
            check_cli(
                &produced,
                key,
                &[
                    "\"statistic\":\"preparer_account_postings\"",
                    "\"value\":1",
                    "\"account\"",
                ],
            );
        }
    }
}

#[test]
fn manual_vs_rule_exports_real_canon_populations_and_exact_share() {
    let mut f = Fixture::new(178);
    let (manual, _) = f.post(2, "3000", "1000", 100, false);
    let rule_entries = rules::post_rule_population(&mut f);
    assert_eq!(rule_entries.len(), 2);
    let historical = f.certify(&request(
        &f,
        "jet.manual_vs_rule",
        &[("min_rule_share_bps", 6666)],
    ));
    assert_eq!(historical.report.findings.len(), 1);
    assert_eq!(historical.report.findings[0].statistic.value, 6666);
    assert_eq!(historical.report.findings[0].statistic.population, 3);
    assert_eq!(
        (
            historical.report.work.entries,
            historical.report.work.legs,
            historical.report.work.comparisons
        ),
        (3, 6, 1)
    );
    let strict = f.certify(&request(
        &f,
        "jet.manual_vs_rule",
        &[("min_rule_share_bps", 6667)],
    ));
    assert!(strict.report.findings.is_empty());
    let mut undo = reversal(&f, rule_entries[0], b"rule-origin-undo", 5);
    undo.origin = template(&f, manual, b"origin-only", 5).origin;
    let undo = post(&mut f, undo);
    let canceled = f.certify(&request(
        &f,
        "jet.manual_vs_rule",
        &[("min_account_entries", 2)],
    ));
    assert!(canceled.report.findings.is_empty());
    reverse(&mut f, undo, b"rule-origin-restore", 6);
    let restored = f.certify(&request(
        &f,
        "jet.manual_vs_rule",
        &[("min_rule_share_bps", 6666)],
    ));
    assert_eq!(restored.report.findings, historical.report.findings);
    reject_resealed(&mut f, &historical);
    let key = f.book.checkpoint_public_key();
    let account = f.id("1000").0.min(f.id("3000").0);
    let artifacts: Vec<_> = [historical, strict, canceled, restored]
        .into_iter()
        .map(|certified| artifact(&mut f, certified))
        .collect();
    drop(f);
    for (certified, produced) in artifacts {
        let result = verify(&produced, &certified.certificate, key)
            .procedure
            .unwrap();
        assert_eq!(
            (result.live_entries, result.live_legs, result.comparisons),
            (
                certified.report.work.entries,
                certified.report.work.legs,
                certified.report.work.comparisons
            )
        );
        if let Some(finding) = result.findings.first() {
            assert_eq!(
                finding.statistic,
                VerifiedProcedureStatistic::RuleShare {
                    account,
                    basis_points: 6666
                }
            );
            assert_eq!(finding.entry, Some(manual.0));
            assert_eq!(
                result.parameters,
                VerifiedProcedureParameters::ManualVsRule {
                    min_account_entries: 3,
                    min_rule_share_bps: 6666
                }
            );
            check_cli(
                &produced,
                key,
                &[
                    "\"statistic\":\"rule_share_bps\"",
                    "\"value\":6666",
                    "\"account\"",
                    "approval admission, rule execution and policy activation are not established",
                ],
            );
        }
    }
}

#[test]
fn large_round_reversals_exports_full_history_scale_and_inclusive_windows() {
    let mut f = Fixture::new(179);
    let (large, _) = f.post(31, "3000", "1000", 100_000, false);
    let (small, _) = f.post(31, "3000", "1010", 1_000, false);
    post_closing_transition(
        &mut f,
        "FY2026-P02",
        PeriodTransition::Open,
        b"jet-open-february",
    );
    let mut undo = reversal(&f, large, b"jet-large-undo", 1);
    undo.effective_date = DateDay::from_ymd(2026, 2, 1).unwrap();
    let undone = post(&mut f, undo);
    let mut undo = reversal(&f, small, b"jet-small-undo", 1);
    undo.effective_date = DateDay::from_ymd(2026, 2, 1).unwrap();
    post(&mut f, undo);
    let historical = f.certify(&request(
        &f,
        "jet.large_round_reversals",
        &[("window_days", 28)],
    ));
    assert_eq!(historical.report.findings.len(), 1);
    assert_eq!(
        (
            historical.report.work.legs,
            historical.report.work.comparisons
        ),
        (4, 2)
    );
    post_closing_transition(
        &mut f,
        "FY2026-P03",
        PeriodTransition::Open,
        b"jet-open-march",
    );
    let mut restore = reversal(&f, undone, b"jet-large-restore", 1);
    restore.effective_date = DateDay::from_ymd(2026, 3, 1).unwrap();
    let restored_entry = post(&mut f, restore);
    let current = f.certify(&request(
        &f,
        "jet.large_round_reversals",
        &[("window_days", 28)],
    ));
    assert_eq!(current.report.findings.len(), 2);
    assert_eq!(
        (current.report.work.legs, current.report.work.comparisons),
        (6, 3)
    );
    let first_day = f.certify(&request(
        &f,
        "jet.large_round_reversals",
        &[("window_days", 1)],
    ));
    assert_eq!(first_day.report.findings.len(), 1);
    let none = f.certify(&request(
        &f,
        "jet.large_round_reversals",
        &[("window_days", 0)],
    ));
    assert!(none.report.findings.is_empty());
    reject_resealed(&mut f, &historical);
    let key = f.book.checkpoint_public_key();
    let artifacts: Vec<_> = [historical, current, first_day, none]
        .into_iter()
        .map(|certified| artifact(&mut f, certified))
        .collect();
    drop(f);
    for (certified, produced) in artifacts {
        let result = verify(&produced, &certified.certificate, key)
            .procedure
            .unwrap();
        assert_eq!(
            (result.live_entries, result.live_legs, result.comparisons),
            (
                certified.report.work.entries,
                certified.report.work.legs,
                certified.report.work.comparisons
            )
        );
        for finding in &result.findings {
            assert_eq!(finding.population, result.population);
            let VerifiedProcedureStatistic::DaysToReversal {
                original,
                reversal,
                days,
            } = finding.statistic
            else {
                panic!("round reversal statistic");
            };
            assert!(
                matches!((original, reversal, days), (o, r, 1) if o == large.0 && r == undone.0)
                    || matches!((original, reversal, days), (o, r, 28) if o == undone.0 && r == restored_entry.0)
            );
            assert_eq!(finding.entry, Some(original.min(reversal)));
        }
        if !result.findings.is_empty() {
            check_cli(
                &produced,
                key,
                &[
                    "\"statistic\":\"days_to_reversal\"",
                    "\"original_entry\"",
                    "\"reversal_entry\"",
                ],
            );
        }
    }
}
