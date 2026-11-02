//! Native and functional custom traces with a zero net change: an expense and
//! its later reversal must remain visible even though every rounded report and
//! the exact endpoints agree. Expected amounts and frames are constructed here,
//! independently of the replay and comparison evaluators.

use super::*;
use crate::report::{
    StatementLineChange, VerifiedStatementEntryLink, VerifiedStatementPublication,
};

const TRACE_END: u64 = 9;

fn exact(functional: bool, at: u64) -> [i128; 3] {
    let expense_present = (7..TRACE_END).contains(&at);
    match (functional, expense_present) {
        (false, false) => [9, 0, 9],
        (false, true) => [9, 1, 8],
        (true, false) => [14, 0, 14],
        (true, true) => [14, 2, 12],
    }
}

fn trace_fixture() -> Fixture {
    let mut fixture = fixture();
    fixture.records.truncate(8);
    let expense = &fixture.records[6];
    let reversal = pair(1, 2)
        .into_iter()
        .enumerate()
        .map(|(index, mut leg)| {
            leg.code = if index == 0 { "5000" } else { "1000" };
            leg.debit = !leg.debit;
            leg
        })
        .collect::<Vec<_>>();
    fixture.records.push(entry(
        TRACE_END,
        4,
        41,
        b"trace-expense-reversal",
        &reversal,
        Some((3, &fixture.rates[1], None)),
        Some(expense),
        None,
    ));
    let later_sale = pair(1, 2)
        .into_iter()
        .enumerate()
        .map(|(index, mut leg)| {
            leg.code = if index == 0 { "1000" } else { "4000" };
            leg
        })
        .collect::<Vec<_>>();
    fixture.records.push(entry(
        10,
        1,
        40,
        b"trace-later-backdate",
        &later_sale,
        Some((3, &fixture.rates[1], None)),
        None,
        None,
    ));
    fixture
}

fn identity(key: &[u8]) -> u128 {
    let digest = framed_hash(b"fa:vid:entry:v1", &[&BOOK, &PRINCIPAL.to_le_bytes(), key]);
    u128::from_le_bytes(digest[..16].try_into().unwrap())
}

fn trace_digest(functional: bool, bytes: &[u8]) -> [u8; 32] {
    framed_hash(
        if functional {
            b"fa:functional-custom-statement-trace-source:v1"
        } else {
            b"fa:custom-statement-trace-source:v1"
        },
        &[bytes],
    )
}

fn sources(fixture: &Fixture, functional: bool, end: u64) -> (Vec<Output>, Vec<Vec<u8>>) {
    let outputs = (BEFORE..=end)
        .map(|at| output_with_amounts(functional, at, fixture.activation, exact(functional, at), 0))
        .collect::<Vec<_>>();
    let sources = outputs
        .iter()
        .enumerate()
        .map(|(offset, output)| source(fixture, functional, BEFORE + offset as u64, output, 0))
        .collect();
    (outputs, sources)
}

fn publications(
    fixture: &Fixture,
    functional: bool,
    outputs: &[Output],
) -> Vec<VerifiedStatementPublication> {
    outputs
        .windows(2)
        .enumerate()
        .map(|(offset, adjacent)| {
            let at = BEFORE + offset as u64 + 1;
            let (key, class, day) = match at {
                6 => (None, 0, None),
                7 => (Some(b"comparison-small-expense".as_slice()), 1, Some(41)),
                8 => (Some(b"comparison-new-layout".as_slice()), 18, None),
                9 => (Some(b"trace-expense-reversal".as_slice()), 4, Some(41)),
                _ => unreachable!(),
            };
            let entries = key
                .into_iter()
                .map(|key| VerifiedStatementEntryLink {
                    entry: identity(key),
                    digest: fixture
                        .records
                        .iter()
                        .find(|record| record.envelope.commit_seq == at)
                        .unwrap()
                        .envelope
                        .record_digest,
                    class,
                    recorded_at: at,
                    posting_date: day,
                    principal: PRINCIPAL,
                    references: if at == TRACE_END {
                        vec![(
                            identity(b"comparison-small-expense"),
                            fixture.records[6].envelope.record_digest,
                        )]
                    } else {
                        Vec::new()
                    },
                })
                .collect();
            let old = exact(functional, at - 1);
            let new = exact(functional, at);
            let changes = [
                ("revenue", "Revenue"),
                ("expense", "Expenses"),
                ("net", "Net income"),
            ]
            .into_iter()
            .enumerate()
            .filter(|(index, _)| old[*index] != new[*index])
            .map(|(index, (code, label))| StatementLineChange {
                code: code.into(),
                label: label.into(),
                unit: u32::from(!functional),
                before: vec![old[index], 0],
                after: vec![new[index], 0],
                delta: vec![new[index] - old[index], 0],
            })
            .collect();
            VerifiedStatementPublication {
                recorded_at: at,
                before_source_digest: trace_digest(functional, &adjacent[0].inner),
                after_source_digest: trace_digest(functional, &adjacent[1].inner),
                entries,
                changes,
                mapping_changes: Vec::new(),
            }
        })
        .collect()
}

fn trace_output(
    functional: bool,
    outputs: &[Output],
    publications: &[VerifiedStatementPublication],
) -> Vec<u8> {
    let end = BEFORE + outputs.len() as u64 - 1;
    let summary = bridge_at(
        functional,
        (BEFORE, &outputs[0], exact(functional, BEFORE)),
        (end, outputs.last().unwrap(), exact(functional, end)),
        false,
    );
    let mut w = Writer::default();
    w.bytes(if functional {
        b"fa:functional-custom-statement-trace:v1"
    } else {
        b"fa:custom-statement-trace:v1"
    })
    .bytes(&summary)
    .count(publications.len());
    for step in publications {
        w.u64(step.recorded_at)
            .fixed(&step.before_source_digest)
            .fixed(&step.after_source_digest)
            .count(step.entries.len());
        for entry in &step.entries {
            w.u8(0)
                .u64(entry.recorded_at)
                .u128(entry.entry)
                .fixed(&entry.digest)
                .u16(entry.class)
                .u8(u8::from(entry.posting_date.is_some()));
            if let Some(day) = entry.posting_date {
                w.i32(day);
            }
            w.u128(entry.principal).count(entry.references.len());
            for (identity, digest) in &entry.references {
                w.u128(*identity).fixed(digest);
            }
            w.u8(0);
        }
        w.count(step.changes.len());
        for line in &step.changes {
            w.bytes(line.code.as_bytes())
                .bytes(line.label.as_bytes())
                .u32(line.unit);
            for amounts in [&line.before, &line.after, &line.delta] {
                w.count(amounts.len());
                for amount in amounts {
                    w.i128(*amount);
                }
            }
        }
        assert!(step.mapping_changes.is_empty());
        w.count(0);
    }
    w.buf
}

fn trace_certificate(
    functional: bool,
    sources: &[Vec<u8>],
    output: &[u8],
    builtin: bool,
) -> (Vec<u8>, [u8; 32]) {
    let (format, domain): (&[u8], &[u8]) = match (functional, builtin) {
        (false, false) => (
            b"fa:custom-statement-trace-certificate:v1",
            b"fa:custom-statement-trace-certificate-digest:v1",
        ),
        (true, false) => (
            b"fa:functional-custom-statement-trace-certificate:v1",
            b"fa:functional-custom-statement-trace-certificate-digest:v1",
        ),
        (false, true) => (
            b"fa:statement-trace-certificate:v1",
            b"fa:statement-trace-certificate-digest:v1",
        ),
        (true, true) => (
            b"fa:functional-statement-trace-certificate:v1",
            b"fa:functional-statement-trace-certificate-digest:v1",
        ),
    };
    let mut w = Writer::default();
    w.bytes(format)
        .u128(PRINCIPAL)
        .fixed(&[8; 32])
        .count(sources.len());
    for source in sources {
        w.bytes(source);
    }
    w.bytes(output);
    let pin = framed_hash(domain, &[&w.buf]);
    w.fixed(&pin);
    (w.buf, pin)
}

fn check(
    fixture: &Fixture,
    functional: bool,
    sources: &[Vec<u8>],
    output: &[u8],
) -> Result<VerifiedReport, ReportError> {
    let (certificate, pin) = trace_certificate(functional, sources, output, false);
    let (bundle, checkpoint) = bundle(fixture, functional, &certificate, &fixture.rates, false);
    verify(&bundle, &checkpoint, Some(&pin))
}

#[test]
fn custom_trace_proves_offsetting_changes_and_original_layout_at_every_frontier() {
    let fixture = trace_fixture();
    for functional in [false, true] {
        let (outputs, sources) = sources(&fixture, functional, TRACE_END);
        let publications = publications(&fixture, functional, &outputs);
        let expected = trace_output(functional, &outputs, &publications);
        let verified = check(&fixture, functional, &sources, &expected).unwrap();
        assert_eq!(verified.output, expected);
        assert_eq!(verified.known_at, TRACE_END);
        assert_eq!(verified.checkpoint.checkpoint.through_seq, 10);
        assert!(verified.custom_statement.is_none());
        assert!(verified.statement_diff.is_none());
        let trace = verified.statement_trace.unwrap();
        assert_eq!(trace.publications, publications);
        assert_eq!(trace.publications.len(), 4);
        assert!(trace.publications[0].entries.is_empty());
        assert!(trace.publications[0].changes.is_empty());
        assert!(trace.publications[2].changes.is_empty());
        assert_eq!(trace.publications[2].entries[0].class, 18);
        assert_eq!(trace.summary.lines.len(), 3 * units(functional).len());
        assert!(trace.summary.lines.iter().all(|line| line.delta == [0, 0]));
        let amount = if functional { 2 } else { 1 };
        assert_eq!(trace.publications[1].changes[0].delta, [amount, 0]);
        assert_eq!(trace.publications[3].changes[0].delta, [-amount, 0]);
        assert_eq!(trace.publications[3].entries[0].references.len(), 1);
        let custom = trace.summary.custom.unwrap();
        assert_eq!(custom.activation.activation, fixture.activation);
        assert_eq!(custom.activation.activated_at, 3);
        assert!(!custom.activation.approval_admission_verified);
        assert!(!custom.activation.definition_birth_verified);
        for (old, new) in custom
            .before_presented
            .unwrap()
            .lines
            .iter()
            .zip(custom.after_presented.unwrap().lines)
        {
            assert_eq!(old.exact_amounts, new.exact_amounts);
            assert_eq!(old.presented_amounts, new.presented_amounts);
        }
    }
}

#[test]
fn custom_trace_allows_one_source_without_inventing_a_publication() {
    let fixture = trace_fixture();
    for functional in [false, true] {
        let (outputs, sources) = sources(&fixture, functional, BEFORE);
        let expected = trace_output(functional, &outputs, &[]);
        // A Rate imported only after this source is not part of its closure.
        let (certificate, pin) = trace_certificate(functional, &sources, &expected, false);
        let (bundle, checkpoint) = bundle(
            &fixture,
            functional,
            &certificate,
            &fixture.rates[..1],
            false,
        );
        let trace = verify(&bundle, &checkpoint, Some(&pin))
            .unwrap()
            .statement_trace
            .unwrap();
        assert!(trace.publications.is_empty());
        assert_eq!(trace.summary.before_known_at, BEFORE);
        assert_eq!(trace.summary.after_known_at, BEFORE);
        assert_eq!(trace.summary.before_digest, trace.summary.after_digest);
        assert!(trace.summary.custom.is_some());
    }
}

#[test]
fn resealed_custom_trace_cannot_hide_cancellation_zero_publications_or_lineage() {
    let fixture = trace_fixture();
    for functional in [false, true] {
        let (outputs, sources) = sources(&fixture, functional, TRACE_END);
        let publications = publications(&fixture, functional, &outputs);
        for mutation in 0..11 {
            let mut changed = publications.clone();
            match mutation {
                0 => {
                    changed.remove(0);
                }
                1 => {
                    changed[1].changes.clear();
                    changed[3].changes.clear();
                }
                2 => changed[1].changes[0].delta[0] = 0,
                3 => changed[3].entries[0].references.clear(),
                4 => changed[2].entries.clear(),
                5 => changed[1].entries[0].principal ^= 1,
                6 => changed[3].entries[0].references[0].1[0] ^= 1,
                7 => changed[0].after_source_digest = trace_digest(functional, &outputs[1].bytes),
                8 => {
                    changed[1].after_source_digest =
                        framed_hash(b"fa:custom-statement-diff-source:v1", &[&outputs[2].inner])
                }
                9 => changed.swap(0, 1),
                10 => changed.push(changed[0].clone()),
                _ => unreachable!(),
            }
            let error = check(
                &fixture,
                functional,
                &sources,
                &trace_output(functional, &outputs, &changed),
            )
            .unwrap_err();
            assert!(
                matches!(
                    error.predicate,
                    "statement_trace_recomputation" | "bounded_input"
                ),
                "functional={functional} mutation={mutation}: {error}"
            );
        }
    }
}

#[test]
fn custom_trace_requires_every_intermediate_exact_report_presentation_and_zero_mapping() {
    let fixture = trace_fixture();
    for functional in [false, true] {
        let (outputs, sources) = sources(&fixture, functional, TRACE_END);
        let expected = trace_output(
            functional,
            &outputs,
            &publications(&fixture, functional, &outputs),
        );
        for defect in 0..=3 {
            let at = 7;
            let values = if defect == 0 {
                exact(functional, BEFORE)
            } else {
                exact(functional, at)
            };
            let false_report =
                output_with_amounts(functional, at, fixture.activation, values, defect);
            let mut changed = sources.clone();
            changed[2] = source(&fixture, functional, at, &false_report, 0);
            let error = check(&fixture, functional, &changed, &expected).unwrap_err();
            assert_eq!(
                error.predicate, "custom_statement_recomputation",
                "functional={functional} defect={defect}: {error}"
            );
        }
        for mutation in 0..4 {
            let mut changed = sources.clone();
            match mutation {
                0 => {
                    changed.remove(1);
                }
                1 => changed.swap(1, 2),
                2 => changed.insert(1, changed[1].clone()),
                3 => {
                    changed.clear();
                }
                _ => unreachable!(),
            }
            assert!(
                check(&fixture, functional, &changed, &expected).is_err(),
                "functional={functional} source mutation={mutation}"
            );
        }
    }
}

#[test]
fn custom_trace_binds_full_selection_family_and_each_historical_registry_closure() {
    let fixture = trace_fixture();
    for functional in [false, true] {
        let (outputs, sources) = sources(&fixture, functional, TRACE_END);
        let expected = trace_output(
            functional,
            &outputs,
            &publications(&fixture, functional, &outputs),
        );
        for defect in 1..=6 {
            let mut changed = sources.clone();
            changed[2] = source(&fixture, functional, 7, &outputs[2], defect);
            assert!(
                check(&fixture, functional, &changed, &expected).is_err(),
                "functional={functional} selection defect={defect}"
            );
        }
        let (wrong_family, pin) = trace_certificate(functional, &sources, &expected, true);
        let (bytes, checkpoint) =
            bundle(&fixture, functional, &wrong_family, &fixture.rates, false);
        assert_eq!(
            verify(&bytes, &checkpoint, Some(&pin))
                .unwrap_err()
                .predicate,
            "supported_report"
        );
        let (certificate, pin) = trace_certificate(functional, &sources, &expected, false);
        let (bytes, checkpoint) = bundle(&fixture, functional, &certificate, &fixture.rates, true);
        assert!(verify(&bytes, &checkpoint, Some(&pin)).is_err());
        let (bytes, checkpoint) = bundle(&fixture, functional, &certificate, &fixture.rates, false);
        for source in &sources {
            let source_pin: [u8; 32] = source[source.len() - 32..].try_into().unwrap();
            assert!(verify(&bytes, &checkpoint, Some(&source_pin)).is_err());
        }
        if functional {
            for rates in [
                &fixture.rates[..1],
                &fixture.rates[1..],
                &fixture.rates[..0],
            ] {
                let (bytes, checkpoint) = bundle(&fixture, functional, &certificate, rates, false);
                assert!(verify(&bytes, &checkpoint, Some(&pin)).is_err());
            }
        }
    }
}
