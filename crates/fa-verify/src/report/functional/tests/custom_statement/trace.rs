//! Native and functional custom traces with a zero net change: an expense and
//! its later reversal must remain visible even though every rounded report and
//! the exact endpoints agree. Expected amounts and frames are constructed here,
//! independently of the replay and comparison evaluators.

use super::*;
use crate::report::{
    MAX_REPORT_BUNDLE_BYTES, StatementLineChange, VerifiedStatementEntryEvent,
    VerifiedStatementEntryLink, VerifiedStatementPublication,
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

fn reversal_identity(target: u128) -> u128 {
    // Reversals have one identity per original target, independently of
    // the caller's idempotency key. This domain hashes the raw target bytes.
    let digest = hash_parts(b"fa:vid:reversal:v1", &[&target.to_le_bytes()]);
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
                    event: VerifiedStatementEntryEvent::Recorded,
                    entry: if class == 4 {
                        reversal_identity(identity(b"comparison-small-expense"))
                    } else {
                        identity(key)
                    },
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
                    migration_run: None,
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
    trace_output_with_summary(functional, &summary, publications)
}

fn trace_output_with_summary(
    functional: bool,
    summary: &[u8],
    publications: &[VerifiedStatementPublication],
) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(if functional {
        b"fa:functional-custom-statement-trace:v1"
    } else {
        b"fa:custom-statement-trace:v1"
    })
    .bytes(summary)
    .count(publications.len());
    for step in publications {
        w.u64(step.recorded_at)
            .fixed(&step.before_source_digest)
            .fixed(&step.after_source_digest)
            .count(step.entries.len());
        for entry in &step.entries {
            w.u8(match entry.event {
                VerifiedStatementEntryEvent::Recorded => 0,
                VerifiedStatementEntryEvent::BecameVisible => 1,
            })
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
            w.u8(u8::from(entry.migration_run.is_some()));
            if let Some(run) = entry.migration_run {
                w.u128(run);
            }
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
fn custom_migration_traces_retain_zero_effect_activation_in_native_and_functional_outputs() {
    use crate::report::functional::tests::migration as migration_fixture;

    let mut fixture = fixture();
    fixture.records.truncate(5);
    fixture.rates.truncate(1);
    let body = migration_fixture::body(0, false);
    let run = migration_fixture::run();
    fixture
        .records
        .push(migration_fixture::control(6, 0, run, &body));
    // Gross movement within one balance-sheet leaf has no custom income
    // effect. Its activation must still be disclosed, even with a zero delta.
    let legs = pair(2, 2)
        .into_iter()
        .map(|mut leg| {
            leg.code = "1000";
            leg.unit = 0;
            leg.base = None;
            leg
        })
        .collect::<Vec<_>>();
    fixture.records.push(entry_with_migration(
        7,
        12,
        10,
        b"custom-migrated-cash",
        &legs,
        None,
        None,
        None,
        Some(run),
    ));
    fixture
        .records
        .push(migration_fixture::control(8, 1, run, &body));
    let chunk_digest = framed_hash(
        b"fa:vid:migration-entry:v1",
        &[&BOOK, &run.to_le_bytes(), b"custom-migrated-cash"],
    );
    let chunk_id = u128::from_le_bytes(chunk_digest[..16].try_into().unwrap());

    for functional in [false, true] {
        let amounts = if functional { [14, 0, 14] } else { [9, 0, 9] };
        let outputs = (5..=8)
            .map(|at| output_with_amounts(functional, at, fixture.activation, amounts, 0))
            .collect::<Vec<_>>();
        let sources = outputs
            .iter()
            .enumerate()
            .map(|(index, output)| source(&fixture, functional, 5 + index as u64, output, 0))
            .collect::<Vec<_>>();
        let link = |at: u64, event| VerifiedStatementEntryLink {
            event,
            entry: if at == 7 {
                chunk_id
            } else {
                identity(&at.to_le_bytes())
            },
            digest: fixture.records[at as usize - 1].envelope.record_digest,
            class: if at == 7 { 12 } else { 22 },
            recorded_at: at,
            posting_date: (at == 7).then_some(10),
            principal: PRINCIPAL,
            references: Vec::new(),
            migration_run: Some(run),
        };
        let publications = outputs
            .windows(2)
            .enumerate()
            .map(|(index, adjacent)| {
                let at = 6 + index as u64;
                let mut entries = vec![link(at, VerifiedStatementEntryEvent::Recorded)];
                if at == 8 {
                    entries.push(link(7, VerifiedStatementEntryEvent::BecameVisible));
                }
                entries.sort_by_key(|entry| entry.entry);
                VerifiedStatementPublication {
                    recorded_at: at,
                    before_source_digest: trace_digest(functional, &adjacent[0].inner),
                    after_source_digest: trace_digest(functional, &adjacent[1].inner),
                    entries,
                    changes: Vec::new(),
                    mapping_changes: Vec::new(),
                }
            })
            .collect::<Vec<_>>();
        let summary = bridge_at(
            functional,
            (5, &outputs[0], amounts),
            (8, &outputs[3], amounts),
            false,
        );
        let expected = trace_output_with_summary(functional, &summary, &publications);
        let (certificate, pin) = trace_certificate(functional, &sources, &expected, false);
        let (raw, checkpoint) = bundle(&fixture, functional, &certificate, &fixture.rates, false);
        let add_body = |raw: &[u8]| {
            let mut r = Reader::new(raw);
            r.bytes(64, "format").unwrap();
            r.u16("major").unwrap();
            r.u16("minor").unwrap();
            for _ in 0..3 {
                r.bytes(MAX_REPORT_BUNDLE_BYTES, "frame").unwrap();
            }
            let count = r.count(100, 8, "records").unwrap();
            for _ in 0..count {
                r.u32("proposal length").unwrap();
                r.bytes(MAX_REPORT_BUNDLE_BYTES, "record").unwrap();
            }
            let offset = raw.len() - r.remaining();
            assert_eq!(r.count(100, 12, "bodies").unwrap(), 0);
            let mut w = Writer::default();
            w.fixed(&raw[..offset])
                .count(1)
                .u64(5)
                .bytes(&body)
                .fixed(&raw[raw.len() - r.remaining()..]);
            w.buf
        };
        let verified = verify(&add_body(&raw), &checkpoint, Some(&pin)).unwrap();
        assert_eq!(verified.output, expected);
        let trace = verified.statement_trace.unwrap();
        assert_eq!(trace.publications, publications);
        assert!(trace.summary.lines.iter().all(|line| line.delta == [0, 0]));
        assert_eq!(
            trace.summary.custom.unwrap().activation.activation,
            fixture.activation
        );
        assert!(verify(&raw, &checkpoint, Some(&pin)).is_err());

        let mut forged = publications;
        let visible = forged[2]
            .entries
            .iter_mut()
            .find(|entry| entry.event == VerifiedStatementEntryEvent::BecameVisible)
            .unwrap();
        visible.migration_run = Some(run ^ 1);
        let false_output = trace_output_with_summary(functional, &summary, &forged);
        let (certificate, pin) = trace_certificate(functional, &sources, &false_output, false);
        let (raw, checkpoint) = bundle(&fixture, functional, &certificate, &fixture.rates, false);
        assert!(verify(&add_body(&raw), &checkpoint, Some(&pin)).is_err());
    }
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
        for mutation in 0..12 {
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
                11 => changed[3].entries[0].entry = identity(b"trace-expense-reversal"),
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
