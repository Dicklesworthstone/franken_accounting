//! Hand-calculated income statement: an expense changes profit, then a hold,
//! closing and two reversals leave period income unchanged. Every publication
//! and its exact lineage must nevertheless survive the portable proof.
use super::*;

#[path = "statement_trace/migration.rs"]
mod migration;

fn key_id(key: &[u8]) -> u128 {
    let mut parts = Writer::default();
    parts
        .bytes(&BOOK)
        .bytes(&PRINCIPAL.to_le_bytes())
        .bytes(key);
    let digest = hash_parts(b"fa:vid:entry:v1", &[&parts.buf]);
    u128::from_le_bytes(digest[..16].try_into().unwrap())
}
fn reversal_id(target: u128) -> u128 {
    let digest = hash_parts(b"fa:vid:reversal:v1", &[&target.to_le_bytes()]);
    u128::from_le_bytes(digest[..16].try_into().unwrap())
}
fn commitment(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    hash_parts(domain, &[&(bytes.len() as u32).to_le_bytes(), bytes])
}

fn comparison(
    before: VerifiedStatement,
    after: VerifiedStatement,
    start: u64,
    end: u64,
) -> VerifiedStatementDiff {
    let definition = definition(true);
    let before_bytes = output_bytes(&before, &definition, start);
    let after_bytes = output_bytes(&after, &definition, end);
    let lines = before
        .lines
        .iter()
        .zip(&after.lines)
        .map(|(old, new)| StatementLineChange {
            code: old.code.clone(),
            label: old.label.clone(),
            unit: old.unit,
            before: old.amounts.clone(),
            after: new.amounts.clone(),
            delta: old
                .amounts
                .iter()
                .zip(&new.amounts)
                .map(|(a, b)| b - a)
                .collect(),
        })
        .collect();
    VerifiedStatementDiff {
        custom: None,
        valuation: StatementDiffValuation::Native,
        before_known_at: start,
        after_known_at: end,
        before_digest: commitment(b"fa:statement-diff-source:v1", &before_bytes),
        after_digest: commitment(b"fa:statement-diff-source:v1", &after_bytes),
        before,
        after,
        lines,
        mapping_changes: Vec::new(),
    }
}

fn fixture_trace() -> (Fixture, Vec<Vec<u8>>, VerifiedStatementTrace) {
    let f = fixture(true);
    let after = f.before.clone();
    let mut before = after.clone();
    for line in &mut before.lines {
        if line.unit == 0 {
            if line.code == "expense" {
                line.amounts[0] = 0;
            }
            if line.code == "net_income" {
                line.amounts[0] = 1234;
            }
        }
    }
    let summary = comparison(before.clone(), after.clone(), 4, 9);
    assert_eq!(
        summary
            .lines
            .iter()
            .find(|line| line.code == "net_income" && line.unit == 0)
            .unwrap()
            .delta,
        [-234, 0]
    );
    let mut sources = vec![f.source(&before, 4)];
    let mut publications = Vec::new();
    let closing = key_id(b"closing");
    let reverse = reversal_id(closing);
    for at in 5..=9 {
        sources.push(f.source(&after, at));
        let old = if at == 5 { &before } else { &after };
        let old_bytes = output_bytes(old, &definition(true), at - 1);
        let new_bytes = output_bytes(&after, &definition(true), at);
        let (entry, class, day, references) = match at {
            5 => (key_id(b"expense"), 1, 41, Vec::new()),
            6 => (key_id(b"reservation"), 2, 42, Vec::new()),
            7 => (closing, 8, 50, Vec::new()),
            8 => (
                reverse,
                4,
                51,
                vec![(closing, f.records[6].envelope.record_digest)],
            ),
            9 => (
                reversal_id(reverse),
                4,
                52,
                vec![(reverse, f.records[7].envelope.record_digest)],
            ),
            _ => unreachable!(),
        };
        publications.push(VerifiedStatementPublication {
            recorded_at: at,
            before_source_digest: commitment(b"fa:statement-trace-source:v1", &old_bytes),
            after_source_digest: commitment(b"fa:statement-trace-source:v1", &new_bytes),
            entries: vec![VerifiedStatementEntryLink {
                event: VerifiedStatementEntryEvent::Recorded,
                entry,
                digest: f.records[at as usize - 1].envelope.record_digest,
                class,
                recorded_at: at,
                posting_date: Some(day),
                principal: PRINCIPAL,
                references,
                migration_run: None,
            }],
            changes: if at == 5 {
                summary
                    .lines
                    .iter()
                    .filter(|line| line.delta.iter().any(|v| *v != 0))
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            },
            mapping_changes: Vec::new(),
        });
    }
    (
        f,
        sources,
        VerifiedStatementTrace {
            summary,
            publications,
        },
    )
}

fn trace_output(trace: &VerifiedStatementTrace) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:statement-trace:v1")
        .bytes(&bridge_output(&trace.summary))
        .count(trace.publications.len());
    for step in &trace.publications {
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
            for (id, digest) in &entry.references {
                w.u128(*id).fixed(digest);
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
        w.count(step.mapping_changes.len());
        for change in &step.mapping_changes {
            w.u128(change.account);
            for item in [&change.before, &change.after] {
                w.u8(u8::from(item.is_some()));
                if let Some(item) = item {
                    mapping(&mut w, item);
                }
            }
        }
    }
    w.buf
}

fn trace_outer(sources: &[Vec<u8>], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    w.bytes(b"fa:statement-trace-certificate:v1")
        .u128(PRINCIPAL)
        .fixed(&[8; 32])
        .count(sources.len());
    for source in sources {
        w.bytes(source);
    }
    w.bytes(output);
    let digest = commitment(b"fa:statement-trace-certificate-digest:v1", &w.buf);
    w.fixed(&digest);
    (w.buf, digest)
}

fn check_trace(
    f: &Fixture,
    sources: &[Vec<u8>],
    output: &[u8],
) -> Result<VerifiedReport, ReportError> {
    let (certificate, pin) = trace_outer(sources, output);
    f.check(&replace_certificate(&f.after_bundle, &certificate), pin)
}

#[test]
fn portable_trace_recomputes_every_source_zero_effect_and_lineage_without_book() {
    let (f, sources, expected) = fixture_trace();
    let output = trace_output(&expected);
    let verified = check_trace(&f, &sources, &output).unwrap();
    assert_eq!(verified.statement_trace, Some(expected.clone()));
    assert!(verified.statement.is_none());
    assert!(verified.statement_diff.is_none());
    assert_eq!(verified.output, output);
    assert_eq!(verified.known_at, 9);
    assert_eq!(verified.checked_records, 13);
    assert_eq!(verified.checkpoint.checkpoint.through_seq, 13);
    assert_eq!(expected.publications.len(), 5);
    assert!(
        expected.publications[1..]
            .iter()
            .all(|p| p.changes.is_empty())
    );
}

#[test]
fn resealed_trace_cannot_forge_or_omit_publications_principals_and_lineage() {
    let (f, sources, expected) = fixture_trace();
    for mutation in 0..8 {
        let mut changed = expected.clone();
        match mutation {
            0 => changed.publications[0].entries[0].principal ^= 1,
            1 => changed.publications[3].entries[0].references[0].1[0] ^= 1,
            2 => {
                changed.publications.remove(1);
            }
            3 => changed.publications[1].changes = expected.publications[0].changes.clone(),
            4 => changed.publications[0].entries.clear(),
            5 => changed.publications[0].entries[0].entry ^= 1,
            6 => changed.publications[2].before_source_digest[0] ^= 1,
            7 => changed.summary.lines.retain(|line| line.unit != 12),
            _ => unreachable!(),
        }
        let error = check_trace(&f, &sources, &trace_output(&changed)).unwrap_err();
        assert!(
            matches!(
                error.predicate,
                "statement_trace_recomputation" | "bounded_input"
            ),
            "mutation {mutation}: {error}"
        );
    }
}

#[test]
fn resealed_intermediate_amount_root_and_missing_zero_effect_source_are_rejected() {
    let (f, sources, expected) = fixture_trace();
    let output = trace_output(&expected);
    let mut false_statement = f.before.clone();
    false_statement.lines[0].amounts[0] += 1;
    let mut changed = sources.clone();
    changed[2] = f.source(&false_statement, 6);
    assert_eq!(
        check_trace(&f, &changed, &output).unwrap_err().predicate,
        "report_recomputation"
    );

    let mut changed = sources.clone();
    let old_root = certificate(&changed[2]).unwrap().journal_root;
    let root_offset = changed[2]
        .windows(32)
        .position(|bytes| bytes == old_root)
        .unwrap();
    changed[2][root_offset] ^= 1;
    let end = changed[2].len() - 32;
    let seal = hash_parts(STATEMENT_CERTIFICATE_FORMAT, &[&changed[2][..end]]);
    changed[2][end..].copy_from_slice(&seal);
    assert_eq!(
        check_trace(&f, &changed, &output).unwrap_err().predicate,
        "historical_prefix"
    );

    let mut changed = sources.clone();
    changed.remove(2);
    assert_eq!(
        check_trace(&f, &changed, &output).unwrap_err().predicate,
        "statement_trace_sources"
    );
    let mut changed = sources;
    changed.swap(2, 3);
    assert_eq!(
        check_trace(&f, &changed, &output).unwrap_err().predicate,
        "statement_trace_sources"
    );
}

#[test]
fn empty_trace_still_requires_its_complete_authenticated_source() {
    let (f, sources, _) = fixture_trace();
    let trace = VerifiedStatementTrace {
        summary: comparison(f.before.clone(), f.before.clone(), 9, 9),
        publications: Vec::new(),
    };
    let last = vec![sources.last().unwrap().clone()];
    let verified = check_trace(&f, &last, &trace_output(&trace)).unwrap();
    assert_eq!(verified.statement_trace, Some(trace.clone()));
    let mut false_statement = f.before.clone();
    false_statement.lines[0].amounts[0] += 1;
    assert_eq!(
        check_trace(&f, &[f.source(&false_statement, 9)], &trace_output(&trace))
            .unwrap_err()
            .predicate,
        "report_recomputation"
    );
    assert_eq!(
        check_trace(&f, &[], &trace_output(&trace))
            .unwrap_err()
            .predicate,
        "statement_trace_sources"
    );
}
