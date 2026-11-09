//! The same visibility transcript must survive retained foreign valuations.
use super::*;
use crate::report::functional::tests::migration as migration_fixture;

#[test]
fn functional_migration_trace_activates_original_valuations_only_at_finalize() {
    let (original, rates) = history();
    let body = migration_fixture::body(0, false);
    let run = migration_fixture::run();
    let mut records = original[..3].to_vec();
    records.push(migration_fixture::control(4, 0, run, &body));
    records.push(entry_with_migration(
        5,
        12,
        10,
        b"capital",
        &valued_pair("1000", "3000", 1000, 1100),
        Some((1, &rates[0], None)),
        None,
        None,
        Some(run),
    ));
    records.push(migration_fixture::control(6, 1, run, &body));
    // This later backdate belongs to the signed prefix but neither endpoint.
    records.push(entry(
        7,
        1,
        10,
        b"after-trace",
        &at_par("1000", "3000", 9),
        None,
        None,
        None,
    ));
    let chunk_digest = framed_hash(
        b"fa:vid:migration-entry:v1",
        &[&BOOK, &run.to_le_bytes(), b"capital"],
    );
    let chunk_id = u128::from_le_bytes(chunk_digest[..16].try_into().unwrap());
    for activity in [false, true] {
        let mut sources = Vec::new();
        let mut states = Vec::new();
        let mut package = None;
        for at in 3..=6 {
            let mut request = request(activity);
            request.known_at = at;
            let mut report = expected(&request, 0);
            for line in &mut report.statement.lines {
                let capital = at == 6
                    && matches!(
                        line.code.as_str(),
                        "assets" | "equity" | "total_equity" | "liabilities_and_equity"
                    );
                line.amounts = if capital {
                    vec![1100, 1100]
                } else {
                    vec![0, 0]
                };
            }
            let output = output(&report, &request);
            let bodies = if at >= 5 {
                vec![(3, body.as_slice())]
            } else {
                Vec::new()
            };
            let (bundle, signed, _) = pack_statement_with_migrations(
                &records,
                &request,
                &book(&[]),
                &rates[..1],
                &output,
                &bodies,
            );
            sources.push(source(&bundle).to_vec());
            states.push((request, report, output));
            package = Some((bundle, signed));
        }
        let link = |recorded: u64, event| {
            let record = &records[recorded as usize - 1];
            VerifiedStatementEntryLink {
                event,
                entry: if recorded == 5 {
                    chunk_id
                } else {
                    key_id(&recorded.to_le_bytes())
                },
                digest: record.envelope.record_digest,
                class: if recorded == 5 { 12 } else { 22 },
                recorded_at: recorded,
                posting_date: (recorded == 5).then_some(10),
                principal: PRINCIPAL,
                references: Vec::new(),
                migration_run: Some(run),
            }
        };
        let publications = states
            .windows(2)
            .map(|pair| {
                let (before_request, before, before_bytes) = &pair[0];
                let (after_request, after, after_bytes) = &pair[1];
                let at = after_request.known_at;
                let delta = comparison(before, after, before_request, after_request);
                let mut entries = vec![link(at, VerifiedStatementEntryEvent::Recorded)];
                if at == 6 {
                    entries.push(link(5, VerifiedStatementEntryEvent::BecameVisible));
                }
                entries.sort_by_key(|entry| entry.entry);
                VerifiedStatementPublication {
                    recorded_at: at,
                    before_source_digest: trace_source(before_bytes),
                    after_source_digest: trace_source(after_bytes),
                    entries,
                    changes: delta
                        .lines
                        .into_iter()
                        .filter(|line| line.delta.iter().any(|v| *v != 0))
                        .collect(),
                    mapping_changes: Vec::new(),
                }
            })
            .collect();
        let expected = VerifiedStatementTrace {
            summary: comparison(&states[0].1, &states[3].1, &states[0].0, &states[3].0),
            publications,
        };
        let output = trace_output(&expected);
        let (certificate, pin) = trace_outer(&sources, &output);
        let (bundle, checkpoint) = package.unwrap();
        let verified = verify(&replace_source(&bundle, &certificate), &checkpoint, &pin).unwrap();
        assert_eq!(verified.statement_trace.as_ref(), Some(&expected));
        assert_eq!(verified.output, output);
        assert_eq!(verified.checkpoint.checkpoint.through_seq, 7);
        if activity {
            assert!(
                expected
                    .publications
                    .iter()
                    .all(|step| step.changes.is_empty())
            );
        } else {
            assert_eq!(
                expected.publications[2]
                    .changes
                    .iter()
                    .find(|line| line.code == "assets")
                    .unwrap()
                    .delta,
                [1100, 1100]
            );
        }
        let activation = expected.publications[2]
            .entries
            .iter()
            .find(|entry| entry.event == VerifiedStatementEntryEvent::BecameVisible)
            .unwrap();
        assert_eq!(activation.recorded_at, 5);
        assert_eq!(activation.migration_run, Some(run));
        let mut forged = expected;
        forged.publications[2]
            .entries
            .retain(|entry| entry.event == VerifiedStatementEntryEvent::Recorded);
        let (certificate, pin) = trace_outer(&sources, &trace_output(&forged));
        assert!(verify(&replace_source(&bundle, &certificate), &checkpoint, &pin).is_err());
    }
}
