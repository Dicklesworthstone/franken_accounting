//! Independently encoded functional traces retain Rate imports, zero-effect
//! publications and changing mappings as well as each intermediate amount.
use super::*;
use crate::report::{
    VerifiedStatementEntryEvent, VerifiedStatementEntryLink, VerifiedStatementPublication,
    VerifiedStatementTrace,
};

#[path = "statement_trace/migration.rs"]
mod migration;

fn commitment(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    hash_parts(domain, &[&(bytes.len() as u32).to_le_bytes(), bytes])
}

fn trace_source(bytes: &[u8]) -> [u8; 32] {
    commitment(
        b"fa:functional-statement-trace-source:v1",
        inner_statement(bytes),
    )
}

fn key_id(key: &[u8]) -> u128 {
    let mut w = Writer::default();
    w.bytes(&BOOK).bytes(&PRINCIPAL.to_le_bytes()).bytes(key);
    let digest = hash_parts(b"fa:vid:entry:v1", &[&w.buf]);
    u128::from_le_bytes(digest[..16].try_into().unwrap())
}

fn comparison(
    before: &VerifiedFunctionalStatement,
    after: &VerifiedFunctionalStatement,
    before_request: &Request,
    after_request: &Request,
) -> VerifiedStatementDiff {
    let before_mapping: BTreeMap<_, _> = before
        .statement
        .mappings
        .iter()
        .map(|m| (m.account, m))
        .collect();
    let after_mapping: BTreeMap<_, _> = after
        .statement
        .mappings
        .iter()
        .map(|m| (m.account, m))
        .collect();
    let accounts: BTreeSet<_> = before_mapping
        .keys()
        .chain(after_mapping.keys())
        .copied()
        .collect();
    VerifiedStatementDiff {
        custom: None,
        valuation: StatementDiffValuation::Functional {
            base_unit: 0,
            book_parameters_source: BOOK_PARAMETERS_SOURCE,
        },
        before_known_at: before_request.known_at,
        after_known_at: after_request.known_at,
        before_digest: source_digest(&output(before, before_request)),
        after_digest: source_digest(&output(after, after_request)),
        before: before.statement.clone(),
        after: after.statement.clone(),
        lines: before
            .statement
            .lines
            .iter()
            .zip(&after.statement.lines)
            .map(|(a, b)| StatementLineChange {
                code: a.code.clone(),
                label: a.label.clone(),
                unit: a.unit,
                before: a.amounts.clone(),
                after: b.amounts.clone(),
                delta: a
                    .amounts
                    .iter()
                    .zip(&b.amounts)
                    .map(|(a, b)| b - a)
                    .collect(),
            })
            .collect(),
        mapping_changes: accounts
            .into_iter()
            .filter_map(|account| {
                let before = before_mapping.get(&account).copied();
                let after = after_mapping.get(&account).copied();
                (before != after).then(|| StatementMappingChange {
                    account,
                    before: before.cloned(),
                    after: after.cloned(),
                })
            })
            .collect(),
    }
}

fn source_at(f: &Fixture, at: u64, result: &VerifiedFunctionalStatement) -> Vec<u8> {
    let mut request = request(f.before_request.activity);
    request.known_at = at;
    let (bundle, _, _) = pack_statement(
        &f.records,
        &request,
        &book(&[]),
        &f.rates,
        &output(result, &request),
    );
    source(&bundle).to_vec()
}

fn expected_at(f: &Fixture, at: u64) -> (Request, VerifiedFunctionalStatement) {
    let mut request = request(f.before_request.activity);
    request.known_at = at;
    let mut result = expected(
        &request,
        if at < 12 {
            0
        } else if at < 16 {
            9990
        } else {
            10_215
        },
    );
    if at >= 15 {
        result
            .statement
            .mappings
            .push(f.after.statement.mappings.last().unwrap().clone());
    }
    (request, result)
}

fn fixture_trace(activity: bool) -> (Fixture, Vec<Vec<u8>>, VerifiedStatementTrace) {
    let f = fixture(activity);
    let mut sources = Vec::new();
    let mut publications = Vec::new();
    for at in 11..=16 {
        let (next_request, next) = expected_at(&f, at);
        sources.push(source_at(&f, at, &next));
        if at == 11 {
            continue;
        }
        let (old_request, old) = expected_at(&f, at - 1);
        let diff = comparison(&old, &next, &old_request, &next_request);
        let entry = match at {
            12 => Some((b"later-backdate".as_slice(), 1, Some(40))),
            15 => Some((b"comparison-zero-chart".as_slice(), 17, None)),
            16 => Some((b"new-rate-sale".as_slice(), 1, Some(40))),
            _ => None,
        };
        publications.push(VerifiedStatementPublication {
            recorded_at: at,
            before_source_digest: trace_source(&output(&old, &old_request)),
            after_source_digest: trace_source(&output(&next, &next_request)),
            entries: entry
                .into_iter()
                .map(|(key, class, posting_date)| VerifiedStatementEntryLink {
                    event: VerifiedStatementEntryEvent::Recorded,
                    entry: key_id(key),
                    digest: f
                        .records
                        .iter()
                        .find(|r| r.envelope.commit_seq == at && r.envelope.kind == KIND_ENTRY)
                        .unwrap()
                        .envelope
                        .record_digest,
                    class,
                    recorded_at: at,
                    posting_date,
                    principal: PRINCIPAL,
                    references: Vec::new(),
                    migration_run: None,
                })
                .collect(),
            changes: diff
                .lines
                .into_iter()
                .filter(|line| line.delta.iter().any(|amount| *amount != 0))
                .collect(),
            mapping_changes: diff.mapping_changes,
        });
    }
    let trace = VerifiedStatementTrace {
        summary: f.claim.clone(),
        publications,
    };
    (f, sources, trace)
}

fn mapping(w: &mut Writer, value: &StatementMapping) {
    w.u128(value.account)
        .bytes(value.code.as_bytes())
        .bytes(value.name.as_bytes())
        .u8(value.account_type)
        .u8(u8::from(value.is_leaf))
        .bytes(value.line_code.as_bytes());
}

fn trace_output(trace: &VerifiedStatementTrace) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:functional-statement-trace:v1")
        .bytes(&bridge(&trace.summary))
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
            for value in [&change.before, &change.after] {
                w.u8(u8::from(value.is_some()));
                if let Some(value) = value {
                    mapping(&mut w, value);
                }
            }
        }
    }
    w.buf
}

fn trace_outer(sources: &[Vec<u8>], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    w.bytes(b"fa:functional-statement-trace-certificate:v1")
        .u128(PRINCIPAL)
        .fixed(&[8; 32])
        .count(sources.len());
    for source in sources {
        w.bytes(source);
    }
    w.bytes(output);
    let pin = commitment(
        b"fa:functional-statement-trace-certificate-digest:v1",
        &w.buf,
    );
    w.fixed(&pin);
    (w.buf, pin)
}

fn trace_bundle(
    f: &Fixture,
    sources: &[Vec<u8>],
    output: &[u8],
) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
    let (bundle, signed, _) = f.source_bundle(false, &f.after);
    let (certificate, pin) = trace_outer(sources, output);
    (replace_source(&bundle, &certificate), signed, pin)
}

fn check_trace(
    f: &Fixture,
    sources: &[Vec<u8>],
    output: &[u8],
) -> Result<VerifiedReport, ReportError> {
    let (bundle, signed, pin) = trace_bundle(f, sources, output);
    verify(&bundle, &signed, &pin)
}

#[test]
fn functional_trace_recomputes_every_historical_rate_set_zero_effect_and_mapping() {
    for activity in [false, true] {
        let (f, sources, expected) = fixture_trace(activity);
        let bytes = trace_output(&expected);
        let (bundle, signed, pin) = trace_bundle(&f, &sources, &bytes);
        let verified = verify(&bundle, &signed, &pin).unwrap();
        assert_eq!(verified.statement_trace, Some(expected.clone()));
        assert_eq!(verified.output, bytes);
        assert_eq!(verified.certificate_digest, pin);
        assert_eq!(verified.known_at, 16);
        assert_eq!(verified.checkpoint.checkpoint.through_seq, 17);
        assert!(verified.functional_statement.is_none());
        assert!(verified.statement_diff.is_none());
        assert!(verified.statement.is_none());
        assert_eq!(expected.publications.len(), 5);
        assert!(
            expected.publications[1..=2]
                .iter()
                .all(|p| p.entries.is_empty() && p.changes.is_empty())
        );
        assert!(expected.publications[3].changes.is_empty());
        assert_eq!(expected.publications[3].mapping_changes.len(), 1);
        assert_eq!(expected.publications[4].changes[0].delta, [225, 0]);
    }
}

#[test]
fn resealed_functional_trace_cannot_forge_publications_domains_or_zero_coverage() {
    let (f, sources, expected) = fixture_trace(true);
    for mutation in 0..10 {
        let mut changed = expected.clone();
        match mutation {
            0 => changed.publications[0].entries[0].principal ^= 1,
            1 => changed.publications[4].changes[0].delta[0] += 1,
            2 => {
                changed.publications.remove(1);
            }
            3 => changed.publications[3].mapping_changes.clear(),
            4 => changed.publications[0].entries.clear(),
            5 => changed.publications[0].entries[0].entry ^= 1,
            6 => changed.publications[2].before_source_digest[0] ^= 1,
            7 => {
                changed.summary.lines.remove(1);
            }
            8 => {
                let source = certificate(&sources[0]).unwrap();
                changed.publications[0].before_source_digest = commitment(
                    b"fa:statement-trace-source:v1",
                    inner_statement(source.output),
                );
            }
            9 => {
                let source = certificate(&sources[0]).unwrap();
                changed.publications[0].before_source_digest =
                    commitment(b"fa:functional-statement-trace-source:v1", source.output);
            }
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
fn resealed_functional_trace_requires_every_authentic_intermediate_source() {
    let (f, sources, expected) = fixture_trace(true);
    let bytes = trace_output(&expected);
    let (_, mut false_statement) = expected_at(&f, 13);
    false_statement.statement.lines[0].amounts[0] += 1;
    let mut changed = sources.clone();
    changed[2] = source_at(&f, 13, &false_statement);
    assert_eq!(
        check_trace(&f, &changed, &bytes).unwrap_err().predicate,
        "report_recomputation"
    );

    let mut changed = sources.clone();
    let root = certificate(&changed[2]).unwrap().journal_root;
    let offset = changed[2]
        .windows(32)
        .position(|bytes| bytes == root)
        .unwrap();
    changed[2][offset] ^= 1;
    let end = changed[2].len() - 32;
    let seal = hash_parts(
        FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT,
        &[&changed[2][..end]],
    );
    changed[2][end..].copy_from_slice(&seal);
    assert_eq!(
        check_trace(&f, &changed, &bytes).unwrap_err().predicate,
        "historical_prefix"
    );

    let mut changed = sources.clone();
    changed.remove(2);
    assert_eq!(
        check_trace(&f, &changed, &bytes).unwrap_err().predicate,
        "statement_trace_sources"
    );
    let mut changed = sources;
    changed.swap(2, 3);
    assert_eq!(
        check_trace(&f, &changed, &bytes).unwrap_err().predicate,
        "statement_trace_sources"
    );
}

#[test]
fn functional_trace_requires_exact_rate_evidence_and_original_first_use() {
    for mutation in 0..3 {
        let mut f = fixture(true);
        match mutation {
            0 => {
                f.rates.pop();
            }
            1 => f.rates.push(rate_fixture(17, 10, 3, 58)),
            2 => {
                // Move the quote intake after first use, resealing the complete
                // prefix. A later valid receipt must not repair its provenance.
                let rate = f.rates[1].clone();
                f.records.remove(4);
                f.records.push(intake(&rate, 18));
            }
            _ => unreachable!(),
        }
        let (_, sources, expected) = fixture_trace(true);
        // Rebuild every source against the altered authenticated prefix, so a
        // stale MMR commitment cannot be the reason this adversary is rejected.
        let sources: Vec<_> = sources
            .iter()
            .map(|raw| {
                let cert = certificate(raw).unwrap();
                let (_, result) = expected_at(&f, cert.known_at);
                source_at(&f, cert.known_at, &result)
            })
            .collect();
        let error = check_trace(&f, &sources, &trace_output(&expected)).unwrap_err();
        assert_eq!(
            error.predicate,
            if mutation == 2 {
                "functional_rate_visibility"
            } else {
                "functional_rates"
            }
        );
    }
}

#[test]
fn functional_trace_rejects_wrong_family_bundle_epoch_and_nested_certificate_pin() {
    let (f, sources, expected) = fixture_trace(false);
    let output = trace_output(&expected);
    let (bytes, signed, pin) = trace_bundle(&f, &sources, &output);
    let nested = certificate(sources.last().unwrap()).unwrap().digest;
    assert_eq!(
        verify(&bytes, &signed, &nested).unwrap_err().predicate,
        "recipient_certificate"
    );
    let mut downgraded = bytes.clone();
    let offset = 4 + REPORT_BUNDLE_FORMAT.len();
    downgraded[offset..offset + 2].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        verify(&downgraded, &signed, &pin).unwrap_err().predicate,
        "supported_report"
    );
    let mut changed = sources.clone();
    let registry = certificate(&changed[2]).unwrap().registry_digest;
    let offset = changed[2]
        .windows(32)
        .position(|bytes| bytes == registry)
        .unwrap();
    changed[2][offset] ^= 1;
    let end = changed[2].len() - 32;
    let seal = hash_parts(
        FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT,
        &[&changed[2][..end]],
    );
    changed[2][end..].copy_from_slice(&seal);
    assert_eq!(
        check_trace(&f, &changed, &output).unwrap_err().predicate,
        "registry_closure"
    );

    // Relabel the functional sources with a correctly sealed native outer
    // certificate. Neither intact native domains nor intact payload hashes
    // authorize cross-measure interpretation.
    let mut native = Writer::default();
    native
        .bytes(b"fa:statement-trace-certificate:v1")
        .u128(PRINCIPAL)
        .fixed(&[8; 32])
        .count(sources.len());
    for source in &sources {
        native.bytes(source);
    }
    native.bytes(&output);
    let native_pin = commitment(b"fa:statement-trace-certificate-digest:v1", &native.buf);
    native.fixed(&native_pin);
    assert_eq!(
        verify(&replace_source(&bytes, &native.buf), &signed, &native_pin)
            .unwrap_err()
            .predicate,
        "supported_report"
    );
}

#[test]
fn functional_trace_empty_interval_still_authenticates_its_entire_source() {
    let (f, sources, _) = fixture_trace(true);
    let (request, result) = expected_at(&f, 16);
    let expected = VerifiedStatementTrace {
        summary: comparison(&result, &result, &request, &request),
        publications: Vec::new(),
    };
    let sources = vec![sources.last().unwrap().clone()];
    assert_eq!(
        check_trace(&f, &sources, &trace_output(&expected))
            .unwrap()
            .statement_trace,
        Some(expected.clone())
    );
    assert_eq!(
        check_trace(&f, &[], &trace_output(&expected))
            .unwrap_err()
            .predicate,
        "statement_trace_sources"
    );
}

#[test]
fn functional_trace_preserves_canceling_foreign_post_and_exact_reversal_lineage() {
    let mut f = fixture(true);
    let original = f
        .records
        .iter()
        .find(|r| r.envelope.commit_seq == 16)
        .unwrap()
        .clone();
    let rate = f.rates.last().unwrap().clone();
    f.records.retain(|r| r.envelope.commit_seq < 17);
    let reversal = entry(
        17,
        4,
        41,
        b"reverse-foreign-sale",
        &valued_pair("1000", "4000", 100, 225)
            .into_iter()
            .map(|mut leg| {
                leg.debit = !leg.debit;
                leg
            })
            .collect::<Vec<_>>(),
        Some((3, &rate, None)),
        Some(&original),
        None,
    );
    f.records.push(reversal.clone());
    let (before_request, before) = expected_at(&f, 15);
    let (middle_request, middle) = expected_at(&f, 16);
    let mut after_request = request(true);
    after_request.known_at = 17;
    let after = before.clone();
    f.after_request = after_request;
    f.after = after.clone();
    let mut sources = Vec::new();
    for (at, result) in [(15, &before), (16, &middle), (17, &after)] {
        sources.push(source_at(&f, at, result));
    }
    let original_id = key_id(b"new-rate-sale");
    let reversal_digest = hash_parts(b"fa:vid:reversal:v1", &[&original_id.to_le_bytes()]);
    let reversal_id = u128::from_le_bytes(reversal_digest[..16].try_into().unwrap());
    let mut publications = Vec::new();
    for (a, b, a_request, b_request, record, identity, references) in [
        (
            &before,
            &middle,
            &before_request,
            &middle_request,
            &original,
            original_id,
            Vec::new(),
        ),
        (
            &middle,
            &after,
            &middle_request,
            &f.after_request,
            &reversal,
            reversal_id,
            vec![(original_id, original.envelope.record_digest)],
        ),
    ] {
        let diff = comparison(a, b, a_request, b_request);
        publications.push(VerifiedStatementPublication {
            recorded_at: b_request.known_at,
            before_source_digest: trace_source(&output(a, a_request)),
            after_source_digest: trace_source(&output(b, b_request)),
            entries: vec![VerifiedStatementEntryLink {
                event: VerifiedStatementEntryEvent::Recorded,
                entry: identity,
                digest: record.envelope.record_digest,
                class: record.envelope.class,
                recorded_at: b_request.known_at,
                posting_date: record.envelope.effective_day,
                principal: PRINCIPAL,
                references,
                migration_run: None,
            }],
            changes: diff
                .lines
                .into_iter()
                .filter(|line| line.delta.iter().any(|v| *v != 0))
                .collect(),
            mapping_changes: diff.mapping_changes,
        });
    }
    let expected = VerifiedStatementTrace {
        summary: comparison(&before, &after, &before_request, &f.after_request),
        publications,
    };
    let verified = check_trace(&f, &sources, &trace_output(&expected)).unwrap();
    assert_eq!(verified.statement_trace, Some(expected.clone()));
    assert!(
        expected
            .summary
            .lines
            .iter()
            .all(|line| line.delta.iter().all(|v| *v == 0))
    );
    assert_eq!(expected.publications[0].changes[0].delta, [225, 0]);
    assert_eq!(expected.publications[1].changes[0].delta, [-225, 0]);
    let mut omitted = expected.clone();
    omitted.publications[1].entries[0].references.clear();
    assert!(check_trace(&f, &sources, &trace_output(&omitted)).is_err());
    // Even when the only uses cancel by the final frontier, the full Rate
    // closure is still mandatory and cannot be pruned to the final net balance.
    f.rates.pop();
    assert_eq!(
        check_trace(&f, &sources, &trace_output(&expected))
            .unwrap_err()
            .predicate,
        "functional_rates"
    );
}
