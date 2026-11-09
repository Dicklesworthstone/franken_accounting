//! Independently encoded migration traces. Staging has no financial effect;
//! Finalize contributes the selected chunks without changing their birth dates.
use super::*;

const FINALIZE: u64 = 9;

fn run(key: &[u8]) -> u128 {
    let mut w = Writer::default();
    w.bytes(&BOOK).bytes(key);
    let digest = hash_parts(b"fa:vid:migration-run:v1", &[&w.buf]);
    u128::from_le_bytes(digest[..16].try_into().unwrap())
}

fn chunk_id(run: u128, key: &[u8]) -> u128 {
    let mut w = Writer::default();
    w.bytes(&BOOK).bytes(&run.to_le_bytes()).bytes(key);
    let digest = hash_parts(b"fa:vid:migration-entry:v1", &[&w.buf]);
    u128::from_le_bytes(digest[..16].try_into().unwrap())
}

fn body(key: &[u8], sole: bool) -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(1)
        .fixed(&BOOK)
        .bytes(key)
        .bytes(b"legacy")
        .u8(2) // FullDetail: earlier detail counts only when sole is true.
        .fixed(&[0; 32])
        .i32(31)
        .count(0)
        .count(0)
        .count(0)
        .u8(u8::from(sole));
    w.buf
}

fn prefix(class: u16, day: i32) -> Writer {
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(class)
        .i32(day)
        .u8(0);
    erasable(&mut w);
    w.u8(0);
    w
}

fn finish(mut w: Writer, at: u64) -> Record {
    w.u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(0)
        .u8(0)
        .count(0)
        .count(0);
    let len = w.buf.len();
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    w.fixed(&proposal).fixed(&digest);
    let envelope = envelope_of_entry(&w.buf, len, at, 0).unwrap();
    Record {
        bytes: w.buf,
        len,
        envelope,
    }
}

fn control(at: u64, key: &[u8], run: u128, body: &[u8], kind: u8) -> Record {
    let digest = commitment(b"fa:migration-run-body:v1", body);
    let mut w = prefix(22, 31);
    w.count(0)
        .u8(1)
        .u8(10)
        .u128(run)
        .u8(kind)
        .fixed(if kind == 0 { &digest } else { &[9; 32] })
        .count(0)
        .u8(0)
        .bytes(key)
        .u8(3)
        .u16(9)
        .fixed(&digest);
    finish(w, at)
}

fn chunk(at: u64, key: &[u8], run: u128, day: i32, amount: i128) -> Record {
    let mut w = prefix(12, day);
    w.count(2);
    for (account, side) in [("1000", 0), ("4000", 1)] {
        w.u8(side)
            .u128(account_id(account))
            .u32(0)
            .i128(amount)
            .u8(0)
            .count(0)
            .u8(0)
            .count(0);
    }
    w.u8(0)
        .count(0)
        .u8(0)
        .bytes(key)
        .u8(2)
        .u128(run)
        .bytes(b"legacy");
    erasable(&mut w);
    w.u8(0).u8(0).u8(0).fixed(&[0; 32]);
    finish(w, at)
}

/// Retain the ordinary test package's independently constructed signed prefix
/// and native source framing, adding the run bodies to the existing wire slot.
fn with_bodies(bundle: &[u8], bodies: &[(u64, &[u8])]) -> Vec<u8> {
    let mut r = Reader::new(bundle);
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
    let before = bundle.len() - r.remaining();
    assert_eq!(r.count(100, 12, "bodies").unwrap(), 0);
    let after = bundle.len() - r.remaining();
    let mut w = Writer::default();
    w.fixed(&bundle[..before]).count(bodies.len());
    for (index, body) in bodies {
        w.u64(*index).bytes(body);
    }
    w.fixed(&bundle[after..]);
    w.buf
}

struct MigrationFixture {
    records: Vec<Record>,
    bodies: Vec<(u64, Vec<u8>)>,
    sole: bool,
}

impl MigrationFixture {
    fn new(sole: bool) -> Self {
        let a = body(b"trace-a", sole);
        let b = body(b"trace-b", true);
        let mut records = history();
        records.truncate(2);
        records.extend([
            control(3, b"open-a", run(b"trace-a"), &a, 0),
            chunk(4, b"old-a", run(b"trace-a"), 10, 40),
            chunk(5, b"new-a", run(b"trace-a"), 40, 70),
            control(6, b"open-b", run(b"trace-b"), &b, 0),
            chunk(7, b"abandoned-b", run(b"trace-b"), 41, 99),
            control(8, b"abandon-b", run(b"trace-b"), &b, 2),
            control(9, b"finalize-a", run(b"trace-a"), &a, 1),
            make(
                1,
                10,
                40,
                b"later-than-trace",
                &[("1000", true, 5), ("4000", false, 5)],
                None,
            ),
        ]);
        Self {
            records,
            bodies: vec![(2, a), (5, b)],
            sole,
        }
    }

    fn statement(&self, at: u64) -> VerifiedStatement {
        let mut statement = expected(true);
        for line in &mut statement.lines {
            line.amounts = if at >= FINALIZE
                && line.unit == 0
                && matches!(line.code.as_str(), "revenue" | "net_income")
            {
                vec![70, if self.sole { 40 } else { 0 }]
            } else {
                vec![0, 0]
            };
        }
        statement
    }

    fn link(
        &self,
        recorded: u64,
        event: VerifiedStatementEntryEvent,
    ) -> VerifiedStatementEntryLink {
        let (key, run_key, monetary) = match recorded {
            3 => (b"open-a".as_slice(), b"trace-a".as_slice(), false),
            4 => (b"old-a".as_slice(), b"trace-a".as_slice(), true),
            5 => (b"new-a".as_slice(), b"trace-a".as_slice(), true),
            6 => (b"open-b".as_slice(), b"trace-b".as_slice(), false),
            7 => (b"abandoned-b".as_slice(), b"trace-b".as_slice(), true),
            8 => (b"abandon-b".as_slice(), b"trace-b".as_slice(), false),
            9 => (b"finalize-a".as_slice(), b"trace-a".as_slice(), false),
            _ => unreachable!(),
        };
        let record = &self.records[recorded as usize - 1];
        VerifiedStatementEntryLink {
            event,
            entry: if monetary {
                chunk_id(run(run_key), key)
            } else {
                key_id(key)
            },
            digest: record.envelope.record_digest,
            class: if monetary { 12 } else { 22 },
            recorded_at: recorded,
            posting_date: monetary.then_some(record.envelope.effective_day.unwrap()),
            principal: PRINCIPAL,
            references: Vec::new(),
            migration_run: Some(run(run_key)),
        }
    }

    fn trace(&self, start: u64, end: u64) -> VerifiedStatementTrace {
        let publications = (start + 1..=end)
            .map(|at| {
                let before = self.statement(at - 1);
                let after = self.statement(at);
                let diff = comparison(before.clone(), after.clone(), at - 1, at);
                let mut entries = vec![self.link(at, VerifiedStatementEntryEvent::Recorded)];
                if at == FINALIZE {
                    entries.push(self.link(5, VerifiedStatementEntryEvent::BecameVisible));
                    if self.sole {
                        entries.push(self.link(4, VerifiedStatementEntryEvent::BecameVisible));
                    }
                }
                entries.sort_by_key(|entry| entry.entry);
                VerifiedStatementPublication {
                    recorded_at: at,
                    before_source_digest: commitment(
                        b"fa:statement-trace-source:v1",
                        &output_bytes(&before, &definition(true), at - 1),
                    ),
                    after_source_digest: commitment(
                        b"fa:statement-trace-source:v1",
                        &output_bytes(&after, &definition(true), at),
                    ),
                    entries,
                    changes: diff
                        .lines
                        .into_iter()
                        .filter(|line| line.delta.iter().any(|v| *v != 0))
                        .collect(),
                    mapping_changes: Vec::new(),
                }
            })
            .collect();
        VerifiedStatementTrace {
            summary: comparison(self.statement(start), self.statement(end), start, end),
            publications,
        }
    }

    fn verify_with_bodies(
        &self,
        trace: &VerifiedStatementTrace,
        bodies: &[(u64, &[u8])],
    ) -> Result<VerifiedReport, ReportError> {
        let docs = registries();
        let mut sources = Vec::new();
        let mut package = None;
        for at in trace.summary.before_known_at..=trace.summary.after_known_at {
            let (bundle, signed, _) = pack_at(
                &self.records,
                &definition(true),
                &output_bytes(&self.statement(at), &definition(true), at),
                &docs,
                closure(&docs),
                at,
            );
            sources.push(certificate_bytes(&bundle).to_vec());
            package = Some((bundle, signed));
        }
        let (bundle, anchor) = package.unwrap();
        let (certificate, pin) = trace_outer(&sources, &trace_output(trace));
        let bundle = with_bodies(&replace_certificate(&bundle, &certificate), bodies);
        verify_statement_fixture(&bundle, anchor, pin)
    }

    fn verify(&self, trace: &VerifiedStatementTrace) -> Result<VerifiedReport, ReportError> {
        let bodies: Vec<_> = self
            .bodies
            .iter()
            .map(|(i, body)| (*i, body.as_slice()))
            .collect();
        self.verify_with_bodies(trace, &bodies)
    }
}

#[test]
fn migrated_trace_reconstructs_finalize_visibility_and_retains_original_recording_dates() {
    for sole in [false, true] {
        let fixture = MigrationFixture::new(sole);
        let expected = fixture.trace(2, FINALIZE);
        let verified = fixture.verify(&expected).unwrap();
        assert_eq!(verified.statement_trace.as_ref(), Some(&expected));
        assert_eq!(verified.output, trace_output(&expected));
        assert_eq!(verified.known_at, FINALIZE);
        assert_eq!(verified.checkpoint.checkpoint.through_seq, 10);
        assert!(
            expected.publications[..6]
                .iter()
                .all(|step| step.changes.is_empty())
        );
        let finalization = expected.publications.last().unwrap();
        let visible: Vec<_> = finalization
            .entries
            .iter()
            .filter(|entry| entry.event == VerifiedStatementEntryEvent::BecameVisible)
            .collect();
        assert_eq!(visible.len(), if sole { 2 } else { 1 });
        assert!(visible.iter().all(|entry| entry.recorded_at < FINALIZE));
        assert!(
            visible
                .iter()
                .all(|entry| entry.migration_run == Some(run(b"trace-a")))
        );
        assert_eq!(
            finalization
                .changes
                .iter()
                .find(|line| line.code == "net_income")
                .unwrap()
                .delta,
            [70, if sole { 40 } else { 0 }]
        );
    }
}

#[test]
fn migrated_trace_historical_frontiers_preserve_staging_abandonment_and_zero_effect_controls() {
    let fixture = MigrationFixture::new(false);
    for (start, end) in [(2, 3), (2, 8), (5, 8), (8, 9), (9, 9)] {
        let trace = fixture.trace(start, end);
        // Before either staged chunk, no run body belongs to the selected
        // report closure even though the later authenticated prefix has them.
        let bodies: Vec<_> = fixture
            .bodies
            .iter()
            .filter(|(index, _)| if *index == 2 { end >= 4 } else { end >= 7 })
            .map(|(index, body)| (*index, body.as_slice()))
            .collect();
        let verified = fixture.verify_with_bodies(&trace, &bodies).unwrap();
        assert_eq!(verified.statement_trace, Some(trace.clone()));
        if end < FINALIZE {
            assert!(
                trace
                    .publications
                    .iter()
                    .all(|step| step.changes.is_empty())
            );
            assert!(
                trace
                    .publications
                    .iter()
                    .flat_map(|step| &step.entries)
                    .all(|entry| entry.event == VerifiedStatementEntryEvent::Recorded)
            );
        }
    }
}

#[test]
fn migrated_trace_refuses_resealed_false_omitted_reordered_and_rebound_attribution() {
    let fixture = MigrationFixture::new(false);
    let original = fixture.trace(2, FINALIZE);
    for mutation in 0..10 {
        let mut changed = original.clone();
        let finalization = changed.publications.last_mut().unwrap();
        let visible = finalization
            .entries
            .iter()
            .position(|entry| entry.event == VerifiedStatementEntryEvent::BecameVisible)
            .unwrap();
        match mutation {
            0 => {
                finalization.entries.remove(visible);
            }
            1 => finalization.entries.swap(0, 1),
            2 => finalization.entries[visible].event = VerifiedStatementEntryEvent::Recorded,
            3 => finalization.entries[visible].recorded_at = FINALIZE,
            4 => finalization.entries[visible].migration_run = Some(run(b"trace-b")),
            5 => finalization.entries[visible].migration_run = None,
            6 => finalization
                .entries
                .push(fixture.link(7, VerifiedStatementEntryEvent::BecameVisible)),
            7 => finalization
                .entries
                .push(fixture.link(4, VerifiedStatementEntryEvent::BecameVisible)),
            8 => finalization.entries[visible].digest[0] ^= 1,
            9 => changed.publications[0].entries[0].migration_run = Some(run(b"trace-b")),
            _ => unreachable!(),
        }
        let error = fixture.verify(&changed).unwrap_err();
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
fn migrated_trace_requires_original_run_bodies_and_counting_policy() {
    let fixture = MigrationFixture::new(false);
    let trace = fixture.trace(2, FINALIZE);
    assert!(fixture.verify_with_bodies(&trace, &[]).is_err());
    let mut changed = fixture.bodies[0].1.clone();
    *changed.last_mut().unwrap() = 1; // A genuine change of counting policy.
    assert!(
        fixture
            .verify_with_bodies(&trace, &[(2, &changed), (5, &fixture.bodies[1].1)])
            .is_err()
    );
    assert!(
        fixture
            .verify_with_bodies(
                &trace,
                &[(5, &fixture.bodies[1].1), (2, &fixture.bodies[0].1)]
            )
            .is_err()
    );
}
