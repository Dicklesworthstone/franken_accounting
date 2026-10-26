//! Independent wire fixtures for full-prefix TimeEvidence selection. Every
//! attack reseals its certificate so failure must come from the claimed law.
use super::*;

pub(super) fn tick(seq: u64, ns: u64, monotonic_ok: bool) -> Record {
    tick_source(seq, ns, monotonic_ok, 0)
}

fn tick_source(seq: u64, ns: u64, monotonic_ok: bool, source: u8) -> Record {
    tick_with_origin_digest(
        seq,
        ns,
        monotonic_ok,
        source,
        hash_parts(b"", &[&ns.to_le_bytes()]),
    )
}

fn tick_with_origin_digest(
    seq: u64,
    ns: u64,
    monotonic_ok: bool,
    source: u8,
    origin_digest: [u8; 32],
) -> Record {
    tick_with_shape(seq, ns, monotonic_ok, source, origin_digest, None)
}

#[derive(Clone, Copy, PartialEq)]
enum MalformedTick {
    Legs,
    UnitTotals,
    Pending,
    EmptyKey,
    LongKey,
}

fn tick_with_shape(
    seq: u64,
    ns: u64,
    monotonic_ok: bool,
    source: u8,
    origin_digest: [u8; 32],
    malformed: Option<MalformedTick>,
) -> Record {
    let key = match malformed {
        Some(MalformedTick::EmptyKey) => Vec::new(),
        Some(MalformedTick::LongKey) => vec![b'k'; 65],
        _ => format!("tick-{seq}").into_bytes(),
    };
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(19)
        .i32(0)
        .u8(0);
    erasable(&mut w);
    w.u8(0)
        .count(usize::from(malformed == Some(MalformedTick::Legs)));
    if malformed == Some(MalformedTick::Legs) {
        w.u8(0)
            .u128(account_id("1000"))
            .u32(1)
            .i128(1)
            .u8(0)
            .count(0)
            .u8(0)
            .count(0);
    }
    w.u8(1)
        .u8(4)
        .u64(ns)
        .u8(source)
        .u8(u8::from(monotonic_ok))
        .count(usize::from(malformed == Some(MalformedTick::UnitTotals)));
    if malformed == Some(MalformedTick::UnitTotals) {
        w.u32(1).i128(1).i128(0);
    }
    w.u8(0)
        .bytes(&key)
        .u8(3)
        .u16(4)
        .fixed(&origin_digest)
        .u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(0);
    w.u8(u8::from(malformed == Some(MalformedTick::Pending)));
    if malformed == Some(MalformedTick::Pending) {
        w.u8(0).u8(0).u8(0);
    }
    w.count(0).count(0);
    let len = w.buf.len();
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    w.fixed(&proposal).fixed(&digest);
    let envelope = if malformed == Some(MalformedTick::Legs) {
        // Keep the hostile, correctly hashed control in the authenticated
        // prefix even though the canonical constructor now rejects its legs.
        // The report verifier must reject it before a later tick retires it.
        assert_eq!(
            crate::envelope::entry_record_digest(&w.buf, len).unwrap(),
            digest
        );
        LeafEnvelope {
            kind: crate::envelope::KIND_ENTRY,
            book_id: BOOK,
            branch_id: [0; 16],
            commit_seq: seq,
            within_commit_ordinal: 0,
            record_digest: digest,
            class: 19,
            effective_day: None,
            account_vids: vec![account_id("1000")],
            unit_ids: vec![1],
        }
    } else {
        envelope_of_entry(&w.buf, len, seq, 0).unwrap()
    };
    Record {
        bytes: w.buf,
        len,
        envelope,
    }
}

fn identity(seq: u64) -> u128 {
    let key = format!("tick-{seq}");
    let mut w = Writer::default();
    w.bytes(&BOOK)
        .bytes(&PRINCIPAL.to_le_bytes())
        .bytes(key.as_bytes());
    let digest = hash_parts(b"fa:vid:entry:v1", &[&w.buf]);
    u128::from_le_bytes(digest[..16].try_into().unwrap())
}

fn observation(seq: u64, ns: u64, corroborated: bool) -> TimeObservation {
    TimeObservation {
        recorded_at: seq,
        observed_utc_ns: ns,
        source: 0,
        monotonic_ok: corroborated,
    }
}

pub(super) fn selection(
    request: u64,
    frontier: u64,
    resolved_seq: u64,
    lower: (u64, u64, bool),
    upper: Option<(u64, u64, bool)>,
) -> VerifiedInstantSelection {
    VerifiedInstantSelection {
        requested_utc_ns: request,
        frontier,
        resolved_seq,
        lower: observation(lower.0, lower.1, lower.2),
        upper: upper.map(|t| observation(t.0, t.1, t.2)),
        lower_entry: identity(lower.0),
        upper_entry: upper.map(|t| identity(t.0)),
    }
}

fn write_observation(w: &mut Writer, tick: TimeObservation) {
    w.u64(tick.recorded_at)
        .u64(tick.observed_utc_ns)
        .u8(tick.source)
        .u8(u8::from(tick.monotonic_ok));
}

pub(super) fn with_time(bytes: &[u8], time: &VerifiedInstantSelection) -> (Vec<u8>, [u8; 32]) {
    let mut r = Reader::new(bytes);
    let format = r.bytes(64, "format").unwrap();
    let major = r.u16("major").unwrap();
    let minor = r.u16("minor").unwrap();
    let certificate = r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap();
    let rest = &bytes[bytes.len() - r.remaining()..];
    let optional_time = certificate.starts_with(STATEMENT_CERTIFICATE_FORMAT)
        || certificate.starts_with(OPEN_ITEMS_CERTIFICATE_FORMAT)
        || certificate.starts_with(DIMENSION_CERTIFICATE_FORMAT);
    let mut cert = Writer::default();
    let end = certificate.len() - 32 - usize::from(optional_time);
    cert.fixed(&certificate[..end]);
    if optional_time {
        cert.u8(1);
    } else {
        cert.buf[..24].copy_from_slice(INSTANT_CERTIFICATE_FORMAT);
    }
    cert.u64(time.requested_utc_ns)
        .u64(time.frontier)
        .u64(time.resolved_seq);
    write_observation(&mut cert, time.lower);
    cert.u8(u8::from(time.upper.is_some()));
    if let Some(tick) = time.upper {
        write_observation(&mut cert, tick);
    }
    cert.u128(time.lower_entry)
        .u8(u8::from(time.upper_entry.is_some()));
    if let Some(identity) = time.upper_entry {
        cert.u128(identity);
    }
    let digest = hash_parts(&cert.buf[..24], &[&cert.buf]);
    cert.fixed(&digest);
    let mut out = Writer::default();
    out.bytes(format)
        .u16(major)
        .u16(minor)
        .bytes(&cert.buf)
        .fixed(rest);
    (out.buf, digest)
}

fn history() -> Vec<Record> {
    let mut records = schema();
    records.extend([
        tick(3, 100, false),
        record(1, 4, 10, b"inside-first-bucket", 100, None, None, None),
        tick(5, 200, true),
        record(1, 6, 10, b"inside-second-bucket", 200, None, None, None),
        tick(7, 300, true),
        record(1, 8, 10, b"inside-open-bucket", 400, None, None, None),
    ]);
    records
}

#[test]
fn instant_trial_balances_recompute_open_closed_and_exact_tick_buckets() {
    let records = history();
    for (time, amount, grade) in [
        (
            selection(150, 4, 4, (3, 100, false), None),
            100,
            "uncorroborated_daemon_clock",
        ),
        (
            selection(150, 8, 4, (3, 100, false), Some((5, 200, true))),
            100,
            "uncorroborated_daemon_clock",
        ),
        (
            selection(200, 8, 6, (5, 200, true), Some((7, 300, true))),
            300,
            "corroborated_daemon_clock",
        ),
        (
            selection(300, 8, 8, (7, 300, true), None),
            700,
            "corroborated_daemon_clock",
        ),
    ] {
        let (bytes, anchor) = bundle(
            &records,
            time.resolved_seq,
            Selection::AsOf(15),
            &rows(amount, 0),
        );
        let (instant, _) = with_time(&bytes, &time);
        let result = verify_fixture(&instant, anchor).unwrap();
        assert_eq!(result.known_at, time.resolved_seq);
        assert_eq!(result.time_selection.as_ref(), Some(&time));
        assert_eq!(result.time_selection.unwrap().source_grade(), grade);
        assert_eq!(result.rows, rows(amount, 0));
    }
}

#[test]
fn resealed_time_tick_origin_digest_must_bind_its_observed_instant() {
    // Both a selected lower bracket and a later tick beyond the requested
    // bucket must retain the TimeTick origin law. Rebuild the record hashes,
    // authenticated prefix and certificate so byte authentication alone passes.
    for (index, sequence, observed_utc_ns, monotonic_ok) in
        [(2, 3, 100_u64, false), (6, 7, 300_u64, true)]
    {
        let mut records = history();
        let mut digest = hash_parts(b"", &[&observed_utc_ns.to_le_bytes()]);
        digest[0] ^= 1;
        records[index] =
            tick_with_origin_digest(sequence, observed_utc_ns, monotonic_ok, 0, digest);
        let time = selection(150, 8, 4, (3, 100, false), Some((5, 200, true)));
        let (bytes, anchor) = bundle(&records, 4, Selection::AsOf(15), &rows(100, 0));
        let (bytes, _) = with_time(&bytes, &time);
        let error = verify_fixture(&bytes, anchor).unwrap_err();
        assert_eq!(error.predicate, "time_history");
        assert!(error.detail.contains("origin digest"), "{error}");
    }
}

#[test]
fn malformed_retired_time_ticks_are_rejected_before_retirement() {
    // Later corroboration retires a valid forward jump; it cannot turn a
    // structurally invalid authenticated entry into admissible TimeEvidence.
    let digest = hash_parts(b"", &[&999_u64.to_le_bytes()]);
    let mut attacks = vec![
        (
            tick_source(4, 999, false, 255),
            "time_history",
            "registered bound",
        ),
        (
            tick_source(4, u64::MAX, false, 0),
            "time_history",
            "registered bound",
        ),
    ];
    attacks.extend(
        [
            (MalformedTick::Legs, "record_derivation", "entry.legs"),
            (MalformedTick::UnitTotals, "time_history", "monetary totals"),
            (MalformedTick::Pending, "time_history", "pending block"),
            (
                MalformedTick::EmptyKey,
                "time_history",
                "key of 1..=64 bytes",
            ),
            (
                MalformedTick::LongKey,
                "time_history",
                "key of 1..=64 bytes",
            ),
        ]
        .into_iter()
        .map(|(shape, predicate, reason)| {
            (
                tick_with_shape(4, 999, false, 0, digest, Some(shape)),
                predicate,
                reason,
            )
        }),
    );
    for (malformed, predicate, reason) in attacks {
        let mut records = schema();
        records.extend([
            tick(3, 100, true),
            malformed,
            record(1, 5, 10, b"between-observations", 100, None, None, None),
            tick(6, 200, true),
            tick(7, 300, true),
        ]);
        let time = selection(150, 7, 5, (3, 100, true), Some((6, 200, true)));
        let (bytes, anchor) = bundle(&records, 5, Selection::AsOf(15), &rows(100, 0));
        let (bytes, _) = with_time(&bytes, &time);
        let error = verify_fixture(&bytes, anchor).unwrap_err();
        assert_eq!(error.predicate, predicate, "{error}");
        assert!(error.detail.contains(reason), "{error}");
    }
}

#[test]
fn resealed_instant_brackets_frontier_and_known_at_must_replay() {
    let records = history();
    let good = selection(150, 8, 4, (3, 100, false), Some((5, 200, true)));
    let (bytes, anchor) = bundle(&records, 4, Selection::AsOf(15), &rows(100, 0));
    for attack in 0..12 {
        let mut time = good.clone();
        match attack {
            0 => time.frontier = 9,
            1 => time.frontier = 3,
            2 => time.resolved_seq = 5,
            3 => time.lower_entry ^= 1,
            4 => time.upper_entry = Some(123),
            5 => time.upper.as_mut().unwrap().observed_utc_ns = 201,
            6 => time.lower.monotonic_ok = true,
            7 => time.lower.source = 1,
            8 => time.requested_utc_ns = 250,
            9 => time.requested_utc_ns = 99,
            10 => time.upper = None,
            11 => {
                time.upper = None;
                time.upper_entry = None;
            }
            _ => unreachable!(),
        }
        let (forged, _) = with_time(&bytes, &time);
        let error = verify_fixture(&forged, anchor.clone()).unwrap_err();
        assert!(
            matches!(error.predicate, "time_selection" | "time_frontier"),
            "attack {attack}: {error}"
        );
    }
    let (wrong_known_at, anchor) = bundle(&records, 6, Selection::AsOf(15), &rows(300, 0));
    let (forged, _) = with_time(&wrong_known_at, &good);
    assert_eq!(
        verify_fixture(&forged, anchor).unwrap_err().predicate,
        "time_selection"
    );
}

#[test]
fn instant_resolution_validates_the_whole_frontier_and_corroborated_corrections() {
    let mut records = schema();
    records.extend([
        tick(3, 100, true),
        tick(4, 999, false),
        record(1, 5, 10, b"between-observations", 100, None, None, None),
        tick(6, 200, true),
        tick(7, 300, true),
    ]);
    let corrected = selection(150, 7, 5, (3, 100, true), Some((6, 200, true)));
    let (bytes, anchor) = bundle(&records, 5, Selection::AsOf(15), &rows(100, 0));
    let (bytes, _) = with_time(&bytes, &corrected);
    assert_eq!(verify_fixture(&bytes, anchor).unwrap().known_at, 5);

    // Before the later corroboration existed, the forward jump was retained.
    let original = selection(150, 5, 3, (3, 100, true), Some((4, 999, false)));
    let (bytes, anchor) = bundle(&records, 3, Selection::AsOf(15), &[]);
    let (bytes, _) = with_time(&bytes, &original);
    assert_eq!(verify_fixture(&bytes, anchor).unwrap().known_at, 3);

    for unsupported in [false, true] {
        records[6] = if unsupported {
            tick_source(7, 300, true, 1)
        } else {
            tick(7, 199, true)
        };
        let (bytes, anchor) = bundle(&records, 5, Selection::AsOf(15), &rows(100, 0));
        let (bytes, _) = with_time(&bytes, &corrected);
        assert_eq!(
            verify_fixture(&bytes, anchor).unwrap_err().predicate,
            "time_history"
        );
        // Malformed observations after the retained frontier cannot rewrite it.
        let (bytes, anchor) = bundle(&records, 3, Selection::AsOf(15), &[]);
        let (bytes, _) = with_time(&bytes, &original);
        assert_eq!(verify_fixture(&bytes, anchor).unwrap().known_at, 3);
    }
}

#[test]
fn instant_histories_refuse_unproved_migration_and_genesis_policy() {
    let mut records = history();
    records.push(record(22, 9, 0, b"migration", 0, None, None, None));
    let time = selection(150, 9, 4, (3, 100, false), Some((5, 200, true)));
    let (bytes, anchor) = bundle(&records, 4, Selection::AsOf(15), &rows(100, 0));
    let (bytes, _) = with_time(&bytes, &time);
    assert_eq!(
        verify_fixture(&bytes, anchor).unwrap_err().predicate,
        "time_genesis_policy"
    );

    let mut historical = Writer::default();
    historical
        .fixed(b"fa:period-creation:v1")
        .bytes(b"cy")
        .i32(2025)
        .count(1)
        .bytes(b"H1")
        .i32(2025)
        .u16(1)
        .u8(4)
        .i32(-31)
        .i32(0)
        .u8(4);
    records[8] = record(
        17,
        9,
        0,
        b"historical",
        0,
        Some((13, &historical.buf)),
        None,
        None,
    );
    let (bytes, anchor) = bundle(&records, 4, Selection::AsOf(15), &rows(100, 0));
    let (bytes, _) = with_time(&bytes, &time);
    assert_eq!(
        verify_fixture(&bytes, anchor).unwrap_err().predicate,
        "time_genesis_policy"
    );
}
