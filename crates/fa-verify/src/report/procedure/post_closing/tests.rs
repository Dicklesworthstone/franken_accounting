//! Handcrafted observations and canonical controls, independent of the native
//! producer. Producer-created certificates are exercised in fa's tests.

use super::super::{
    Certificate, EntryPeriod, Registry, VerifiedProcedureParameters, decode, recompute_version,
    replay,
};
use super::*;
use crate::blake3::hash_parts;
use crate::codec::Writer;
use crate::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};

const BOOK: [u8; 16] = [3; 16];
const PROFILE: VerifiedProcedureParameters = VerifiedProcedureParameters::PostClosing;

fn registry() -> Registry {
    Registry {
        unit_scales: BTreeMap::from([(1, 2)]),
        unit_currencies: BTreeMap::from([(1, 840)]),
        account_types: BTreeMap::new(),
        trace: None,
        policy_oid: [7; 32],
    }
}

fn posting(identity: u128, recorded_at: u64, period: &str) -> Entry {
    Entry {
        identity,
        digest: hash_parts(b"post-closing-test", &[&identity.to_le_bytes()]),
        recorded_at,
        effective: Some(5),
        class: 1,
        legs: vec![(1, 100), (1, 100)],
        leg_accounts: vec![(1, true), (2, false)],
        supersession: Vec::new(),
        settlements: Vec::new(),
        period: Some(EntryPeriod {
            code: period.into(),
            effective: 5,
            end: 31,
        }),
        transition: None,
    }
}

fn transition(identity: u128, recorded_at: u64, period: &str, to: u8) -> Entry {
    let mut entry = posting(identity, recorded_at, period);
    entry.class = 16;
    entry.legs.clear();
    entry.leg_accounts.clear();
    entry.period = None;
    entry.transition = Some(PeriodTransition {
        period: period.into(),
        to,
    });
    entry
}

fn history() -> Vec<Entry> {
    vec![
        transition(9, 1, "A", 1),
        transition(8, 5, "A", 2),
        transition(7, 7, "A", 1),
        transition(6, 9, "A", 3),
        transition(5, 10, "A", 4),
        transition(4, 3, "B", 1),
        transition(3, 8, "B", 3),
        transition(2, 11, "B", 2),
        transition(1, 4, "C", 1),
        posting(100, 4, "A"),
        posting(101, 5, "A"),
        posting(102, 6, "A"),
        posting(103, 8, "A"),
        posting(104, 12, "A"),
        posting(105, 8, "B"),
        posting(106, 9, "B"),
        posting(107, 12, "C"),
    ]
}

#[test]
fn first_close_survives_reopen_and_work_counts_only_transitions_through_that_close() {
    let (verified, output) =
        recompute_version(BOOK, 12, 1, None, PROFILE, history(), &registry()).unwrap();
    assert_eq!(verified.procedure, "jet.post_closing");
    assert_eq!(
        (
            verified.population,
            verified.live_entries,
            verified.live_legs,
            verified.comparisons
        ),
        (17, 8, 0, 5)
    );
    let observed: Vec<_> = verified
        .findings
        .iter()
        .map(|finding| {
            let VerifiedProcedureStatistic::CommitsAfterClose { period, commits } =
                &finding.statistic
            else {
                panic!("post-closing statistic");
            };
            assert_eq!(finding.severity, 2);
            assert_eq!(finding.population, 8);
            (finding.entry.unwrap(), period.as_str(), *commits)
        })
        .collect();
    assert_eq!(
        observed,
        [(104, "A", 7), (103, "A", 3), (102, "A", 1), (106, "B", 1)]
    );
    assert_eq!(
        verified.findings[0].narrative,
        "recorded 7 commit(s) after the period's first transition to SoftClosed"
    );
    assert_eq!(
        verified.findings[3].narrative,
        "recorded 1 commit(s) after the period's first transition to Closed"
    );
    let mut reversed = history();
    reversed.reverse();
    assert_eq!(
        recompute_version(BOOK, 12, 1, None, PROFILE, reversed, &registry())
            .unwrap()
            .1,
        output
    );

    for (frontier, findings, comparisons) in [(4, 0, 3), (6, 1, 4), (8, 2, 5)] {
        let selected = history()
            .into_iter()
            .filter(|entry| entry.recorded_at <= frontier)
            .collect();
        let (historical, _) =
            recompute_version(BOOK, frontier, 1, None, PROFILE, selected, &registry()).unwrap();
        assert_eq!(historical.findings.len(), findings, "frontier {frontier}");
        assert_eq!(historical.comparisons, comparisons, "frontier {frontier}");
    }
}

#[test]
fn reversal_parity_removes_and_restores_post_closing_findings() {
    let original = posting(200, 3, "A");
    let mut entries = vec![transition(1, 1, "A", 1), transition(2, 2, "A", 2), original];
    for length in 0..8 {
        let (report, _) = recompute_version(
            BOOK,
            3 + length,
            1,
            None,
            PROFILE,
            entries.clone(),
            &registry(),
        )
        .unwrap();
        assert_eq!(report.live_entries, u64::from(length % 2 == 0));
        assert_eq!(report.findings.len(), usize::from(length % 2 == 0));
        assert_eq!(report.comparisons, 2);
        if let Some(finding) = report.findings.first() {
            assert_eq!(finding.entry, Some(200));
            assert_eq!(finding.statistic.value(), 1);
        }
        let previous = entries.last().unwrap();
        let mut reversal = posting(199 - u128::from(length), 4 + length, "A");
        reversal.class = 4;
        reversal
            .supersession
            .push((previous.identity, previous.digest, 1));
        entries.push(reversal);
    }
}

#[test]
fn complete_output_binds_close_distance_citations_work_and_source_selection() {
    let (_, output) =
        recompute_version(BOOK, 12, 1, None, PROFILE, history(), &registry()).unwrap();
    let request = Certificate {
        source: &[],
        registry_digest: [0; 32],
        output: &output,
        digest: [0; 32],
        parameters: PROFILE,
        version: 1,
        book: BOOK,
        known_at: 12,
        effective_through: None,
    };
    for what in [
        "distance",
        "period citation",
        "narrative",
        "work",
        "omitted close",
    ] {
        let mut entries = history();
        match what {
            "distance" => entries[1].recorded_at = 4,
            "period citation" => entries[13].period.as_mut().unwrap().code = "B".into(),
            "narrative" => entries[1].transition.as_mut().unwrap().to = 3,
            "work" => {
                entries.remove(0);
            }
            "omitted close" => {
                entries.remove(1);
            }
            _ => unreachable!(),
        }
        assert_eq!(
            replay(&request, BOOK, 12, entries, &registry())
                .unwrap_err()
                .predicate,
            "procedure_recomputation",
            "{what}"
        );
    }
    for (book, at) in [([4; 16], 12), (BOOK, 11)] {
        assert_eq!(
            replay(&request, book, at, history(), &registry())
                .unwrap_err()
                .predicate,
            "procedure_selection"
        );
    }
    let mut wrong = output.clone();
    *wrong.last_mut().unwrap() ^= 1;
    let forged = Certificate {
        output: &wrong,
        ..request
    };
    assert_eq!(
        replay(&forged, BOOK, 12, history(), &registry())
            .unwrap_err()
            .predicate,
        "procedure_recomputation"
    );
}

#[test]
fn missing_or_malformed_authenticated_facts_cannot_be_silently_ignored() {
    for what in [
        "missing transition",
        "wrong class",
        "unknown state",
        "control legs",
        "missing period",
    ] {
        let mut entries = history();
        match what {
            "missing transition" => entries[1].transition = None,
            "wrong class" => entries[1].class = 17,
            "unknown state" => entries[1].transition.as_mut().unwrap().to = 9,
            "control legs" => entries[1].legs.push((1, 1)),
            "missing period" => entries[13].period = None,
            _ => unreachable!(),
        }
        assert_eq!(
            recompute_version(BOOK, 12, 1, None, PROFILE, entries, &registry())
                .unwrap_err()
                .predicate,
            "procedure_period",
            "{what}"
        );
    }
}

fn framed_certificate(output: &[u8]) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:procedure-certificate:v1")
        .bytes(&[])
        .bytes(&[])
        .fixed(&[0; 32])
        .u128(7)
        .fixed(&[0; 32])
        .bytes(output);
    let digest = hash_parts(
        b"fa:procedure-certificate-digest:v1",
        &[&(w.buf.len() as u32).to_le_bytes(), &w.buf],
    );
    w.fixed(&digest);
    w.buf
}

#[test]
fn profile_is_exactly_v1_without_cutoff_parameters_or_input_handles() {
    for what in [
        "valid",
        "version",
        "evidence",
        "claim",
        "cutoff",
        "parameter",
        "input",
    ] {
        let mut q = Writer::default();
        q.bytes(b"fa:procedure-output:v1")
            .bytes(b"jet.post_closing")
            .u16(if what == "version" { 2 } else { 1 })
            .u8(u8::from(what == "claim"))
            .bytes(if what == "evidence" {
                b"FA-EVID-L02"
            } else {
                b"FA-EVID-L03"
            })
            .fixed(&BOOK)
            .u64(12)
            .u8(u8::from(what == "cutoff"));
        if what == "cutoff" {
            q.i32(30);
        }
        q.count(usize::from(what == "parameter"));
        if what == "parameter" {
            q.bytes(b"window_days").i128(3);
        }
        q.count(usize::from(what == "input"));
        if what == "input" {
            q.bytes(b"untrusted").bytes(b"control");
        }
        let bytes = framed_certificate(&q.buf);
        let result = decode(&bytes);
        if what == "valid" {
            assert_eq!(result.unwrap().parameters, PROFILE);
        } else {
            assert!(result.is_err(), "{what}");
        }
    }
}

struct Record {
    bytes: Vec<u8>,
    len: usize,
    envelope: LeafEnvelope,
}

fn control_record(
    seq: u64,
    class: u16,
    date: i32,
    period: Option<(&str, &str)>,
    control: &[u8],
    origin_kind: u16,
) -> Record {
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(class)
        .i32(date)
        .u8(0)
        .fixed(&[0; 32])
        .u8(0)
        .fixed(&[0; 24])
        .bytes(&[])
        .u8(u8::from(period.is_some()));
    if let Some((calendar, code)) = period {
        w.bytes(calendar.as_bytes()).bytes(code.as_bytes());
    }
    w.count(0)
        .u8(u8::from(!control.is_empty()))
        .fixed(control)
        .count(0)
        .u8(0)
        .bytes(&seq.to_le_bytes())
        .u8(3)
        .u16(origin_kind)
        .fixed(&[0; 32])
        .u128(7)
        .u8(0)
        .count(0)
        .count(0)
        .u8(0)
        .count(0)
        .count(0);
    let len = w.buf.len();
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[]]);
    w.fixed(&proposal_digest).fixed(&digest);
    let envelope = envelope_of_entry(&w.buf, len, seq, 0).unwrap();
    Record {
        bytes: w.buf,
        len,
        envelope,
    }
}

fn birth() -> Record {
    let mut body = Writer::default();
    body.fixed(b"fa:period-creation:v1")
        .bytes(b"cy")
        .i32(2026)
        .count(3);
    for (code, start, end, kind, state) in
        [("A", 0, 31, 0, 0), ("B", 31, 59, 0, 0), ("H", -31, 0, 4, 4)]
    {
        body.bytes(code.as_bytes())
            .i32(2026)
            .u16(1)
            .u8(kind)
            .i32(start)
            .i32(end)
            .u8(state);
    }
    let mut control = Writer::default();
    control.u8(1).u16(13).bytes(&body.buf);
    control_record(1, 17, 0, None, &control.buf, 13)
}

fn period_control(seq: u64, code: &str, from: u8, to: u8, date: i32) -> Record {
    let mut control = Writer::default();
    control
        .u8(0)
        .bytes(b"cy")
        .bytes(code.as_bytes())
        .u8(from)
        .u8(to)
        .u16(1)
        .u8(0);
    control_record(seq, 16, date, Some(("cy", code)), &control.buf, 2)
}

fn parsed(
    records: &[Record],
    known_at: u64,
) -> Result<BTreeMap<usize, PeriodTransition>, ReportError> {
    let envelopes: Vec<_> = records
        .iter()
        .map(|record| record.envelope.clone())
        .collect();
    let payloads: Vec<_> = records
        .iter()
        .map(|record| (record.len, record.bytes.as_slice()))
        .collect();
    let infos = records
        .iter()
        .enumerate()
        .filter(|(_, record)| record.envelope.commit_seq <= known_at)
        .map(|(index, record)| {
            metadata::entry_info(&record.bytes[..record.len], &record.envelope)
                .map(|info| (index, info))
        })
        .collect::<Result<_, _>>()?;
    period_transitions(&BOOK, &envelopes, &payloads, &infos)
}

#[test]
fn original_period_controls_respect_the_certificate_frontier_and_check_later_transitions() {
    let records = vec![
        birth(),
        period_control(2, "A", 0, 1, 0),
        period_control(3, "A", 1, 2, 30),
        period_control(4, "A", 2, 1, 30),
        period_control(5, "A", 1, 3, 30),
        period_control(6, "A", 3, 4, 30),
        period_control(7, "B", 0, 1, 31),
        // A historical period born Locked has no invented first transition.
        period_control(8, "H", 4, 1, -1),
        // Its from-state is forged after the valid first close. A longer signed
        // checkpoint cannot inject it into the older certificate's selection.
        period_control(9, "A", 2, 3, 30),
    ];
    assert_eq!(parsed(&records, 1).unwrap().len(), 0);
    assert_eq!(parsed(&records, 2).unwrap()[&1].to, 1);
    assert_eq!(parsed(&records, 3).unwrap()[&2].to, 2);
    let transitions = parsed(&records, 8).unwrap();
    assert_eq!(transitions.len(), 7);
    assert_eq!(
        transitions[&7],
        PeriodTransition {
            period: "H".into(),
            to: 1
        }
    );
    assert_eq!(
        parsed(&records, 9).unwrap_err().predicate,
        "period_metadata"
    );
    assert!(
        parsed(&records[1..], 2).is_err(),
        "a later period declaration cannot supply an earlier transition"
    );
}

#[test]
fn malformed_control_coordinates_and_state_histories_fail_before_findings() {
    for what in [
        "header calendar",
        "control calendar",
        "header code",
        "missing header",
        "wrong date",
        "wrong from",
        "unknown to",
        "missing control",
        "wrong class",
        "unknown period",
    ] {
        let mut control = Writer::default();
        control
            .u8(0)
            .bytes(if what == "control calendar" {
                b"other"
            } else {
                b"cy"
            })
            .bytes(if what == "unknown period" {
                b"missing"
            } else {
                b"A"
            })
            .u8(if what == "wrong from" { 1 } else { 0 })
            .u8(if what == "unknown to" { 9 } else { 1 })
            .u16(1)
            .u8(0);
        let header = if what == "missing header" {
            None
        } else {
            Some((
                if what == "header calendar" {
                    "other"
                } else {
                    "cy"
                },
                if what == "header code" { "B" } else { "A" },
            ))
        };
        let record = control_record(
            2,
            if what == "wrong class" { 17 } else { 16 },
            if what == "wrong date" { 30 } else { 0 },
            header,
            if what == "missing control" {
                &[]
            } else {
                &control.buf
            },
            2,
        );
        assert!(parsed(&[birth(), record], 2).is_err(), "{what}");
    }
}
