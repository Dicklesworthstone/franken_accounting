//! Search and citation integration over real committed entries/documents.
//! The paired input adapter is supplied explicitly here; original statement
//! parsing and active-match authentication belong to the facade's v4 tests.

use super::*;
use fa_lantern::kiting::{BankTransfer, Kiting, MatchedBankLine};

fn document(h: &mut Harness, kind: &str, contents: String) -> Oid {
    let evidence = fa_registry::evidence_policy::EvidencePolicy::embedded().unwrap();
    let document = Document {
        book_id: h.book.book_id,
        kind: evidence.kind_by_name(kind).unwrap().tag,
        mime: "application/octet-stream".into(),
        grade: 3,
        retrieved_by: PREPARER,
        bytes: contents.into_bytes(),
    };
    let context = h.ctx();
    h.runtime
        .block_on(add_document(&mut h.db, &context, &h.book, &document))
        .unwrap()
        .unwrap();
    document.oid()
}

pub(super) fn fixture() -> (Harness, Snapshot, Vec<VId>) {
    let mut h = harness();
    for code in ["1000", "1010", "1020"] {
        let spec = AccountRoleSpec {
            account: h.account(code),
            role: "cash".into(),
            assigned: true,
        };
        let description = h.seal("bank cycle cash role");
        let context = h.ctx();
        h.runtime
            .block_on(record_account_role(
                &mut h.db,
                &context,
                &h.book,
                &spec,
                PREPARER,
                format!("kiting-role:{code}").as_bytes(),
                description,
                &Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
    }
    let mut specs = Vec::new();
    let mut ids = Vec::new();
    for (index, from, to) in [
        (0, "1000", "1010"),
        (1, "1010", "1020"),
        (2, "1020", "1000"),
    ] {
        let vid = h.post(&Spec::simple(day(2026, 1, 3), to, from, 50_000));
        ids.push(vid);
        let mut matched_line = |side: &str, account: &str, booking, value| MatchedBankLine {
            manifest_oid: document(&mut h, "Workpaper", format!("manifest:{index}:{side}")),
            line_oid: document(&mut h, "Other", format!("line:{index}:{side}")),
            account: h.account(account),
            instrument: format!("instrument-{account}"),
            booking_date: booking,
            value_date: value,
        };
        let source = matched_line("debit", from, day(2026, 1, 3), day(2026, 1, 7));
        let destination = matched_line("credit", to, day(2026, 1, 3), day(2026, 1, 5));
        specs.push((vid, source, destination));
    }
    let mut snapshot = h.snapshot();
    snapshot.bank_transfers = Some(
        specs
            .into_iter()
            .map(|(vid, source, destination)| {
                let entry = snapshot
                    .entries
                    .iter()
                    .find(|entry| entry.vid == vid)
                    .unwrap();
                BankTransfer {
                    entry: entry.entry.entry_ref(vid),
                    source_ordinal: 1,
                    destination_ordinal: 0,
                    source,
                    destination,
                }
            })
            .collect(),
    );
    (h, snapshot, ids)
}

#[test]
fn real_posted_transfer_cycle_cites_every_original_leg_line_manifest_and_account() {
    let (h, snapshot, ids) = fixture();
    let procedure = Kiting::new().unwrap();
    let head = h.db.frontier().unwrap();
    let result = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_eq!(finding.statistic.value, 50_000);
    assert_eq!(finding.statistic.scale, 2);
    assert_eq!(finding.statistic.population, 3);
    assert!(finding.narrative.contains("[2026-01-05, 2026-01-07)"));
    assert!(finding.narrative.contains("does not establish intent"));
    for id in ids {
        assert!(finding.cites.contains(&Cite::Entry(id)));
        for ordinal in [0, 1] {
            assert!(finding.cites.contains(&Cite::Leg { entry: id, ordinal }));
        }
    }
    for transfer in snapshot.bank_transfers.as_ref().unwrap() {
        for line in [&transfer.source, &transfer.destination] {
            assert!(finding.cites.contains(&Cite::Account(line.account)));
            assert!(finding.cites.contains(&Cite::Document(line.line_oid)));
            assert!(finding.cites.contains(&Cite::Document(line.manifest_oid)));
        }
    }
    h.assert_cites_resolve(&result);
    assert!(
        determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );
    let mut reordered = snapshot.with_entries_reversed();
    reordered.bank_transfers.as_mut().unwrap().reverse();
    let repeated = run_over(&reordered, &h.book, &procedure).unwrap();
    assert_eq!(repeated.findings_digest, result.findings_digest);
    assert_eq!(repeated.inputs_digest, result.inputs_digest);
    let row = fa_lantern::bind(Kiting::ID).unwrap();
    let bounds = fa_lantern::Work::registered_bounds(&row.complexity, &snapshot).unwrap();
    assert!(result.work.entries <= bounds.entries);
    assert!(result.work.legs <= bounds.legs);
    assert!(result.work.comparisons <= bounds.comparisons);
    assert_eq!(
        h.db.frontier().unwrap(),
        head,
        "pure procedure publishes nothing"
    );
}

#[test]
fn no_hit_report_still_binds_bank_dates_and_the_declared_effective_cutoff() {
    let (h, mut snapshot, _) = fixture();
    let procedure = Kiting::new().unwrap();
    snapshot.coordinate.effective_through = Some(day(2026, 1, 4));
    let before = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert!(before.findings.is_empty());
    snapshot.bank_transfers.as_mut().unwrap()[0]
        .source
        .value_date = day(2026, 1, 8);
    let changed = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert!(changed.findings.is_empty());
    assert_ne!(before.inputs_digest, changed.inputs_digest);
    assert_ne!(before.findings_digest, changed.findings_digest);
    snapshot.coordinate.effective_through = Some(day(2026, 1, 5));
    assert_eq!(
        run_over(&snapshot, &h.book, &procedure)
            .unwrap()
            .findings
            .len(),
        1
    );
}

#[test]
fn unavailable_sources_repeated_lines_wrong_ordinals_and_foreign_entries_are_refused() {
    let (h, original, _) = fixture();
    let procedure = Kiting::new().unwrap();
    for mutation in 0..6 {
        let mut snapshot = original.clone();
        match mutation {
            0 => snapshot.bank_transfers = None,
            1 => {
                let transfers = snapshot.bank_transfers.as_mut().unwrap();
                transfers[1].source.line_oid = transfers[0].source.line_oid;
            }
            2 => snapshot.bank_transfers.as_mut().unwrap()[0].source_ordinal = 0,
            3 => {
                snapshot.bank_transfers.as_mut().unwrap()[0]
                    .entry
                    .entry_digest[0] ^= 1
            }
            4 => {
                let oid = snapshot.bank_transfers.as_ref().unwrap()[0]
                    .source
                    .manifest_oid;
                snapshot.documents.remove(&oid);
            }
            5 => snapshot.coordinate.book_id = Id128([0xff; 16]),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                run_over(&snapshot, &h.book, &procedure),
                Err(LanternError::Parameter { .. })
            ),
            "mutation {mutation}"
        );
    }
}

#[test]
fn same_day_and_reverse_dated_funding_debits_never_establish_positive_float() {
    let (h, original, _) = fixture();
    let procedure = Kiting::new().unwrap();
    for (booking, value) in [(3, 5), (8, 7)] {
        let mut snapshot = original.clone();
        let transfer = &mut snapshot.bank_transfers.as_mut().unwrap()[0];
        transfer.source.booking_date = day(2026, 1, booking);
        transfer.source.value_date = day(2026, 1, value);
        assert!(
            run_over(&snapshot, &h.book, &procedure)
                .unwrap()
                .findings
                .is_empty()
        );
    }
}

#[test]
fn original_instrument_identity_is_bounded_before_network_construction() {
    let (h, original, _) = fixture();
    let procedure = Kiting::new().unwrap();
    for length in [
        fa_lantern::kiting::MAX_INSTRUMENT_BYTES,
        fa_lantern::kiting::MAX_INSTRUMENT_BYTES + 1,
    ] {
        let mut snapshot = original.clone();
        let account = h.account("1000");
        for transfer in snapshot.bank_transfers.as_mut().unwrap() {
            for line in [&mut transfer.source, &mut transfer.destination] {
                if line.account == account {
                    line.instrument = "I".repeat(length);
                }
            }
        }
        let result = run_over(&snapshot, &h.book, &procedure);
        if length == fa_lantern::kiting::MAX_INSTRUMENT_BYTES {
            assert_eq!(result.unwrap().findings.len(), 1);
        } else {
            assert!(
                matches!(result, Err(LanternError::Parameter { message, .. }) if message.contains("bounded and nonempty"))
            );
        }
    }
}

#[test]
fn transfer_population_refuses_before_duplicate_or_network_expansion() {
    let (h, mut snapshot, _) = fixture();
    let procedure = Kiting::new().unwrap();
    let template = snapshot.bank_transfers.as_ref().unwrap()[0].clone();
    snapshot.bank_transfers = Some(vec![
        template.clone();
        fa_lantern::kiting::MAX_KITING_TRANSFERS
    ]);
    assert!(matches!(
        run_over(&snapshot, &h.book, &procedure),
        Err(LanternError::Parameter { message, .. }) if message.contains("more than once")
    ));
    snapshot.bank_transfers.as_mut().unwrap().push(template);
    assert!(matches!(
        run_over(&snapshot, &h.book, &procedure),
        Err(LanternError::Parameter { message, .. }) if message.contains("population exceeds 100000")
    ));
}

#[test]
fn verified_empty_population_has_a_commitment_and_parameters_have_hard_bounds() {
    let (h, mut snapshot, _) = fixture();
    snapshot.bank_transfers = Some(Vec::new());
    let result = run_over(&snapshot, &h.book, &Kiting::new().unwrap()).unwrap();
    assert!(result.findings.is_empty());
    assert_ne!(result.inputs_digest, snapshot.inputs_digest);
    for (name, lower, upper) in [
        ("window_days", 1, 365),
        ("max_hops", 2, 8),
        ("max_search_steps", 1, 10_000_000),
    ] {
        for value in [lower, upper] {
            let procedure = Kiting::with(
                Params::defaults(Kiting::ID)
                    .unwrap()
                    .set(name, value)
                    .unwrap(),
            );
            assert!(
                run_over(&snapshot, &h.book, &procedure)
                    .unwrap()
                    .findings
                    .is_empty()
            );
        }
        for value in [lower - 1, upper + 1] {
            let procedure = Kiting::with(
                Params::defaults(Kiting::ID)
                    .unwrap()
                    .set(name, value)
                    .unwrap(),
            );
            assert!(matches!(
                run_over(&snapshot, &h.book, &procedure),
                Err(LanternError::Parameter { .. })
            ));
        }
    }
}
