use super::*;
use crate::statement_trace::acceptance::{Harness, PRINCIPAL, cap, day};
use crate::statement_trace::{StatementEntryEvent, StatementPublication};
use fa_model::symbols::{property, relation};
use fgdb::{WriteBatch, WriteMismatchPolicy};
use fgdb_types::CanonicalScalar;

fn certify(h: &Harness, request: &StatementTraceRequest) -> CertifiedStatementTrace {
    h.book
        .certify_statement_trace(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
        .unwrap()
        .unwrap()
}

fn replay(h: &Harness, certificate: &StatementTraceCertificate) -> StatementTrace {
    h.book
        .replay_statement_trace(&h.cx(), PRINCIPAL, &cap(&["read"]), certificate)
        .unwrap()
        .unwrap()
}

fn reseal(source: &StatementTraceCertificate, output: Vec<u8>) -> StatementTraceCertificate {
    StatementTraceCertificate::seal(
        source.sources.clone(),
        source.producer,
        source.capability_commitment,
        output,
    )
    .unwrap()
}

fn assert_false_trace(h: &Harness, certificate: &StatementTraceCertificate) {
    // Public checksums can honestly commit to a false assertion. Only replay
    // of every native source and publication can reject that assertion.
    let bytes = certificate.canonical_bytes().unwrap();
    let decoded = StatementTraceCertificate::decode(&bytes).unwrap();
    let refusal = h
        .book
        .replay_statement_trace(&h.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
    assert_eq!(refusal.exit, exit::VERIFICATION);
}

#[test]
fn every_intermediate_source_replays_after_reopen_and_later_postings() {
    let mut h = Harness::new();
    h.initial();
    let before = h.head();
    h.post("plus", "2026-03-15", h.usd, ("cash", "sales"), 15, false);
    h.post("minus", "2026-03-15", h.usd, ("sales", "cash"), 15, false);
    h.post("pending", "2026-03-15", h.usd, ("cash", "capital"), 5, true);
    let after = h.head();
    let request = h.request(before, "balance-sheet");
    let certified = certify(&h, &request);
    assert!(certified.report.summary().is_unchanged());
    assert!(certified.report.had_changes());
    assert_eq!(certified.certificate.sources().len(), 4);
    for (offset, source) in certified.certificate.sources().iter().enumerate() {
        assert_eq!(source.known_at.0, before.0 + offset as u64);
        assert_eq!(
            source.selection,
            certified.certificate.sources()[0].selection
        );
    }
    assert_eq!(certified.report, h.trace(&request));
    assert_eq!(
        certified.certificate.output(),
        certified.report.canonical_bytes().unwrap()
    );
    assert_eq!(certified.certificate.producer(), PRINCIPAL);
    assert_eq!(
        *certified.certificate.capability_commitment(),
        cap(&["read", "produce"]).commitment().unwrap()
    );
    let bytes = certified.certificate.canonical_bytes().unwrap();
    let decoded = StatementTraceCertificate::decode(&bytes).unwrap();
    assert_eq!(decoded, certified.certificate);
    assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    assert_eq!(decoded.request().unwrap().comparison.after, Some(after));
    assert_eq!(
        h.head(),
        after,
        "certification and ordinary tracing do not publish"
    );
    let mut h = h.reopen();
    h.post(
        "after-saved-trace",
        "2026-03-20",
        h.usd,
        ("expense", "cash"),
        27,
        false,
    );
    let head = h.head();
    assert_eq!(replay(&h, &decoded), certified.report);
    assert_eq!(h.head(), head);
}

#[test]
fn augmenting_a_saved_comparison_preserves_both_original_endpoint_certificates() {
    let mut h = Harness::new();
    h.initial();
    let before = h.head();
    h.post("prior", "2025-03-20", h.usd, ("expense", "cash"), 10, false);
    h.post(
        "current",
        "2026-03-20",
        h.eur,
        ("expense", "cash"),
        7,
        false,
    );
    let request = h.request(before, "balance-sheet");
    let diff = h
        .book
        .certify_statement_diff(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &request.comparison,
        )
        .unwrap()
        .unwrap();
    let after = h.head();
    h.post(
        "new-head",
        "2026-03-21",
        h.usd,
        ("expense", "cash"),
        99,
        false,
    );
    let head = h.head();
    let trace = h
        .book
        .certify_statement_trace_from_diff(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &diff.certificate,
            2,
        )
        .unwrap()
        .unwrap();
    let (old, new) = diff.certificate.sources();
    assert_eq!(
        trace
            .certificate
            .sources()
            .first()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        old.canonical_bytes().unwrap()
    );
    assert_eq!(
        trace
            .certificate
            .sources()
            .last()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        new.canonical_bytes().unwrap()
    );
    assert_eq!(trace.report.summary(), &diff.report);
    assert_eq!(trace.report.summary().after().known_at, after.0);
    assert_eq!(replay(&h, &trace.certificate), trace.report);
    assert!(
        h.book
            .certify_statement_trace_from_diff(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &diff.certificate,
                1
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), head);
}

#[test]
fn dropping_reordering_or_repeating_intermediate_source_certificates_is_refused() {
    let mut h = Harness::new();
    let before = h.head();
    for key in ["first", "second", "third"] {
        h.post(key, "2026-03-20", h.usd, ("cash", "sales"), 1, false);
    }
    let good = certify(&h, &h.request(before, "balance-sheet"));
    let original = good.certificate.sources().to_vec();
    let mut missing = original.clone();
    missing.remove(1);
    let mut repeated = original.clone();
    repeated.insert(1, repeated[1].clone());
    let mut reordered = original.clone();
    reordered.swap(1, 2);
    let endpoints = vec![original[0].clone(), original[3].clone()];
    for chain in [Vec::new(), missing, repeated, reordered, endpoints] {
        assert!(
            StatementTraceCertificate::seal(
                chain,
                PRINCIPAL,
                [0; 32],
                good.certificate.output().to_vec()
            )
            .is_err()
        );
    }
    // A shorter *consecutive* source chain is structurally valid. It still
    // cannot authenticate an output claiming the original complete interval.
    let shorter = StatementTraceCertificate::seal(
        original[..3].to_vec(),
        PRINCIPAL,
        [0; 32],
        good.certificate.output().to_vec(),
    )
    .unwrap();
    assert_false_trace(&h, &shorter);
}

#[test]
fn resealed_false_deltas_omitted_zero_steps_and_rebound_entry_links_fail_semantic_replay() {
    let mut h = Harness::new();
    let before = h.head();
    h.post("plus", "2026-03-20", h.usd, ("cash", "sales"), 15, false);
    h.post("minus", "2026-03-20", h.usd, ("sales", "cash"), 15, false);
    h.post(
        "irrelevant",
        "2026-04-20",
        h.eur,
        ("cash", "capital"),
        5,
        false,
    );
    let certified = certify(&h, &h.request(before, "balance-sheet"));
    let mut false_amount = certified.report.clone();
    false_amount.publications[0].changes[0].delta[0] += 1;
    let mut no_links = certified.report.clone();
    no_links.publications[0].entries.clear();
    let mut false_entry = certified.report.clone();
    false_entry.publications[0].entries[0]
        .entry_ref
        .entry_digest[0] ^= 1;
    let mut false_event = certified.report.clone();
    false_event.publications[0].entries[0].event = StatementEntryEvent::BecameVisible;
    let mut wrong_source = certified.report.clone();
    wrong_source.publications[1].before_source_digest[0] ^= 1;
    let mut omitted_zero = certified.report.clone();
    omitted_zero.publications.pop();
    let mut no_cancellation = certified.report.clone();
    no_cancellation.publications[0].changes.clear();
    no_cancellation.publications[1].changes.clear();
    let head = h.head();
    for forged in [
        false_amount,
        no_links,
        false_entry,
        false_event,
        wrong_source,
        omitted_zero,
        no_cancellation,
    ] {
        assert_false_trace(
            &h,
            &reseal(&certified.certificate, forged.canonical_bytes().unwrap()),
        );
    }
    assert_eq!(h.head(), head);
}

#[test]
fn hostile_frames_and_corrupt_inner_source_checksums_are_rejected_without_replay() {
    let h = Harness::new();
    let good = certify(&h, &h.request(h.head(), "balance-sheet"));
    let bytes = good.certificate.canonical_bytes().unwrap();
    for end in [
        0,
        1,
        4,
        4 + CERTIFICATE_FORMAT.len(),
        bytes.len() / 2,
        bytes.len() - 1,
    ] {
        assert!(StatementTraceCertificate::decode(&bytes[..end]).is_err());
    }
    for at in [0, 4, bytes.len() / 2, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(StatementTraceCertificate::decode(&changed).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(StatementTraceCertificate::decode(&trailing).is_err());
    let count_offset = 4 + CERTIFICATE_FORMAT.len() + 16 + 32;
    for count in [0u32, (MAX_SOURCES + 1) as u32, u32::MAX] {
        let mut hostile = bytes.clone();
        hostile[count_offset..count_offset + 4].copy_from_slice(&count.to_le_bytes());
        assert!(StatementTraceCertificate::decode(&hostile).is_err());
    }
    let mut oversized_source = bytes;
    oversized_source[count_offset + 4..count_offset + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(StatementTraceCertificate::decode(&oversized_source).is_err());
    let mut sources = good.certificate.sources.clone();
    sources[0].output_digest[0] ^= 1;
    assert!(
        StatementTraceCertificate::seal(
            sources,
            PRINCIPAL,
            [0; 32],
            good.certificate.output.clone()
        )
        .is_err()
    );
    assert!(total([MAX_STATEMENT_TRACE_CERTIFICATE_BYTES, 1]).is_err());
    assert!(total([usize::MAX, 1]).is_err());
}

#[test]
fn zero_length_trace_has_one_source_and_can_augment_a_same_frontier_comparison() {
    let h = Harness::new();
    let head = h.head();
    let request = h.request(head, "balance-sheet");
    let good = certify(&h, &request);
    assert_eq!(good.certificate.sources().len(), 1);
    assert!(good.report.publications().is_empty());
    assert!(!good.report.had_changes());
    assert_eq!(replay(&h, &good.certificate), good.report);
    let diff = h
        .book
        .certify_statement_diff(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &request.comparison,
        )
        .unwrap()
        .unwrap();
    let upgraded = h
        .book
        .certify_statement_trace_from_diff(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &diff.certificate,
            1,
        )
        .unwrap()
        .unwrap();
    assert_eq!(upgraded.report, good.report);
    assert_eq!(
        upgraded.certificate.sources()[0],
        *diff.certificate.sources().0
    );
    assert_eq!(h.head(), head);
}

#[test]
fn current_authority_precedes_corrupt_sources_and_provenance_never_grants_access() {
    let mut h = Harness::new();
    let before = h.head();
    h.post("real", "2026-03-20", h.usd, ("cash", "sales"), 15, false);
    let request = h.request(before, "balance-sheet");
    let good = certify(&h, &request);
    // Altered producer provenance remains unsigned. It does not change the
    // trace's arithmetic, nor confer any of that principal's permissions.
    let changed_producer = StatementTraceCertificate::seal(
        good.certificate.sources.clone(),
        VId(42),
        [0x42; 32],
        good.certificate.output.clone(),
    )
    .unwrap();
    assert_eq!(replay(&h, &changed_producer), good.report);
    let cx = h.cx();
    let row = cx
        .query()
        .with_restriction(|| h.book.db.vertex(h.chart_entry))
        .unwrap()
        .unwrap();
    let original = fa_journal::rows::prop(&row, property::FA_PAYLOAD)
        .cloned()
        .unwrap();
    let mut damage = WriteBatch::new(relation::CHILD_OF);
    damage.compare_and_set_vertex_property(
        h.chart_entry,
        property::FA_PAYLOAD,
        Some(original),
        CanonicalScalar::bytes(Vec::new()).unwrap(),
        WriteMismatchPolicy::AbortWrite,
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), damage))
        .unwrap();
    let head = h.head();
    for ops in [&["read"][..], &["produce"][..], &["post"][..]] {
        let refusal = h
            .book
            .certify_statement_trace(&cx, PRINCIPAL, &cap(ops), &request)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
    }
    for (principal, capability) in [(PRINCIPAL, cap(&["produce"])), (VId(42), cap(&["read"]))] {
        let refusal = h
            .book
            .replay_statement_trace(&cx, principal, &capability, &changed_producer)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
    }
    assert!(!matches!(
        h.book
            .replay_statement_trace(&cx, PRINCIPAL, &cap(&["read"]), &good.certificate),
        Ok(Ok(_))
    ));
    let foreign = Harness::in_book(Id128([0x74; 16]));
    let refusal = foreign
        .book
        .replay_statement_trace(&foreign.cx(), PRINCIPAL, &cap(&["read"]), &good.certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, exit::VERIFICATION);
    assert_eq!(h.head(), head);
}

#[test]
fn trace_scope_admission_requires_head_even_for_historical_and_equal_frontiers() {
    fn denied<T: std::fmt::Debug>(outcome: Outcome<T>, caveat: &str) {
        let refusal = outcome.unwrap().unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
        assert_eq!(refusal.exit, exit::SAFETY);
        assert!(refusal.message.contains(caveat), "{refusal:?}");
    }

    let mut h = Harness::new();
    h.initial();
    let before = h.head();
    h.post("plus", "2026-03-15", h.usd, ("cash", "sales"), 15, false);
    h.post("minus", "2026-03-15", h.usd, ("sales", "cash"), 15, false);
    let after = h.head();
    let mut request = h.request(before, "balance-sheet");
    request.comparison.after = Some(after);
    let good = certify(&h, &request);
    let authority = cap(&["read", "produce"]);
    let diff = h
        .book
        .certify_statement_diff(&h.cx(), PRINCIPAL, &authority, &request.comparison)
        .unwrap()
        .unwrap();
    let jsonl = h
        .book
        .statement_trace_jsonl(&h.cx(), PRINCIPAL, &authority, &good.certificate)
        .unwrap()
        .unwrap();
    h.post("later", "2026-03-20", h.usd, ("cash", "sales"), 9, false);
    let head = h.head();
    let cx = h.cx();
    let admitted = authority
        .clone()
        .for_books(&[h.book.context().book_id])
        .unwrap()
        .on_branch(Id128::TRUNK)
        .unwrap();
    let pinned = admitted.clone().known_at_most(head);
    assert_eq!(
        h.book
            .statement_trace(&cx, PRINCIPAL, &admitted, &request)
            .unwrap()
            .unwrap(),
        good.report
    );
    assert_eq!(
        h.book
            .certify_statement_trace(&cx, PRINCIPAL, &admitted, &request)
            .unwrap()
            .unwrap()
            .report,
        good.report
    );
    assert_eq!(
        h.book
            .certify_statement_trace_from_diff(&cx, PRINCIPAL, &admitted, &diff.certificate, 32)
            .unwrap()
            .unwrap()
            .report,
        good.report
    );
    assert_eq!(
        h.book
            .replay_statement_trace(&cx, PRINCIPAL, &admitted, &good.certificate)
            .unwrap()
            .unwrap(),
        good.report
    );
    assert_eq!(
        h.book
            .statement_trace_jsonl(&cx, PRINCIPAL, &admitted, &good.certificate)
            .unwrap()
            .unwrap(),
        jsonl
    );
    let mut equal = request.clone();
    equal.comparison.before = after;
    let unchanged = h
        .book
        .certify_statement_trace(&cx, PRINCIPAL, &admitted, &equal)
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.certificate.sources().len(), 1);
    assert!(unchanged.report.publications().is_empty());
    assert_eq!(
        h.book
            .replay_statement_trace(&cx, PRINCIPAL, &admitted, &unchanged.certificate)
            .unwrap()
            .unwrap(),
        unchanged.report
    );
    denied(
        h.book.statement_trace(&cx, PRINCIPAL, &pinned, &equal),
        "known_at",
    );
    denied(
        h.book
            .certify_statement_trace(&cx, PRINCIPAL, &pinned, &equal),
        "known_at",
    );
    denied(
        h.book
            .replay_statement_trace(&cx, PRINCIPAL, &pinned, &unchanged.certificate),
        "known_at",
    );

    for (caveat, scoped) in [
        (
            "accounts",
            authority.clone().for_accounts(&["cash"]).unwrap(),
        ),
        (
            "periods",
            authority
                .clone()
                .for_periods(&["FY2025-P03", "FY2026-P03"])
                .unwrap(),
        ),
        (
            "effective",
            authority.clone().effective_through(day("2026-03-31")),
        ),
        ("known_at", pinned.clone()),
        (
            "branch",
            authority.clone().on_branch(Id128([0xd3; 16])).unwrap(),
        ),
        (
            "books",
            authority.clone().for_books(&[Id128([0xf3; 16])]).unwrap(),
        ),
    ] {
        denied(
            h.book.statement_trace(&cx, PRINCIPAL, &scoped, &request),
            caveat,
        );
        denied(
            h.book
                .certify_statement_trace(&cx, PRINCIPAL, &scoped, &request),
            caveat,
        );
        denied(
            h.book.certify_statement_trace_from_diff(
                &cx,
                PRINCIPAL,
                &scoped,
                &diff.certificate,
                32,
            ),
            caveat,
        );
        denied(
            h.book
                .replay_statement_trace(&cx, PRINCIPAL, &scoped, &good.certificate),
            caveat,
        );
        denied(
            h.book
                .statement_trace_jsonl(&cx, PRINCIPAL, &scoped, &good.certificate),
            caveat,
        );
        let mut damaged = good.certificate.clone();
        damaged.sources[1].output_digest[0] ^= 1;
        denied(
            h.book
                .replay_statement_trace(&cx, PRINCIPAL, &scoped, &damaged),
            caveat,
        );
        denied(
            h.book
                .statement_trace_jsonl(&cx, PRINCIPAL, &scoped, &damaged),
            caveat,
        );
    }
    let mut at_head = request.clone();
    at_head.comparison.after = None;
    denied(
        h.book.statement_trace(&cx, PRINCIPAL, &pinned, &at_head),
        "known_at",
    );
    denied(
        h.book
            .certify_statement_trace(&cx, PRINCIPAL, &pinned, &at_head),
        "known_at",
    );
    let mut reversed = request.clone();
    reversed.comparison.before = head;
    denied(
        h.book.statement_trace(&cx, PRINCIPAL, &pinned, &reversed),
        "known_at",
    );
    denied(
        h.book
            .certify_statement_trace(&cx, PRINCIPAL, &pinned, &reversed),
        "known_at",
    );
    // Malformed intermediate sources do not waive current integrity reach,
    // even when every explicitly named sequence falls within the pin.
    let mut moved = good.certificate.clone();
    moved.sources[1].known_at = head;
    assert_eq!(moved.sources.last().unwrap().known_at, after);
    denied(
        h.book
            .replay_statement_trace(&cx, PRINCIPAL, &pinned, &moved),
        "known_at",
    );
    denied(
        h.book
            .statement_trace_jsonl(&cx, PRINCIPAL, &pinned, &moved),
        "known_at",
    );
    for mut damaged in [good.certificate.clone(), unchanged.certificate] {
        damaged.digest[0] ^= 1;
        assert_eq!(
            h.book
                .replay_statement_trace(&cx, PRINCIPAL, &admitted, &damaged)
                .unwrap()
                .unwrap_err()
                .code,
            crate::certificate::code::CERTIFICATE_INVALID
        );
    }
    let mut damaged = good.certificate.clone();
    damaged.sources[1].output_digest[0] ^= 1;
    assert_eq!(
        h.book
            .replay_statement_trace(&cx, PRINCIPAL, &admitted, &damaged)
            .unwrap()
            .unwrap_err()
            .code,
        crate::certificate::code::CERTIFICATE_INVALID
    );
    assert_eq!(
        h.book
            .replay_statement_trace(
                &cx,
                PRINCIPAL,
                &admitted.expiring_at(head),
                &good.certificate
            )
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-014"
    );
    assert_eq!(h.head(), head);
}

#[test]
fn native_source_and_trace_encoding_lengths_include_all_frames_and_optional_metadata() {
    let mut h = Harness::new();
    let before = h.head();
    h.post("change", "2026-03-20", h.usd, ("cash", "sales"), 15, false);
    let good = certify(&h, &h.request(before, "balance-sheet"));
    let mut length = 92 + CERTIFICATE_FORMAT.len() + good.certificate.output().len();
    for source in good.certificate.sources() {
        length += 4 + source.canonical_bytes().unwrap().len();
    }
    assert_eq!(length, good.certificate.canonical_bytes().unwrap().len());
    let step: &StatementPublication = &good.report.publications()[0];
    assert_eq!(step.entries[0].recorded_at, step.recorded_at);
    assert!(step.entries[0].posting_date.is_some());
    assert_eq!(
        good.report.encoded_len().unwrap(),
        good.report.canonical_bytes().unwrap().len()
    );
}
