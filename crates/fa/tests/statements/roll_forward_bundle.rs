//! Real native lead-schedule export, followed by independent prefix replay.
//! Matching opening and closing balances cannot hide omitted offsetting legs.

use super::*;

fn produce(book: &mut Book, certificate: &fa::RollForwardCertificate) -> fa::ProducedBundle {
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    let checkpoint = book.checkpoint(PRINCIPAL, &capability).unwrap().unwrap();
    let state = checkpoint.checkpoint.checkpoint.body.state_oid;
    let before = book.head().unwrap();
    let produced = book
        .produce_roll_forward_bundle(PRINCIPAL, &capability, Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    let repeated = book
        .produce_roll_forward_bundle(PRINCIPAL, &capability, Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(produced.bundle.bytes, repeated.bundle.bytes);
    assert_eq!(produced.receipt, repeated.receipt);
    assert_eq!(
        book.head().unwrap(),
        before,
        "lead-schedule export is a read"
    );
    produced
}

fn verify(
    book: &Book,
    certificate: &fa::RollForwardCertificate,
    produced: &fa::ProducedBundle,
) -> fa_verify::report::VerifiedReport {
    let key = book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        Some(certificate.digest()),
    )
    .expect("the complete signed prefix independently reproduces the lead schedule");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.certificate_digest, *certificate.digest());
    assert_eq!(verified.known_at, certificate.known_at().0);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.receipt.is_some());
    assert!(verified.rows.is_empty());
    assert!(verified.statement.is_none());
    assert!(verified.open_items.is_none());
    assert!(verified.aging.is_none());
    assert!(verified.time_selection.is_none());
    let roll_forward = verified
        .roll_forward
        .as_ref()
        .expect("lead schedule result");
    assert_eq!(
        roll_forward.source_certificate_digest,
        certificate.source_certificate().digest
    );
    assert_eq!(
        roll_forward.effective_from,
        certificate.request().effective_from.0
    );
    assert_eq!(
        roll_forward.effective_through,
        certificate.request().effective_through.0
    );
    assert_eq!(
        verified.effective_through,
        Some(certificate.request().effective_through.0)
    );
    verified
}

fn request(fixture: &Fixture, accounts: &[&str], units: &[UnitId]) -> fa::RollForwardRequest {
    fa::RollForwardRequest {
        accounts: accounts
            .iter()
            .map(|code| account_vid(fixture.book.context().book_id, code))
            .collect(),
        units: units.iter().map(|unit| unit.0).collect(),
        label: "Cash and capital lead schedule".into(),
        effective_from: day(2026, 2, 1),
        effective_through: day(2026, 2, 28),
        known_at: Some(fixture.book.head().unwrap()),
    }
}

fn reverse(fixture: &mut Fixture, target: fa_model::EntryRef, date: DateDay, key: &[u8]) -> Posted {
    let (source, _) = fixture.book.read_entry(target.vid).unwrap().unwrap();
    let mut legs = source.proposal.legs.clone();
    for leg in &mut legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
        leg.settles.clear();
    }
    let mut proposal = fixture.proposal(date, key, EntryClass::REVERSAL, legs);
    proposal.supersession = vec![fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    fixture.commit(proposal)
}

#[test]
fn native_roll_forward_bundles_preserve_historical_stock_every_movement_and_zero_cells() {
    let mut fixture = Fixture::new(0x91);
    let (usd, jpy) = (fixture.usd, fixture.jpy);
    let cash = account_vid(fixture.book.context().book_id, "1000").0;
    let unused = account_vid(fixture.book.context().book_id, "3000").0;
    fixture.transfer(
        day(2026, 1, 10),
        b"rf-opening-usd",
        usd,
        ("1000", "4000"),
        1_000,
    );
    fixture.transfer(
        day(2026, 1, 10),
        b"rf-opening-jpy",
        jpy,
        ("1000", "4000"),
        500,
    );
    fixture.transfer(day(2026, 2, 2), b"rf-inflow", usd, ("1000", "4000"), 500);
    fixture.transfer(day(2026, 2, 3), b"rf-outflow", usd, ("2000", "1000"), 200);
    let corrected = fixture.transfer(day(2026, 2, 4), b"rf-corrected", usd, ("1000", "4000"), 75);
    let reversal = reverse(
        &mut fixture,
        corrected.entry_ref(),
        day(2026, 2, 5),
        b"rf-reversal",
    );
    let offset_in = fixture.transfer(day(2026, 2, 6), b"rf-offset-in", usd, ("1000", "4000"), 40);
    let offset_out = fixture.transfer(day(2026, 2, 7), b"rf-offset-out", usd, ("2000", "1000"), 40);
    fixture.transfer(
        day(2026, 2, 8),
        b"rf-jpy-movement",
        jpy,
        ("1000", "4000"),
        200,
    );
    let mut pending = fixture.proposal(
        day(2026, 2, 9),
        b"rf-reservation",
        EntryClass::PENDING,
        fixture.legs(usd, ("6000", "1000"), 200),
    );
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let hold = fixture.commit(pending);
    let future = fixture.transfer(day(2026, 3, 1), b"rf-future", usd, ("1000", "4000"), 999);
    let request = request(&fixture, &["3000", "1000"], &[jpy, usd]);
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let certified = fixture
        .book
        .certify_roll_forward(PRINCIPAL, &capability, &request)
        .unwrap()
        .unwrap();
    let later = fixture.transfer(
        day(2026, 2, 1),
        b"rf-later-backdated",
        usd,
        ("1000", "4000"),
        900,
    );
    let produced = produce(&mut fixture.book, &certified.certificate);
    let verified = verify(&fixture.book, &certified.certificate, &produced);
    let lead = verified.roll_forward.as_ref().unwrap();
    assert_eq!(
        lead.rows.len(),
        4,
        "explicit zero account/unit cells are retained"
    );
    assert_eq!(lead.movements.len(), 7);
    let row = |account, unit| {
        lead.rows
            .iter()
            .find(|row| row.account_id == account && row.unit_id == unit)
            .unwrap()
    };
    assert_eq!(
        (
            row(cash, usd.0).opening,
            row(cash, usd.0).net_change,
            row(cash, usd.0).closing
        ),
        (1_000, 300, 1_300)
    );
    assert_eq!(
        (
            row(cash, jpy.0).opening,
            row(cash, jpy.0).net_change,
            row(cash, jpy.0).closing
        ),
        (500, 200, 700)
    );
    for unit in [usd, jpy] {
        assert_eq!(
            (
                row(unused, unit.0).opening,
                row(unused, unit.0).net_change,
                row(unused, unit.0).closing
            ),
            (0, 0, 0)
        );
        assert!(
            row(unused, unit.0)
                .activity
                .iter()
                .all(|amount| *amount == 0)
        );
    }
    for selected in [offset_in, offset_out, reversal] {
        assert!(
            lead.movements
                .iter()
                .any(|movement| movement.entry_digest == selected.entry_ref().entry_digest)
        );
    }
    for excluded in [hold, future, later] {
        assert!(
            !lead
                .movements
                .iter()
                .any(|movement| movement.entry_digest == excluded.entry_ref().entry_digest)
        );
    }
    assert!(
        lead.buckets
            .iter()
            .any(|bucket| bucket.class == EntryClass::REVERSAL.0
                && bucket.reason_code == "supersession:1")
    );
    assert!(
        lead.movements
            .iter()
            .all(|movement| movement.recorded_seq <= certified.certificate.known_at().0)
    );

    let key = fixture.book.checkpoint_public_key();
    assert!(
        fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            Some(&certified.certificate.source_certificate().digest),
        )
        .is_err(),
        "the nested closing-stock digest is not the recipient's schedule pin"
    );
    assert!(fa_verify::report::verify_report_expected(
        &produced.bundle.bytes, &[key], None, None, None,
    ).is_err(), "outer selectors and the unit universe need input authority");
    let pinned = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        None,
        None,
        Some(certified.certificate.digest()),
    )
    .unwrap();
    assert_eq!(pinned.output, certified.certificate.output());
    assert!(pinned.receipt.is_none());
}

fn reseal(certificate: &fa::RollForwardCertificate, output: &[u8]) -> fa::RollForwardCertificate {
    let request = certificate.request();
    let source = certificate.source_certificate().canonical_bytes().unwrap();
    let mut writer = fa_model::Writer::new();
    writer
        .bytes(fa::ROLL_FORWARD_CERTIFICATE_FORMAT)
        .bytes(&source)
        .list(&request.accounts, |writer, account| {
            writer.u128(account.0);
        })
        .list(&request.units, |writer, unit| {
            writer.u32(*unit);
        })
        .str(&request.label)
        .i32(request.effective_from.0)
        .i32(request.effective_through.0)
        .bytes(output);
    let mut bytes = writer.finish().unwrap();
    let digest = fa_model::domain_digest(b"fa:roll-forward-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    fa::RollForwardCertificate::decode(&bytes).unwrap()
}

fn replace_outer(bundle: &[u8], certificate: &fa::RollForwardCertificate) -> Vec<u8> {
    let at = 4 + fa_notary::report::REPORT_BUNDLE_FORMAT.len() + 4;
    let old_len = u32::from_le_bytes(bundle[at..at + 4].try_into().unwrap()) as usize;
    let outer = certificate.canonical_bytes().unwrap();
    let mut bytes = bundle[..at].to_vec();
    bytes.extend_from_slice(&u32::try_from(outer.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&outer);
    bytes.extend_from_slice(&bundle[at + 4 + old_len..]);
    bytes
}

#[test]
fn native_roll_forward_exports_refuse_resealed_offsetting_omissions_and_bucket_changes() {
    let mut fixture = Fixture::new(0x92);
    let usd = fixture.usd;
    fixture.transfer(
        day(2026, 1, 10),
        b"rf-proof-opening",
        usd,
        ("1000", "4000"),
        100,
    );
    fixture.transfer(day(2026, 2, 2), b"rf-proof-in", usd, ("1000", "4000"), 50);
    fixture.transfer(day(2026, 2, 3), b"rf-proof-out", usd, ("2000", "1000"), 50);
    let request = request(&fixture, &["1000"], &[usd]);
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let certified = fixture
        .book
        .certify_roll_forward(PRINCIPAL, &capability, &request)
        .unwrap()
        .unwrap();
    assert_eq!(
        certified.report.rows[0].opening,
        certified.report.rows[0].closing
    );
    assert_eq!(certified.report.movements.len(), 2);
    let produced = produce(&mut fixture.book, &certified.certificate);
    verify(&fixture.book, &certified.certificate, &produced);

    let mut omitted = certified.report.clone();
    omitted.movements.clear();
    let mut relabeled = certified.report.clone();
    relabeled.buckets[0].reason_code = "supersession:999".into();
    relabeled.buckets[0].rule_digest = Some([0x99; 32]);
    for movement in &mut relabeled.movements {
        movement.bucket = relabeled.buckets[0].clone();
    }
    let before = fixture.book.head().unwrap();
    let key = fixture.book.checkpoint_public_key();
    for changed in [omitted, relabeled] {
        let forged = reseal(&certified.certificate, &changed.canonical_bytes().unwrap());
        let refusal = fixture
            .book
            .produce_roll_forward_bundle(PRINCIPAL, &capability, None, &forged)
            .unwrap()
            .unwrap_err();
        assert!(refusal.message.contains("did not replay"));
        assert_eq!(fixture.book.head().unwrap(), before);
        // Re-pin the resealed outer bytes and omit the stale receipt. The
        // authenticated source remains valid, so only actual schedule replay
        // can detect the omitted net-zero movements or invented bucket facts.
        assert!(
            fa_verify::report::verify_report_expected(
                &replace_outer(&produced.bundle.bytes, &forged),
                &[key],
                None,
                None,
                Some(forged.digest()),
            )
            .is_err()
        );
    }
}

#[test]
fn roll_forward_bundle_production_requires_current_whole_book_read_and_produce() {
    let mut fixture = Fixture::new(0x93);
    let request = request(&fixture, &["1000"], &[fixture.usd]);
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let certificate = fixture
        .book
        .certify_roll_forward(PRINCIPAL, &capability, &request)
        .unwrap()
        .unwrap()
        .certificate;
    let before_checkpoint = fixture.book.head().unwrap();
    assert!(
        fixture
            .book
            .produce_roll_forward_bundle(PRINCIPAL, &capability, None, &certificate)
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert_eq!(fixture.book.head().unwrap(), before_checkpoint);
    let produced = produce(&mut fixture.book, &certificate);
    verify(&fixture.book, &certificate, &produced);
    let before = fixture.book.head().unwrap();
    for denied in [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["produce"]).unwrap(),
        capability.clone().for_accounts(&["1000"]).unwrap(),
        capability.clone().for_periods(&[FEBRUARY]).unwrap(),
        capability.clone().effective_through(day(2026, 2, 28)),
        capability
            .clone()
            .known_at_most(CommitSeq(certificate.known_at().0 - 1)),
        capability.clone().known_at_most(before),
        capability.clone().for_books(&[Id128([0xff; 16])]).unwrap(),
        capability.clone().expiring_at(before),
    ] {
        assert!(
            fixture
                .book
                .produce_roll_forward_bundle(PRINCIPAL, &denied, None, &certificate)
                .unwrap()
                .is_err()
        );
        assert_eq!(fixture.book.head().unwrap(), before);
    }
    assert!(
        fixture
            .book
            .produce_roll_forward_bundle(VId(99), &capability, None, &certificate)
            .unwrap()
            .is_err()
    );
    let mut foreign = Fixture::new(0x94);
    let foreign_before = foreign.book.head().unwrap();
    // Even a pin covering the current head is narrower than the direct
    // certificate replay contract. Reject its authority before inspecting
    // the foreign source certificate, which would otherwise refuse with 3.
    let covering_pin = capability.clone().known_at_most(foreign_before);
    let refusal = foreign
        .book
        .produce_roll_forward_bundle(PRINCIPAL, &covering_pin, None, &certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, fa_journal::exit::SAFETY, "{refusal:?}");
    assert_eq!(foreign.book.head().unwrap(), foreign_before);
    assert!(
        foreign
            .book
            .produce_roll_forward_bundle(PRINCIPAL, &capability, None, &certificate)
            .unwrap()
            .is_err()
    );
    assert_eq!(foreign.book.head().unwrap(), foreign_before);
    assert_eq!(fixture.book.head().unwrap(), before);
}
