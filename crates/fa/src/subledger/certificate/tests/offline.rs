//! Real native AR/AP certificates cross the independent verifier boundary.
//! Repaired public digests cannot replace the authenticated declaration, party
//! controls, gross accounting columns or complete recorded prefix.

use super::*;
use crate::NativeSubledgerKind;
use fa_journal::{Document, PostRequest, Posted};
use fa_model::{
    ControlPayload, Disposition, Entry, EntryClass, EntryOrigin, EntryPayload, EntryRef,
    EvidenceRef, LegPayload, Oid, PARTY_DIMENSION, PartyKind, PartySpec, Pending, Reader,
    Supersession, SupersessionKind, party_value_vid, party_vid,
};
use fa_money::{Amount, Side, UnitId};
use fa_time::PeriodTransition;
use fa_verify::report::{
    NativeSubledgerRequest as ExpectedSubledger, VerifiedReport, verify_report_expected,
    verify_report_native_subledger_expected,
};

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

fn march() -> DateDay {
    DateDay::from_ymd(2026, 3, 31).unwrap()
}

fn april() -> DateDay {
    DateDay::from_ymd(2026, 4, 20).unwrap()
}

struct Fixture {
    book: Book,
    usd: UnitId,
    eur: UnitId,
    evidence: Vec<EvidenceRef>,
}

impl Fixture {
    fn new() -> Self {
        // Keep the original native certificate fixture and its real AR
        // registration; extend its chart through ordinary journaled controls.
        let (mut book, _, authority) = fixture();
        let usd = book.context().units.lookup("USD").unwrap();
        let eur = book.context().units.lookup("EUR").unwrap();
        let accounts = [
            ("AP", AccountType::LIABILITY, 1),
            ("CASH", AccountType::ASSET, 0),
        ]
        .map(|(code, account_type, normal_balance)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: account_type.0,
            normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        });
        book.install_chart(&accounts, PRINCIPAL, march(), b"portable-chart", &authority)
            .unwrap()
            .unwrap();
        book.create_native_subledger(
            &NativeSubledgerSpec {
                code: "SUPPLIERS".into(),
                name: "Trade payables".into(),
                kind: NativeSubledgerKind::Payables,
                control_account: account_vid(book.context().book_id, "AP"),
            },
            PRINCIPAL,
            march(),
            b"portable-ap",
            &authority,
        )
        .unwrap()
        .unwrap();
        book.create_periods(2026, PRINCIPAL, &authority)
            .unwrap()
            .unwrap();
        for period in ["FY2026-P03", "FY2026-P04"] {
            book.transition_period(
                period,
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                period.as_bytes(),
                &cap(&["close"]),
            )
            .unwrap()
            .unwrap();
        }
        for (code, kind) in [
            ("C-1", PartyKind::Customer),
            ("C-2", PartyKind::Customer),
            ("V-1", PartyKind::Vendor),
        ] {
            let party = PartySpec {
                code: code.into(),
                kind,
                name: book.seal_text(code).unwrap(),
                identifiers: Vec::new(),
                external_ids: Vec::new(),
            };
            book.create_party(&party, PRINCIPAL, march(), code.as_bytes(), &authority)
                .unwrap()
                .unwrap();
        }
        let source = Document {
            book_id: book.context().book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Retained sources for native subledger portable verification".to_vec(),
        };
        book.add_document(&source).unwrap().unwrap();
        Self {
            book,
            usd,
            eur,
            evidence: vec![source.evidence_ref(1)],
        }
    }

    fn request(&self, code: &str, through: DateDay) -> NativeSubledgerRequest {
        NativeSubledgerRequest {
            code: code.into(),
            control_account: account_vid(
                self.book.context().book_id,
                if code == "CUSTOMERS" { "AR" } else { "AP" },
            ),
            effective_through: through,
            known_at: Some(self.book.head().unwrap()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn proposal(
        &self,
        control: &str,
        party: &str,
        side: Side,
        unit: UnitId,
        amount: i128,
        date: DateDay,
        key: &[u8],
    ) -> EntryPayload {
        let mut selected = LegPayload::simple(
            side,
            account_vid(self.book.context().book_id, control),
            Amount::new(unit, amount),
        );
        selected.dimension_set = vec![(
            PARTY_DIMENSION,
            party_value_vid(self.book.context().book_id, party),
        )];
        let legs = vec![
            selected,
            LegPayload::simple(
                match side {
                    Side::Debit => Side::Credit,
                    Side::Credit => Side::Debit,
                },
                account_vid(self.book.context().book_id, "CASH"),
                Amount::new(unit, amount),
            ),
        ];
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: date,
            document_date: None,
            description: self.book.seal_text("Portable subledger posting").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([0x97; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn commit(&mut self, proposal: EntryPayload) -> Posted {
        self.book
            .post(PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            })
            .unwrap()
            .unwrap()
    }

    fn post(
        &mut self,
        control: &str,
        party: &str,
        side: Side,
        unit: UnitId,
        amount: i128,
        key: &[u8],
    ) -> EntryRef {
        self.commit(self.proposal(control, party, side, unit, amount, march(), key))
            .entry_ref()
    }

    fn hold(
        &mut self,
        control: &str,
        party: &str,
        side: Side,
        unit: UnitId,
        amount: i128,
        key: &[u8],
    ) -> EntryRef {
        let mut proposal = self.proposal(control, party, side, unit, amount, march(), key);
        proposal.class = EntryClass::PENDING;
        proposal.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        });
        self.commit(proposal).entry_ref()
    }

    fn apply(&mut self, target: EntryRef, amount: i128, key: &[u8]) -> EntryRef {
        let (entry, _) = self.book.read_entry(target.vid).unwrap().unwrap();
        let mut proposal = entry.proposal;
        proposal.idempotency_key = key.to_vec();
        for leg in &mut proposal.legs {
            leg.amount.mantissa = amount;
            leg.side = match leg.side {
                Side::Debit => Side::Credit,
                Side::Credit => Side::Debit,
            };
        }
        proposal.legs[0].settles = vec![fa_model::Settlement {
            target,
            ordinal: 0,
            amount: proposal.legs[0].amount,
        }];
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        self.commit(proposal).entry_ref()
    }

    fn reverse(&mut self, target: EntryRef, key: &[u8]) {
        let (entry, _) = self.book.read_entry(target.vid).unwrap().unwrap();
        let mut proposal = entry.proposal;
        proposal.class = EntryClass::REVERSAL;
        proposal.idempotency_key = key.to_vec();
        proposal.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        for leg in &mut proposal.legs {
            leg.side = match leg.side {
                Side::Debit => Side::Credit,
                Side::Credit => Side::Debit,
            };
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        self.commit(proposal);
    }

    fn resolve_after_cutoff(&mut self, target: EntryRef, amount: i128) -> EntryRef {
        let (entry, _) = self.book.read_entry(target.vid).unwrap().unwrap();
        let mut proposal = entry.proposal;
        proposal.class = EntryClass::RESOLUTION;
        proposal.idempotency_key = b"portable-future-resolution".to_vec();
        proposal.effective_date = april();
        for leg in &mut proposal.legs {
            leg.amount.mantissa = amount;
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        proposal.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(Disposition::Posts {
                source_ordinals: vec![0, 1],
            }),
        });
        self.commit(proposal).entry_ref()
    }

    fn certify(&self, code: &str, through: DateDay) -> CertifiedNativeSubledger {
        self.book
            .certify_native_subledger(
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &self.request(code, through),
            )
            .unwrap()
            .unwrap()
    }
}

fn expectation(request: &NativeSubledgerRequest) -> ExpectedSubledger {
    ExpectedSubledger {
        code: request.code.clone(),
        control_account: request.control_account.0,
        effective_through: request.effective_through.0,
        known_at: request.known_at.unwrap().0,
    }
}

fn produce(book: &mut Book, certificate: &NativeSubledgerCertificate) -> crate::ProducedBundle {
    let checkpoint = book
        .checkpoint(PRINCIPAL, &cap(&["witness"]))
        .unwrap()
        .unwrap();
    let state = checkpoint.checkpoint.checkpoint.body.state_oid;
    let request = certificate.request().unwrap();
    let before = book.head().unwrap();
    let result = book
        .produce_native_subledger_bundle(
            PRINCIPAL,
            &cap(&["read", "produce"]),
            Some(state),
            certificate,
            &request,
        )
        .unwrap()
        .unwrap()
        .expect("checkpoint covers original native sources");
    let repeated = book
        .produce_native_subledger_bundle(
            PRINCIPAL,
            &cap(&["read", "produce"]),
            Some(state),
            certificate,
            &request,
        )
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        result, repeated,
        "one checkpoint and request produce identical bytes"
    );
    assert_eq!(
        book.head().unwrap(),
        before,
        "production publishes no accounting effects"
    );
    result
}

fn verify(
    book: &Book,
    produced: &crate::ProducedBundle,
    certificate: &NativeSubledgerCertificate,
) -> VerifiedReport {
    let key = book.checkpoint_public_key();
    let checkpoint = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let expected = expectation(&certificate.request().unwrap());
    let verified = verify_report_native_subledger_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&produced.receipt),
        &expected,
        Some(certificate.digest()),
    )
    .expect("independent native reconstruction must match every certified byte");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.certificate_digest, *certificate.digest());
    assert_eq!(verified.known_at, expected.known_at);
    assert!(verified.receipt.is_some());
    let native = verified.native_subledger.as_ref().unwrap();
    assert_eq!(
        native.source_certificate_digest,
        certificate.source_certificate().digest
    );
    assert_eq!(native.code, expected.code);
    assert_eq!(native.control_account, expected.control_account);
    assert_eq!(native.effective_through, expected.effective_through);
    assert!(native.reconciled);
    verified
}

fn replace_certificate(bundle: &[u8], certificate: &NativeSubledgerCertificate) -> Vec<u8> {
    let mut r = Reader::new(bundle);
    let format = r.bytes(64, "format").unwrap();
    let major = r.u16("major").unwrap();
    let minor = r.u16("minor").unwrap();
    r.bytes(MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES, "certificate")
        .unwrap();
    let mut w = Writer::new();
    w.bytes(format)
        .u16(major)
        .u16(minor)
        .bytes(&certificate.canonical_bytes().unwrap())
        .fixed(&bundle[r.offset()..]);
    w.finish().unwrap()
}

fn reseal(certificate: &mut NativeSubledgerCertificate) {
    certificate.digest = domain_digest(DIGEST, &[&certificate.body_bytes().unwrap()]);
    assert_eq!(
        NativeSubledgerCertificate::decode(&certificate.canonical_bytes().unwrap()).unwrap(),
        *certificate,
        "negative vectors must pass the native integrity-only decoder"
    );
}

#[test]
fn ar_and_ap_recompute_all_gross_columns_native_units_and_original_coordinates() {
    let mut f = Fixture::new();
    let large = 9_007_199_254_740_993_i128;
    let invoice = f.post("AR", "C-1", Side::Debit, f.usd, large, b"portable-invoice");
    f.apply(invoice, 4_000, b"portable-receipt");
    let reversed = f.post(
        "AR",
        "C-2",
        Side::Debit,
        f.usd,
        3_000,
        b"portable-reversed-invoice",
    );
    f.reverse(reversed, b"portable-invoice-reversal");
    f.hold(
        "AR",
        "C-1",
        Side::Debit,
        f.usd,
        700,
        b"portable-ar-debit-hold",
    );
    f.hold(
        "AR",
        "C-1",
        Side::Credit,
        f.usd,
        200,
        b"portable-ar-credit-hold",
    );
    let bill = f.post("AP", "V-1", Side::Credit, f.usd, 9_000, b"portable-bill");
    f.apply(bill, 2_500, b"portable-payment");
    f.hold(
        "AP",
        "V-1",
        Side::Debit,
        f.usd,
        300,
        b"portable-ap-debit-hold",
    );
    f.hold(
        "AP",
        "V-1",
        Side::Credit,
        f.usd,
        800,
        b"portable-ap-credit-hold",
    );
    f.post("AP", "V-1", Side::Credit, f.eur, 75, b"portable-euro-bill");
    f.hold(
        "AP",
        "V-1",
        Side::Debit,
        f.eur,
        5,
        b"portable-euro-debit-hold",
    );
    f.hold(
        "AP",
        "V-1",
        Side::Credit,
        f.eur,
        9,
        b"portable-euro-credit-hold",
    );
    let future = f.proposal(
        "AR",
        "C-1",
        Side::Debit,
        f.usd,
        777,
        april(),
        b"portable-future-invoice",
    );
    f.commit(future);
    let ar = f.certify("CUSTOMERS", march());
    let ap = f.certify("SUPPLIERS", march());
    f.post(
        "AR",
        "C-1",
        Side::Debit,
        f.usd,
        999,
        b"portable-later-backdated",
    );
    for certified in [ar, ap] {
        let produced = produce(&mut f.book, &certified.certificate);
        let verified = verify(&f.book, &produced, &certified.certificate);
        assert!(verified.checkpoint.checkpoint.through_seq > verified.known_at);
        let native = verified.native_subledger.unwrap();
        assert_eq!(native.subledger_vid, certified.report.subledger.vid.0);
        assert_eq!(
            native.declaration_entry_vid,
            certified.report.subledger.entry.vid.0
        );
        assert_eq!(
            native.declaration_entry_digest,
            certified.report.subledger.entry.entry_digest
        );
        assert_eq!(native.declared_at, certified.report.subledger.recorded_at.0);
        for row in &native.rows {
            assert_eq!(
                row.party,
                party_vid(f.book.context().book_id, &row.party_code).0
            );
            assert_eq!(
                row.party_value,
                party_value_vid(f.book.context().book_id, &row.party_code).0
            );
            assert_ne!(row.party, row.party_value);
        }
        let rows: Vec<_> = native
            .rows
            .iter()
            .map(|row| {
                (
                    row.party_code.as_str(),
                    row.unit,
                    [
                        row.debits,
                        row.credits,
                        row.debits_pending,
                        row.credits_pending,
                    ],
                )
            })
            .collect();
        let totals: Vec<_> = native
            .totals
            .iter()
            .map(|total| {
                let detail = [
                    total.detail_debits,
                    total.detail_credits,
                    total.detail_debits_pending,
                    total.detail_credits_pending,
                ];
                assert_eq!(
                    detail,
                    [
                        total.control_debits,
                        total.control_credits,
                        total.control_debits_pending,
                        total.control_credits_pending
                    ]
                );
                (total.unit, detail)
            })
            .collect();
        if native.kind == 1 {
            assert_eq!(
                rows,
                vec![
                    ("C-1", f.usd.0, [large, 4_000, 700, 200]),
                    ("C-2", f.usd.0, [3_000, 3_000, 0, 0])
                ]
            );
            assert_eq!(totals, vec![(f.usd.0, [large + 3_000, 7_000, 700, 200])]);
        } else {
            assert_eq!(native.kind, 2);
            let mut expected = vec![
                ("V-1", f.usd.0, [2_500, 9_000, 300, 800]),
                ("V-1", f.eur.0, [0, 75, 5, 9]),
            ];
            expected.sort_by_key(|row| row.1);
            assert_eq!(rows, expected);
            assert_eq!(
                totals,
                expected
                    .into_iter()
                    .map(|(_, unit, columns)| (unit, columns))
                    .collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn a_resolution_after_the_cutoff_releases_the_whole_original_hold_at_known_at() {
    let mut f = Fixture::new();
    let hold = f.hold(
        "AR",
        "C-1",
        Side::Debit,
        f.usd,
        700,
        b"portable-released-hold",
    );
    let before = f.certify("CUSTOMERS", march());
    f.resolve_after_cutoff(hold, 250);
    let released = f.certify("CUSTOMERS", march());
    let posted = f.certify("CUSTOMERS", april());
    assert!(matches!(
        f.book
            .native_subledger_certificate_status(PRINCIPAL, &cap(&["read"]), &before.certificate)
            .unwrap()
            .unwrap(),
        CertificateStatus::SupersededBy { .. }
    ));
    for (certified, expected) in [
        (before, [0, 0, 700, 0]),
        (released, [0, 0, 0, 0]),
        (posted, [250, 0, 0, 0]),
    ] {
        let produced = produce(&mut f.book, &certified.certificate);
        let verified = verify(&f.book, &produced, &certified.certificate);
        let native = verified.native_subledger.unwrap();
        let mut actual = [0_i128; 4];
        for row in native.rows {
            actual[0] += row.debits;
            actual[1] += row.credits;
            actual[2] += row.debits_pending;
            actual[3] += row.credits_pending;
        }
        assert_eq!(actual, expected);
    }
}

#[test]
fn portable_subledger_requires_an_independent_question_and_current_whole_book_production_authority()
{
    let mut f = Fixture::new();
    let old = f
        .book
        .checkpoint(PRINCIPAL, &cap(&["witness"]))
        .unwrap()
        .unwrap();
    f.post(
        "AR",
        "C-1",
        Side::Debit,
        f.usd,
        100,
        b"portable-authority-source",
    );
    let certified = f.certify("CUSTOMERS", march());
    let certificate = &certified.certificate;
    let request = certificate.request().unwrap();
    let refusal = f
        .book
        .produce_native_subledger_bundle(
            PRINCIPAL,
            &cap(&["read", "produce"]),
            Some(old.checkpoint.checkpoint.body.state_oid),
            certificate,
            &request,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_notary::code::SCOPE_UNSUPPORTED);
    let produced = produce(&mut f.book, certificate);
    let key = f.book.checkpoint_public_key();
    assert!(
        verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            Some(certificate.digest())
        )
        .is_err(),
        "the artifact cannot choose the recipient's accounting question"
    );
    let mut wrong_requests = Vec::new();
    let mut wrong = request.clone();
    wrong.code = "SUPPLIERS".into();
    wrong_requests.push(wrong);
    let mut wrong = request.clone();
    wrong.control_account = account_vid(f.book.context().book_id, "AP");
    wrong_requests.push(wrong);
    let mut wrong = request.clone();
    wrong.effective_through = april();
    wrong_requests.push(wrong);
    let mut wrong = request.clone();
    wrong.known_at = Some(CommitSeq(request.known_at.unwrap().0 - 1));
    wrong_requests.push(wrong);
    let before = f.book.head().unwrap();
    for wrong in wrong_requests {
        assert!(
            f.book
                .produce_native_subledger_bundle(
                    PRINCIPAL,
                    &cap(&["read", "produce"]),
                    None,
                    certificate,
                    &wrong
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(
            verify_report_native_subledger_expected(
                &produced.bundle.bytes,
                &[key],
                None,
                None,
                &expectation(&wrong),
                Some(certificate.digest())
            )
            .unwrap_err()
            .predicate,
            "native_subledger_request"
        );
    }
    let mut unpinned = request.clone();
    unpinned.known_at = None;
    assert!(
        f.book
            .produce_native_subledger_bundle(
                PRINCIPAL,
                &cap(&["read", "produce"]),
                None,
                certificate,
                &unpinned
            )
            .unwrap()
            .is_err()
    );
    let mut damaged = certificate.clone();
    damaged.digest[0] ^= 1;
    for denied in [
        cap(&["read"]),
        cap(&["produce"]),
        cap(&["read", "produce"]).for_accounts(&["AR"]).unwrap(),
        cap(&["read", "produce"]).known_at_most(certificate.known_at()),
    ] {
        for source in [certificate, &damaged] {
            let refusal = f
                .book
                .produce_native_subledger_bundle(
                    PRINCIPAL,
                    &denied,
                    Some(Oid([0xff; 32])),
                    source,
                    &request,
                )
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
        }
    }
    assert_eq!(
        f.book.head().unwrap(),
        before,
        "denied or mismatched production publishes nothing"
    );
}

#[test]
fn repaired_outer_hashes_cannot_change_gross_or_pending_columns_even_when_the_net_ties() {
    let mut f = Fixture::new();
    f.post(
        "AR",
        "C-1",
        Side::Debit,
        f.usd,
        100,
        b"portable-tamper-invoice",
    );
    f.hold(
        "AR",
        "C-1",
        Side::Credit,
        f.usd,
        20,
        b"portable-tamper-hold",
    );
    let saved = f.certify("CUSTOMERS", march());
    let produced = produce(&mut f.book, &saved.certificate);
    let expected = expectation(&saved.certificate.request().unwrap());
    let key = f.book.checkpoint_public_key();
    let mut variants = Vec::new();
    let mut gross = saved.report.clone();
    gross.rows[0].debits += 1;
    gross.rows[0].credits += 1;
    gross.totals[0].detail_debits += 1;
    gross.totals[0].detail_credits += 1;
    gross.totals[0].control_debits += 1;
    gross.totals[0].control_credits += 1;
    variants.push(gross);
    let mut pending = saved.report.clone();
    pending.rows[0].credits_pending += 1;
    pending.totals[0].detail_credits_pending += 1;
    pending.totals[0].control_credits_pending += 1;
    variants.push(pending);
    let mut party = saved.report.clone();
    party.rows[0].party_code = "C-2".into();
    variants.push(party);
    let mut verdict = saved.report.clone();
    verdict.reconciled = false;
    variants.push(verdict);
    for altered in variants {
        let mut forged = saved.certificate.clone();
        forged.output = altered.canonical_bytes().unwrap();
        reseal(&mut forged);
        let bundle = replace_certificate(&produced.bundle.bytes, &forged);
        assert_eq!(
            verify_report_native_subledger_expected(
                &bundle,
                &[key],
                None,
                None,
                &expected,
                Some(forged.digest())
            )
            .unwrap_err()
            .predicate,
            "native_subledger_recomputation"
        );
    }
}

fn records_reader(bytes: &[u8]) -> (Reader<'_>, u16) {
    let mut r = Reader::new(bytes);
    r.bytes(64, "format").unwrap();
    assert_eq!(r.u16("major").unwrap(), 2);
    let minor = r.u16("minor").unwrap();
    r.bytes(MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES, "certificate")
        .unwrap();
    r.bytes(MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES, "checkpoint")
        .unwrap();
    r.bytes(MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES, "prefix")
        .unwrap();
    (r, minor)
}

fn omit_control(bytes: &[u8], wanted: u16) -> Vec<u8> {
    let (mut r, _) = records_reader(bytes);
    let count_at = r.offset();
    let count = r.u32("record count").unwrap();
    let start = r.offset();
    let mut removed = None;
    for _ in 0..count {
        let record_start = r.offset();
        r.u32("proposal length").unwrap();
        let payload = r
            .bytes(MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES, "record")
            .unwrap();
        if removed.is_none() && Entry::decode(payload).ok().is_some_and(|entry| matches!(&entry.proposal.control, Some(ControlPayload::SchemaChange { kind, .. }) if *kind == wanted)) {
            removed = Some((record_start, r.offset()));
        }
    }
    let (from, through) = removed.expect("real native control is present in the complete prefix");
    let mut w = Writer::new();
    w.fixed(&bytes[..count_at])
        .u32(count - 1)
        .fixed(&bytes[start..from])
        .fixed(&bytes[through..]);
    w.finish().unwrap()
}

fn omit_registry(bytes: &[u8], wanted: &str) -> Vec<u8> {
    let (mut r, minor) = records_reader(bytes);
    for _ in 0..r.u32("record count").unwrap() {
        r.u32("proposal length").unwrap();
        r.bytes(MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES, "record")
            .unwrap();
    }
    for _ in 0..r.u32("migration body count").unwrap() {
        r.u64("migration index").unwrap();
        r.bytes(MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES, "migration body")
            .unwrap();
    }
    if minor == 1 {
        for _ in 0..r.u32("source witness count").unwrap() {
            r.u64("source index").unwrap();
            r.bytes(MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES, "source witness")
                .unwrap();
        }
    }
    let count_at = r.offset();
    let count = r.u32("registry count").unwrap();
    let start = r.offset();
    let mut removed = None;
    for _ in 0..count {
        let registry_start = r.offset();
        let name = r.str(256, "registry name").unwrap();
        r.bytes(MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES, "registry document")
            .unwrap();
        if name == wanted {
            removed = Some((registry_start, r.offset()));
        }
    }
    let (from, through) = removed.expect("native subledger closure carries the required registry");
    let mut w = Writer::new();
    w.fixed(&bytes[..count_at])
        .u32(count - 1)
        .fixed(&bytes[start..from])
        .fixed(&bytes[through..]);
    w.finish().unwrap()
}

#[test]
fn nested_control_recomputation_and_complete_declaration_party_registry_closures_are_required() {
    let mut f = Fixture::new();
    f.post(
        "AR",
        "C-1",
        Side::Debit,
        f.usd,
        100,
        b"portable-closure-invoice",
    );
    let saved = f.certify("CUSTOMERS", march());
    let produced = produce(&mut f.book, &saved.certificate);
    let expected = expectation(&saved.certificate.request().unwrap());
    let key = f.book.checkpoint_public_key();
    let mut forged = saved.certificate.clone();
    *forged.source.output.last_mut().unwrap() ^= 1;
    forged.source.output_digest =
        fa_verify::blake3::hash_parts(b"fa:report-output:v1", &[&forged.source.output]);
    let source = forged.source.canonical_bytes().unwrap();
    forged.source.digest = fa_verify::blake3::hash_parts(
        crate::certificate::CERTIFICATE_FORMAT,
        &[&source[..source.len() - 32]],
    );
    reseal(&mut forged);
    let bundle = replace_certificate(&produced.bundle.bytes, &forged);
    assert_eq!(
        verify_report_native_subledger_expected(
            &bundle,
            &[key],
            None,
            None,
            &expected,
            Some(forged.digest())
        )
        .unwrap_err()
        .predicate,
        "report_recomputation"
    );
    for incomplete in [
        omit_control(&produced.bundle.bytes, 5),
        omit_control(&produced.bundle.bytes, 15),
        omit_registry(&produced.bundle.bytes, "control_payload"),
        omit_registry(&produced.bundle.bytes, "symbols"),
    ] {
        assert!(
            verify_report_native_subledger_expected(
                &incomplete,
                &[key],
                None,
                None,
                &expected,
                Some(saved.certificate.digest())
            )
            .is_err(),
            "count-repaired omissions cannot satisfy the signed prefix and two registry closures"
        );
    }
}

#[test]
fn an_empty_designated_control_is_still_an_authenticated_portable_assertion() {
    let (mut book, request, authority) = fixture();
    let saved = book
        .certify_native_subledger(PRINCIPAL, &authority, &request)
        .unwrap()
        .unwrap();
    let produced = produce(&mut book, &saved.certificate);
    let verified = verify(&book, &produced, &saved.certificate);
    let native = verified.native_subledger.unwrap();
    assert!(native.rows.is_empty());
    assert!(native.totals.is_empty());
    assert_eq!(native.code, "CUSTOMERS");
    assert_eq!(native.kind, 1);
    assert_eq!(
        native.declaration_entry_vid,
        saved.report.subledger.entry.vid.0
    );
}
