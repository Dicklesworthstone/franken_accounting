//! Real direct and policy cash-flow production, independently recomputed from
//! the complete signed native source, including net-zero cash movements.

use super::*;
use fa::cash_flow_policy::{
    CashFlowAccountRule, CashFlowDecisionBasis, CashFlowPolicy, CashFlowPolicyCertificate,
};
use fa::{CashFlowActivity, CashFlowAssignment, CashFlowCertificate, CashFlowDefinition};

fn capability() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap()
}

fn checkpoint(book: &mut Book) -> Oid {
    let witness = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    book.checkpoint(PRINCIPAL, &witness)
        .unwrap()
        .unwrap()
        .checkpoint
        .checkpoint
        .body
        .state_oid
}

fn request(fixture: &Fixture, accounts: &[&str], units: &[UnitId]) -> fa::RollForwardRequest {
    fa::RollForwardRequest {
        accounts: accounts
            .iter()
            .map(|code| account_vid(fixture.book.context().book_id, code))
            .collect(),
        units: units.iter().map(|unit| unit.0).collect(),
        label: "Historical direct cash flow".into(),
        effective_from: day(2026, 2, 1),
        effective_through: day(2026, 2, 28),
        known_at: Some(fixture.book.head().unwrap()),
    }
}

fn verify(
    book: &Book,
    produced: &fa::ProducedBundle,
    expected: &[u8; 32],
    output: &[u8],
    known_at: CommitSeq,
) -> fa_verify::report::VerifiedReport {
    let key = book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        Some(expected),
    )
    .expect("the independent verifier reproduces the complete native cash report");
    assert_eq!(verified.output, output);
    assert_eq!(verified.certificate_digest, *expected);
    assert_eq!(verified.known_at, known_at.0);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.receipt.is_some());
    assert!(verified.rows.is_empty());
    assert!(verified.statement.is_none());
    assert!(verified.open_items.is_none());
    assert!(verified.aging.is_none());
    assert!(verified.roll_forward.is_none());
    assert!(verified.cash_flow.is_some());
    verified
}

fn reverse(fixture: &mut Fixture, target: fa_model::EntryRef, key: &[u8]) -> Posted {
    let (source, _) = fixture.book.read_entry(target.vid).unwrap().unwrap();
    let mut legs = source.proposal.legs.clone();
    for leg in &mut legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
        leg.settles.clear();
    }
    let mut proposal = fixture.proposal(day(2026, 2, 9), key, EntryClass::REVERSAL, legs);
    proposal.supersession = vec![fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    fixture.commit(proposal)
}

#[test]
fn native_cash_flow_bundles_recompute_gross_turnover_transfers_policy_and_historical_zeros() {
    let mut fixture = Fixture::new(0x95);
    let (usd, jpy) = (fixture.usd, fixture.jpy);
    let eur = fixture.book.context().units.lookup("EUR").unwrap();
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    for (code, name) in [
        ("1010", "Reserve cash"),
        ("1020", "Unused cash"),
        ("1500", "Equipment"),
    ] {
        fixture
            .book
            .open_account(
                &account(code, name, AccountType::ASSET),
                day(2025, 12, 1),
                None,
                PRINCIPAL,
                day(2025, 12, 1),
                code.as_bytes(),
                &schema,
            )
            .unwrap()
            .unwrap();
    }
    let id = fixture.book.context().book_id;
    fixture.transfer(
        day(2026, 1, 10),
        b"cash-opening",
        usd,
        ("1000", "3000"),
        1_000,
    );
    fixture.transfer(day(2026, 1, 10), b"jpy-opening", jpy, ("1000", "3000"), 500);
    fixture.transfer(day(2026, 2, 2), b"cash-sale", usd, ("1000", "4000"), 500);
    fixture.transfer(day(2026, 2, 3), b"cash-expense", usd, ("6000", "1000"), 200);
    fixture.transfer(
        day(2026, 2, 4),
        b"cash-investing",
        usd,
        ("1500", "1000"),
        300,
    );
    fixture.transfer(
        day(2026, 2, 5),
        b"cash-financing",
        usd,
        ("1000", "2000"),
        700,
    );
    let internal = fixture.transfer(
        day(2026, 2, 6),
        b"cash-transfer",
        usd,
        ("1010", "1000"),
        250,
    );
    // Two opposing cash legs in one entry are one net operating inflow of 100,
    // not 120 of inflows plus 20 of outflows. Both original legs remain cited.
    let netted = fixture.proposal(
        day(2026, 2, 7),
        b"cash-intra-entry-net",
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, account_vid(id, "1000"), Amount::new(usd, 120)),
            LegPayload::simple(Side::Credit, account_vid(id, "1010"), Amount::new(usd, 20)),
            LegPayload::simple(Side::Credit, account_vid(id, "4000"), Amount::new(usd, 100)),
        ],
    );
    let netted = fixture.commit(netted);
    let corrected = fixture.transfer(
        day(2026, 2, 8),
        b"cash-corrected",
        usd,
        ("1000", "4000"),
        75,
    );
    let reversed = reverse(&mut fixture, corrected.entry_ref(), b"cash-reversal");
    let offset_in = fixture.transfer(
        day(2026, 2, 10),
        b"cash-offset-in",
        usd,
        ("1000", "4000"),
        40,
    );
    let offset_out = fixture.transfer(
        day(2026, 2, 11),
        b"cash-offset-out",
        usd,
        ("6000", "1000"),
        40,
    );
    let mixed = fixture.proposal(
        day(2026, 2, 12),
        b"cash-explicit-choice",
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, account_vid(id, "1000"), Amount::new(usd, 120)),
            LegPayload::simple(Side::Credit, account_vid(id, "4000"), Amount::new(usd, 90)),
            LegPayload::simple(Side::Credit, account_vid(id, "2000"), Amount::new(usd, 30)),
        ],
    );
    let mixed = fixture.commit(mixed);
    fixture.transfer(
        day(2026, 2, 13),
        b"cash-jpy-sale",
        jpy,
        ("1000", "4000"),
        200,
    );
    let mut pending = fixture.proposal(
        day(2026, 2, 14),
        b"cash-pending",
        EntryClass::PENDING,
        fixture.legs(usd, ("6000", "1000"), 30),
    );
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let pending = fixture.commit(pending);
    let future = fixture.transfer(day(2026, 3, 1), b"cash-future", usd, ("1000", "4000"), 999);
    let request = request(&fixture, &["1020", "1000", "1010"], &[jpy, usd, eur]);
    let policy = CashFlowPolicy {
        name: "Explicit cash policy".into(),
        cash_accounts: request.accounts.iter().map(|id| id.0).collect(),
        account_rules: [
            ("4000", CashFlowActivity::Operating),
            ("6000", CashFlowActivity::Operating),
            ("6100", CashFlowActivity::Operating),
            ("2000", CashFlowActivity::Financing),
            ("1500", CashFlowActivity::Investing),
        ]
        .into_iter()
        .map(|(code, activity)| CashFlowAccountRule {
            account_id: account_vid(id, code).0,
            activity,
        })
        .collect(),
        overrides: vec![CashFlowAssignment {
            entry_digest: mixed.entry_ref().entry_digest,
            leg_index: 0,
            activity: CashFlowActivity::Investing,
        }],
    };
    let certified = fixture
        .book
        .certify_cash_flow_with_policy(PRINCIPAL, &capability(), &request, &policy)
        .unwrap()
        .unwrap();
    let policy_certificate = certified.certificate();
    let direct = policy_certificate.source_certificate();
    let later = fixture.transfer(
        day(2026, 2, 1),
        b"cash-later-backdated",
        usd,
        ("1000", "4000"),
        900,
    );
    let state = checkpoint(&mut fixture.book);
    let before = fixture.book.head().unwrap();
    let produced = fixture
        .book
        .produce_cash_flow_bundle(PRINCIPAL, &capability(), Some(state), direct)
        .unwrap()
        .unwrap()
        .unwrap();
    let repeated = fixture
        .book
        .produce_cash_flow_bundle(PRINCIPAL, &capability(), Some(state), direct)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(produced.bundle.bytes, repeated.bundle.bytes);
    assert_eq!(produced.receipt, repeated.receipt);
    let direct_verified = verify(
        &fixture.book,
        &produced,
        direct.digest(),
        direct.output(),
        direct.known_at(),
    );
    let policy_bundle = fixture
        .book
        .produce_cash_flow_policy_bundle(PRINCIPAL, &capability(), Some(state), policy_certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    let repeated = fixture
        .book
        .produce_cash_flow_policy_bundle(PRINCIPAL, &capability(), Some(state), policy_certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(policy_bundle.bundle.bytes, repeated.bundle.bytes);
    assert_eq!(policy_bundle.receipt, repeated.receipt);
    let policy_verified = verify(
        &fixture.book,
        &policy_bundle,
        policy_certificate.digest(),
        &policy_certificate.output().unwrap(),
        policy_certificate.known_at(),
    );
    assert_eq!(
        fixture.book.head().unwrap(),
        before,
        "exports publish no book records"
    );
    let cash = direct_verified.cash_flow.as_ref().unwrap();
    let classified = policy_verified.cash_flow.as_ref().unwrap();
    assert_eq!(
        cash.source_certificate_digest,
        *direct.source_certificate().digest()
    );
    assert_eq!(cash.units, classified.units);
    assert_eq!(cash.ledger, classified.ledger);
    assert!(cash.policy.is_none());
    let retained_policy = classified.policy.as_ref().unwrap();
    assert_eq!(retained_policy.source_certificate_digest, *direct.digest());
    assert_eq!(
        retained_policy.policy.account_rules.len(),
        5,
        "unused rules stay bound"
    );
    assert_eq!(retained_policy.decisions.len(), 14);
    assert_eq!(
        retained_policy
            .decisions
            .iter()
            .filter(|d| d.basis == fa_verify::report::CashFlowDecisionBasis::InternalTransfer)
            .count(),
        2
    );
    assert_eq!(
        retained_policy
            .decisions
            .iter()
            .filter(|d| d.basis == fa_verify::report::CashFlowDecisionBasis::ExplicitOverride)
            .count(),
        1
    );
    assert_eq!(cash.ledger.lines.len(), 14);
    assert_eq!(cash.ledger.cells.len(), 9);
    let row = |unit| cash.units.iter().find(|row| row.unit_id == unit).unwrap();
    let usd_row = row(usd.0);
    assert_eq!(
        (usd_row.opening, usd_row.net_change, usd_row.closing),
        (1_000, 920, 1_920)
    );
    assert_eq!(
        (
            usd_row.operating.inflows,
            usd_row.operating.outflows,
            usd_row.operating.net
        ),
        (715, 315, 400)
    );
    assert_eq!(
        (
            usd_row.investing.inflows,
            usd_row.investing.outflows,
            usd_row.investing.net
        ),
        (120, 300, -180)
    );
    assert_eq!(
        (
            usd_row.financing.inflows,
            usd_row.financing.outflows,
            usd_row.financing.net
        ),
        (700, 0, 700)
    );
    assert_eq!(
        (
            row(jpy.0).opening,
            row(jpy.0).net_change,
            row(jpy.0).closing
        ),
        (500, 200, 700)
    );
    assert_eq!(
        (
            row(eur.0).opening,
            row(eur.0).net_change,
            row(eur.0).closing
        ),
        (0, 0, 0)
    );
    for entry in [internal, netted, corrected, reversed, offset_in, offset_out] {
        assert!(
            cash.ledger
                .lines
                .iter()
                .any(|line| line.entry_digest == entry.entry_ref().entry_digest)
        );
    }
    for entry in [pending, future, later] {
        assert!(
            !cash
                .ledger
                .lines
                .iter()
                .any(|line| line.entry_digest == entry.entry_ref().entry_digest)
        );
    }
    let key = fixture.book.checkpoint_public_key();
    for (bundle, nested) in [
        (&produced, direct.source_certificate().digest()),
        (&policy_bundle, direct.digest()),
    ] {
        assert!(
            fa_verify::report::verify_report_expected(
                &bundle.bundle.bytes,
                &[key],
                None,
                Some(&bundle.receipt),
                Some(nested),
            )
            .is_err(),
            "a nested report digest does not pin the outer cash report"
        );
        assert!(
            fa_verify::report::verify_report_expected(
                &bundle.bundle.bytes,
                &[key],
                None,
                None,
                None,
            )
            .is_err(),
            "the recipient must authorize the outer inputs"
        );
    }
    for (bundle, digest, output) in [
        (&produced, direct.digest(), direct.output().to_vec()),
        (
            &policy_bundle,
            policy_certificate.digest(),
            policy_certificate.output().unwrap(),
        ),
    ] {
        assert_eq!(
            fa_verify::report::verify_report_expected(
                &bundle.bundle.bytes,
                &[key],
                None,
                None,
                Some(digest),
            )
            .unwrap()
            .output,
            output
        );
    }
}

fn simple(fixture: &mut Fixture) -> fa::cash_flow_policy::CertifiedPolicyCashFlow {
    let usd = fixture.usd;
    fixture.transfer(
        day(2026, 2, 5),
        b"simple-cash-sale",
        usd,
        ("1000", "4000"),
        100,
    );
    let request = request(fixture, &["1000"], &[usd]);
    let id = fixture.book.context().book_id;
    fixture
        .book
        .certify_cash_flow_with_policy(
            PRINCIPAL,
            &capability(),
            &request,
            &CashFlowPolicy {
                name: "Simple cash policy".into(),
                cash_accounts: vec![account_vid(id, "1000").0],
                account_rules: vec![CashFlowAccountRule {
                    account_id: account_vid(id, "4000").0,
                    activity: CashFlowActivity::Operating,
                }],
                overrides: Vec::new(),
            },
        )
        .unwrap()
        .unwrap()
}

fn replace_outer(bundle: &[u8], outer: &[u8]) -> Vec<u8> {
    let at = 4 + fa_notary::report::REPORT_BUNDLE_FORMAT.len() + 4;
    let old_len = u32::from_le_bytes(bundle[at..at + 4].try_into().unwrap()) as usize;
    let mut bytes = bundle[..at].to_vec();
    bytes.extend_from_slice(&u32::try_from(outer.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(outer);
    bytes.extend_from_slice(&bundle[at + 4 + old_len..]);
    bytes
}

fn reseal_direct(certificate: &CashFlowCertificate, output: &[u8]) -> CashFlowCertificate {
    let definition = certificate.definition();
    let mut writer = fa_model::Writer::new();
    writer
        .bytes(fa::CASH_FLOW_CERTIFICATE_FORMAT)
        .bytes(&certificate.source_certificate().canonical_bytes().unwrap())
        .str(&definition.name)
        .list(&definition.cash_accounts, |writer, account| {
            writer.u128(*account);
        })
        .list(&definition.assignments, |writer, assignment| {
            writer
                .fixed(&assignment.entry_digest)
                .u32(assignment.leg_index)
                .u8(assignment.activity as u8);
        })
        .bytes(output);
    let mut bytes = writer.finish().unwrap();
    let digest = fa_model::domain_digest(b"fa:cash-flow-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    CashFlowCertificate::decode(&bytes).unwrap()
}

#[test]
fn native_cash_export_replays_financial_bytes_and_policy_counterparts_after_resealing() {
    let mut fixture = Fixture::new(0x96);
    let certified = simple(&mut fixture);
    let policy = certified.certificate();
    let direct = policy.source_certificate();
    let mut financial = direct.output().to_vec();
    let end = financial.len();
    financial[end - 16..].copy_from_slice(&101_i128.to_le_bytes());
    let bad_direct = reseal_direct(direct, &financial);
    let mut wrong_definition: CashFlowDefinition = direct.definition().clone();
    for assignment in &mut wrong_definition.assignments {
        assignment.activity = CashFlowActivity::Financing;
    }
    let wrong_cash = fixture
        .book
        .certify_cash_flow(
            PRINCIPAL,
            &capability(),
            direct.request(),
            &wrong_definition,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        wrong_cash.certificate().source_certificate(),
        direct.source_certificate()
    );
    let mut writer = fa_model::Writer::new();
    writer
        .bytes(fa::cash_flow_policy::CASH_FLOW_POLICY_CERTIFICATE_FORMAT)
        .bytes(&wrong_cash.certificate().canonical_bytes().unwrap())
        .bytes(&policy.policy().canonical_bytes().unwrap())
        .list(policy.decisions(), |writer, decision| {
            assert_eq!(decision.basis, CashFlowDecisionBasis::AccountRules);
            writer
                .fixed(&decision.entry_digest)
                .u32(decision.leg_index)
                .u8(CashFlowActivity::Financing as u8)
                .u8(decision.basis as u8);
        });
    let mut bytes = writer.finish().unwrap();
    let digest = fa_model::domain_digest(b"fa:cash-flow-policy-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    let bad_policy = CashFlowPolicyCertificate::decode(&bytes).unwrap();
    let state = checkpoint(&mut fixture.book);
    let produced = fixture
        .book
        .produce_cash_flow_bundle(PRINCIPAL, &capability(), Some(state), direct)
        .unwrap()
        .unwrap()
        .unwrap();
    let policy_bundle = fixture
        .book
        .produce_cash_flow_policy_bundle(PRINCIPAL, &capability(), Some(state), policy)
        .unwrap()
        .unwrap()
        .unwrap();
    verify(
        &fixture.book,
        &produced,
        direct.digest(),
        direct.output(),
        direct.known_at(),
    );
    verify(
        &fixture.book,
        &policy_bundle,
        policy.digest(),
        &policy.output().unwrap(),
        policy.known_at(),
    );
    let before = fixture.book.head().unwrap();
    let refusal = fixture
        .book
        .produce_cash_flow_bundle(PRINCIPAL, &capability(), Some(state), &bad_direct)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, fa_journal::exit::VERIFICATION);
    assert!(refusal.message.contains("did not replay"), "{refusal:?}");
    let refusal = fixture
        .book
        .produce_cash_flow_policy_bundle(PRINCIPAL, &capability(), Some(state), &bad_policy)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, fa_journal::exit::VERIFICATION);
    assert!(refusal.message.contains("did not reproduce"), "{refusal:?}");
    assert_eq!(fixture.book.head().unwrap(), before);
    let key = fixture.book.checkpoint_public_key();
    for (bundle, outer, digest) in [
        (
            &produced,
            bad_direct.canonical_bytes().unwrap(),
            bad_direct.digest(),
        ),
        (
            &policy_bundle,
            bad_policy.canonical_bytes().unwrap(),
            bad_policy.digest(),
        ),
    ] {
        // The forged outer bytes have their own consistent hash and explicit
        // recipient pin. The complete authenticated source must still defeat
        // invented amounts and an unsupported claim about counterpart rules.
        assert!(
            fa_verify::report::verify_report_expected(
                &replace_outer(&bundle.bundle.bytes, &outer),
                &[key],
                None,
                None,
                Some(digest),
            )
            .is_err()
        );
    }
}

#[test]
fn native_cash_bundle_authority_precedes_history_and_outer_report_observation() {
    let mut fixture = Fixture::new(0x97);
    let certified = simple(&mut fixture);
    let policy = certified.certificate();
    let direct = policy.source_certificate();
    let before = fixture.book.head().unwrap();
    assert!(
        fixture
            .book
            .produce_cash_flow_bundle(PRINCIPAL, &capability(), None, direct)
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .book
            .produce_cash_flow_policy_bundle(PRINCIPAL, &capability(), None, policy)
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert_eq!(fixture.book.head().unwrap(), before);
    let state = checkpoint(&mut fixture.book);
    let before = fixture.book.head().unwrap();
    for denied in [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["produce"]).unwrap(),
        capability().for_accounts(&["1000"]).unwrap(),
        capability().for_periods(&[FEBRUARY]).unwrap(),
        capability().effective_through(day(2026, 2, 28)),
        capability().known_at_most(before),
        capability().for_books(&[Id128([0xff; 16])]).unwrap(),
        capability().expiring_at(before),
    ] {
        assert!(
            fixture
                .book
                .produce_cash_flow_bundle(PRINCIPAL, &denied, Some(state), direct)
                .unwrap()
                .is_err()
        );
        assert!(
            fixture
                .book
                .produce_cash_flow_policy_bundle(PRINCIPAL, &denied, Some(state), policy)
                .unwrap()
                .is_err()
        );
        assert_eq!(fixture.book.head().unwrap(), before);
    }
    assert!(
        fixture
            .book
            .produce_cash_flow_bundle(VId(99), &capability(), Some(state), direct)
            .unwrap()
            .is_err()
    );
    assert!(
        fixture
            .book
            .produce_cash_flow_policy_bundle(VId(99), &capability(), Some(state), policy)
            .unwrap()
            .is_err()
    );
    let mut foreign = Fixture::new(0x98);
    let foreign_before = foreign.book.head().unwrap();
    let pinned = capability().known_at_most(foreign_before);
    for refusal in [
        foreign
            .book
            .produce_cash_flow_bundle(PRINCIPAL, &pinned, None, direct)
            .unwrap()
            .unwrap_err(),
        foreign
            .book
            .produce_cash_flow_policy_bundle(PRINCIPAL, &pinned, None, policy)
            .unwrap()
            .unwrap_err(),
    ] {
        assert_eq!(refusal.exit, fa_journal::exit::SAFETY, "{refusal:?}");
    }
    assert!(
        foreign
            .book
            .produce_cash_flow_bundle(PRINCIPAL, &capability(), None, direct)
            .unwrap()
            .is_err()
    );
    assert!(
        foreign
            .book
            .produce_cash_flow_policy_bundle(PRINCIPAL, &capability(), None, policy)
            .unwrap()
            .is_err()
    );
    assert_eq!(foreign.book.head().unwrap(), foreign_before);
    assert_eq!(fixture.book.head().unwrap(), before);
}
