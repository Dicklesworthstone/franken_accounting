//! Complete-prefix fixtures with independently encoded input/output bytes and
//! hand-calculated application balances. No producer crate or stored mirror is
//! used by these tests.
use super::statements::{closure, registries};
use super::*;
use crate::envelope::SettlementRef;

#[derive(Clone)]
struct InputLeg {
    code: &'static str,
    debit: bool,
    unit: u32,
    amount: i128,
    dimensions: Vec<(u32, u128)>,
    settles: Vec<SettlementRef>,
}

fn leg(code: &'static str, debit: bool, amount: i128) -> InputLeg {
    InputLeg {
        code,
        debit,
        unit: 1,
        amount,
        dimensions: Vec::new(),
        settles: Vec::new(),
    }
}

fn derived(domain: &[u8], target: u128) -> u128 {
    let hash = hash_parts(domain, &[&target.to_le_bytes()]);
    u128::from_le_bytes(hash[..16].try_into().unwrap())
}

#[allow(clippy::too_many_arguments)]
fn posting(
    class: u16,
    seq: u64,
    key: &[u8],
    legs: &[InputLeg],
    supersession: Option<(u128, [u8; 32], u8)>,
    pending: Option<(u128, [u8; 32])>,
) -> (Record, u128) {
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(class)
        .i32(10)
        .u8(0);
    erasable(&mut w);
    w.u8(0).count(legs.len());
    for leg in legs {
        w.u8(u8::from(!leg.debit))
            .u128(account_id(leg.code))
            .u32(leg.unit)
            .i128(leg.amount)
            .u8(0)
            .count(leg.dimensions.len());
        for (id, value) in &leg.dimensions {
            w.u32(*id).u128(*value);
        }
        w.u8(0).count(leg.settles.len());
        for reference in &leg.settles {
            w.u128(reference.target)
                .fixed(&reference.digest)
                .u16(reference.ordinal)
                .u32(reference.unit)
                .i128(reference.amount);
        }
    }
    w.u8(0)
        .count(0)
        .u8(0)
        .bytes(key)
        .u8(0)
        .fixed(&[0; 32])
        .u16(1)
        .u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(usize::from(supersession.is_some()));
    if let Some((target, digest, kind)) = supersession {
        w.u128(target).fixed(&digest).u8(kind).u16(1);
    }
    w.u8(u8::from(class == 2 || pending.is_some()));
    if class == 2 || pending.is_some() {
        w.u8(0).u8(u8::from(pending.is_some()));
        if let Some((target, digest)) = pending {
            w.u128(target).fixed(&digest);
        }
        w.u8(u8::from(pending.is_some()));
        if pending.is_some() {
            if legs.is_empty() {
                w.u8(1); // Voids is a release; it has no posted legs.
            } else {
                w.u8(3).count(legs.len());
                for ordinal in 0..legs.len() {
                    w.u16(ordinal as u16);
                }
            }
        }
    }
    w.count(0).count(0);
    let len = w.buf.len();
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[]]);
    w.fixed(&proposal_digest).fixed(&digest);
    let envelope = envelope_of_entry(&w.buf, len, seq, 0).unwrap();
    let identity = match class {
        4 => derived(b"fa:vid:reversal:v1", supersession.unwrap().0),
        5 => derived(b"fa:vid:replacement:v1", supersession.unwrap().0),
        3 => derived(b"fa:vid:resolution:v1", pending.unwrap().0),
        _ => {
            let mut framed = Writer::default();
            framed
                .bytes(&BOOK)
                .bytes(&PRINCIPAL.to_le_bytes())
                .bytes(key);
            let hash = hash_parts(b"fa:vid:entry:v1", &[&framed.buf]);
            u128::from_le_bytes(hash[..16].try_into().unwrap())
        }
    };
    (
        Record {
            bytes: w.buf,
            len,
            envelope,
        },
        identity,
    )
}

fn application(target: &Record, id: u128, ordinal: u16, amount: i128) -> SettlementRef {
    SettlementRef {
        target: id,
        digest: target.envelope.record_digest,
        ordinal,
        unit: 1,
        amount,
    }
}

fn reverse(target: &Record, id: u128, seq: u64, key: &[u8], legs: &[InputLeg]) -> (Record, u128) {
    let reversed: Vec<_> = legs
        .iter()
        .cloned()
        .map(|mut leg| {
            leg.debit = !leg.debit;
            leg.settles.clear();
            leg
        })
        .collect();
    posting(
        4,
        seq,
        key,
        &reversed,
        Some((id, target.envelope.record_digest, 1)),
        None,
    )
}

fn displayed(code: &str) -> VerifiedOpenItemAccount {
    let (name, account_type, normal_balance) = match code {
        "1000" => ("Cash", 1, 0),
        "3000" => ("Equity", 3, 1),
        _ => panic!("unknown fixture account"),
    };
    VerifiedOpenItemAccount {
        account: account_id(code),
        code: code.into(),
        name: name.into(),
        account_type,
        normal_balance,
        is_leaf: true,
        unit_policy: OpenItemUnitPolicy::Single(1),
        limit: None,
        created_at: 1,
    }
}

#[allow(clippy::too_many_arguments)]
fn item(
    id: u128,
    ordinal: u16,
    code: &str,
    debit: bool,
    seq: u64,
    original: i128,
    applied: i128,
    applied_out: i128,
    open: i128,
    applications: Vec<VerifiedApplication>,
) -> VerifiedOpenItem {
    VerifiedOpenItem {
        entry: id,
        ordinal,
        account: account_id(code),
        unit_id: 1,
        debit,
        effective_date: 10,
        recorded_at: seq,
        original,
        applied,
        applied_out,
        open,
        applications,
    }
}

fn report(filter: Option<u128>, mut items: Vec<VerifiedOpenItem>) -> VerifiedOpenItems {
    items.sort_by_key(|item| (item.account, item.recorded_at, item.entry, item.ordinal));
    let ids: BTreeSet<_> = items
        .iter()
        .map(|item| item.account)
        .chain(filter)
        .collect();
    let accounts = [displayed("1000"), displayed("3000")]
        .into_iter()
        .filter(|account| ids.contains(&account.account))
        .map(|account| (account.account, account))
        .collect();
    VerifiedOpenItems {
        account_filter: filter,
        accounts,
        items,
    }
}

fn output_bytes(known_at: u64, expected: &VerifiedOpenItems) -> Vec<u8> {
    // Deliberately independent of open_items::encode: exact format fields,
    // including the map key AND row VId, are part of the expected fixture.
    let mut out = Writer::default();
    out.fixed(b"fa:open-items:v1")
        .u64(known_at)
        .u8(u8::from(expected.account_filter.is_some()));
    if let Some(id) = expected.account_filter {
        out.u128(id);
    }
    out.count(expected.accounts.len());
    for (key, row) in &expected.accounts {
        out.u128(*key)
            .u128(row.account)
            .bytes(row.code.as_bytes())
            .bytes(row.name.as_bytes())
            .u8(row.account_type)
            .u8(row.normal_balance)
            .u8(u8::from(row.is_leaf));
        match row.unit_policy {
            OpenItemUnitPolicy::Single(unit) => {
                out.u8(0).u32(unit);
            }
            OpenItemUnitPolicy::AnyCurrency => {
                out.u8(1);
            }
            OpenItemUnitPolicy::AnyUnit => {
                out.u8(2);
            }
        }
        out.u8(u8::from(row.limit.is_some()));
        if let Some(limit) = &row.limit {
            for bound in [limit.lower, limit.upper] {
                out.u8(u8::from(bound.is_some()));
                if let Some(value) = bound {
                    out.i128(value);
                }
            }
            out.u8(u8::from(limit.period_scoped));
        }
        out.u64(row.created_at);
    }
    out.count(expected.items.len());
    for row in &expected.items {
        out.u128(row.entry)
            .u16(row.ordinal)
            .u128(row.account)
            .u32(row.unit_id)
            .u8(u8::from(!row.debit))
            .i32(row.effective_date)
            .u64(row.recorded_at)
            .i128(row.original)
            .i128(row.applied)
            .i128(row.applied_out)
            .i128(row.open)
            .count(row.applications.len());
        for event in &row.applications {
            out.u128(event.entry)
                .u16(event.ordinal)
                .i128(event.amount)
                .u64(event.recorded_at)
                .u8(u8::from(event.live));
        }
    }
    out.buf
}

fn pack(
    records: &[Record],
    known_at: u64,
    expected: &VerifiedOpenItems,
) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
    let mut last_seq = None;
    let mut ordinal = 0;
    let envelopes: Vec<_> = records
        .iter()
        .map(|record| {
            if last_seq != Some(record.envelope.commit_seq) {
                ordinal = 0;
                last_seq = Some(record.envelope.commit_seq);
            }
            let mut envelope = record.envelope.clone();
            envelope.within_commit_ordinal = ordinal;
            ordinal += 1;
            envelope
        })
        .collect();
    let hashes: Vec<_> = envelopes.iter().map(|e| leaf_hash(&e.encode())).collect();
    let checkpoint = Checkpoint {
        book_id: BOOK,
        branch_id: [0; 16],
        through_seq: envelopes.last().unwrap().commit_seq,
        leaf_count: hashes.len() as u64,
        root: root_of(&hashes),
    };
    let mut prefix = Writer::default();
    prefix
        .bytes(PREFIX_FORMAT)
        .fixed(&checkpoint.encode())
        .count(envelopes.len());
    for envelope in &envelopes {
        prefix.bytes(&envelope.encode());
    }
    let historical: Vec<_> = envelopes
        .iter()
        .zip(&hashes)
        .filter(|(e, _)| e.commit_seq <= known_at)
        .map(|(_, hash)| *hash)
        .collect();
    let docs = registries();
    let output = output_bytes(known_at, expected);
    let mut certificate = Writer::default();
    certificate
        .fixed(OPEN_ITEMS_CERTIFICATE_FORMAT)
        .bytes(b"fa-fold-over-prefix")
        .bytes(b"embedded-owner")
        .bytes(b"fa:open-items:v1")
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(known_at)
        .u8(1)
        .u8(u8::from(expected.account_filter.is_some()));
    if let Some(account) = expected.account_filter {
        certificate.u128(account);
    }
    certificate
        .fixed(&closure(&docs))
        .fixed(&root_of(&historical))
        .u64(historical.len() as u64)
        .count(7);
    for _ in 0..7 {
        certificate.bytes(b"opaque native read");
    }
    certificate
        .bytes(&output)
        .fixed(&hash_parts(b"fa:report-output:v1", &[&output]))
        .u8(0);
    let digest = hash_parts(OPEN_ITEMS_CERTIFICATE_FORMAT, &[&certificate.buf]);
    certificate.fixed(&digest);
    let mut bundle = Writer::default();
    bundle
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(&certificate.buf)
        .bytes(b"externally trusted fixture")
        .bytes(&prefix.buf)
        .count(records.len());
    for record in records {
        bundle.u32(record.len as u32).bytes(&record.bytes);
    }
    bundle.count(0).count(docs.len());
    for (name, bytes) in docs {
        bundle.bytes(name.as_bytes()).bytes(&bytes);
    }
    (bundle.buf, signed(checkpoint), digest)
}

fn verify(
    records: &[Record],
    known_at: u64,
    expected: &VerifiedOpenItems,
) -> Result<VerifiedReport, ReportError> {
    let (bytes, anchor, pin) = pack(records, known_at, expected);
    verify_report_with(&bytes, &[], None, None, Some(&pin), |_, _| Ok(anchor))
}

#[test]
fn partial_applications_refunds_and_zero_open_legs_recompute_exactly() {
    let mut records = schema();
    let invoice_legs = [leg("1000", true, 100), leg("3000", false, 100)];
    let (invoice, invoice_id) = posting(1, 3, b"invoice", &invoice_legs, None, None);
    let mut payment_legs = [leg("1000", false, 80), leg("3000", true, 80)];
    payment_legs[0]
        .settles
        .push(application(&invoice, invoice_id, 0, 60));
    let (payment, payment_id) = posting(1, 4, b"payment", &payment_legs, None, None);
    let mut refund_legs = [leg("1000", true, 20), leg("3000", false, 20)];
    refund_legs[0]
        .settles
        .push(application(&payment, payment_id, 0, 20));
    let (refund, refund_id) = posting(7, 5, b"refund", &refund_legs, None, None);
    records.extend([invoice, payment, refund]);
    let history = |entry, amount, recorded_at| {
        vec![VerifiedApplication {
            entry,
            ordinal: 0,
            amount,
            recorded_at,
            live: true,
        }]
    };
    let expected = report(
        None,
        vec![
            item(
                invoice_id,
                0,
                "1000",
                true,
                3,
                100,
                60,
                0,
                40,
                history(payment_id, 60, 4),
            ),
            item(invoice_id, 1, "3000", false, 3, 100, 0, 0, 100, vec![]),
            item(
                payment_id,
                0,
                "1000",
                false,
                4,
                80,
                20,
                60,
                0,
                history(refund_id, 20, 5),
            ),
            item(payment_id, 1, "3000", true, 4, 80, 0, 0, 80, vec![]),
            item(refund_id, 0, "1000", true, 5, 20, 0, 20, 0, vec![]),
            item(refund_id, 1, "3000", false, 5, 20, 0, 0, 20, vec![]),
        ],
    );
    let verified = verify(&records, 5, &expected).unwrap();
    assert_eq!(verified.open_items.as_ref(), Some(&expected));
    assert_eq!(verified.output, output_bytes(5, &expected));
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.rows.is_empty() && verified.statement.is_none());
    let filtered = report(
        Some(account_id("1000")),
        expected
            .items
            .iter()
            .filter(|row| row.account == account_id("1000"))
            .cloned()
            .collect(),
    );
    assert_eq!(
        verify(&records, 5, &filtered).unwrap().open_items,
        Some(filtered)
    );
}

#[test]
fn undone_applications_remain_in_history_and_later_records_do_not_rewrite_old_reports() {
    let mut records = schema();
    let invoice_legs = [leg("1000", true, 100), leg("3000", false, 100)];
    let (invoice, invoice_id) = posting(1, 3, b"invoice", &invoice_legs, None, None);
    let mut payment_legs = [leg("1000", false, 40), leg("3000", true, 40)];
    payment_legs[0]
        .settles
        .push(application(&invoice, invoice_id, 0, 40));
    let (payment, payment_id) = posting(1, 4, b"payment", &payment_legs, None, None);
    let (undo, _) = reverse(&payment, payment_id, 5, b"undo", &payment_legs);
    records.extend([invoice, payment, undo]);
    let expected = report(
        Some(account_id("1000")),
        vec![item(
            invoice_id,
            0,
            "1000",
            true,
            3,
            100,
            0,
            0,
            100,
            vec![VerifiedApplication {
                entry: payment_id,
                ordinal: 0,
                amount: 40,
                recorded_at: 4,
                live: false,
            }],
        )],
    );
    assert_eq!(
        verify(&records, 5, &expected).unwrap().open_items,
        Some(expected)
    );
    let historical = report(
        Some(account_id("1000")),
        vec![
            item(
                invoice_id,
                0,
                "1000",
                true,
                3,
                100,
                40,
                0,
                60,
                vec![VerifiedApplication {
                    entry: payment_id,
                    ordinal: 0,
                    amount: 40,
                    recorded_at: 4,
                    live: true,
                }],
            ),
            item(payment_id, 0, "1000", false, 4, 40, 0, 40, 0, vec![]),
        ],
    );
    assert_eq!(
        verify(&records, 4, &historical).unwrap().open_items,
        Some(historical)
    );
}

#[test]
fn reversal_of_reversal_restores_original_items_and_pending_holds_never_become_items() {
    let mut records = schema();
    let legs = [leg("1000", true, 90), leg("3000", false, 90)];
    let (original, original_id) = posting(1, 3, b"original", &legs, None, None);
    let (reversal, reversal_id) = reverse(&original, original_id, 4, b"reversal", &legs);
    let reversed_legs = [leg("1000", false, 90), leg("3000", true, 90)];
    let (restoration, _) = reverse(&reversal, reversal_id, 5, b"restoration", &reversed_legs);
    let (hold, hold_id) = posting(2, 6, b"hold", &legs, None, None);
    let (release, _) = posting(
        3,
        7,
        b"void",
        &[],
        None,
        Some((hold_id, hold.envelope.record_digest)),
    );
    records.extend([original, reversal, restoration, hold, release]);
    let expected = report(
        Some(account_id("1000")),
        vec![item(original_id, 0, "1000", true, 3, 90, 0, 0, 90, vec![])],
    );
    assert_eq!(
        verify(&records, 7, &expected).unwrap().open_items,
        Some(expected)
    );
    assert!(
        verify(&records, 4, &report(Some(account_id("1000")), vec![]))
            .unwrap()
            .open_items
            .unwrap()
            .items
            .is_empty()
    );
}

#[test]
fn posted_pending_resolution_carries_only_its_actual_applied_legs() {
    let mut records = schema();
    let (invoice, invoice_id) = posting(1, 3, b"invoice", &[leg("1000", true, 100)], None, None);
    let (hold, hold_id) = posting(2, 4, b"hold", &[leg("1000", false, 80)], None, None);
    let mut posted = leg("1000", false, 40);
    posted
        .settles
        .push(application(&invoice, invoice_id, 0, 40));
    let (resolution, resolution_id) = posting(
        3,
        5,
        b"post part",
        &[posted],
        None,
        Some((hold_id, hold.envelope.record_digest)),
    );
    records.extend([invoice, hold, resolution]);
    let expected = report(
        Some(account_id("1000")),
        vec![
            item(
                invoice_id,
                0,
                "1000",
                true,
                3,
                100,
                40,
                0,
                60,
                vec![VerifiedApplication {
                    entry: resolution_id,
                    ordinal: 0,
                    amount: 40,
                    recorded_at: 5,
                    live: true,
                }],
            ),
            item(resolution_id, 0, "1000", false, 5, 40, 0, 40, 0, vec![]),
        ],
    );
    assert_eq!(
        verify(&records, 5, &expected).unwrap().open_items,
        Some(expected)
    );
}

#[test]
fn same_commit_targets_are_valid_even_when_the_prefix_orders_applying_entry_first() {
    let mut records = schema();
    let (target, target_id) = posting(1, 3, b"target", &[leg("1000", true, 100)], None, None);
    let mut paid = leg("1000", false, 35);
    paid.settles.push(application(&target, target_id, 0, 35));
    let (payer, payer_id) = posting(1, 3, b"payer", &[paid], None, None);
    records.extend([payer, target]);
    let expected = report(
        Some(account_id("1000")),
        vec![
            item(
                target_id,
                0,
                "1000",
                true,
                3,
                100,
                35,
                0,
                65,
                vec![VerifiedApplication {
                    entry: payer_id,
                    ordinal: 0,
                    amount: 35,
                    recorded_at: 3,
                    live: true,
                }],
            ),
            item(payer_id, 0, "1000", false, 3, 35, 0, 35, 0, vec![]),
        ],
    );
    assert_eq!(
        verify(&records, 3, &expected).unwrap().open_items,
        Some(expected)
    );
}

#[test]
fn malformed_application_targets_amounts_and_dimensions_fail_after_authentication() {
    for mutation in 0..11 {
        let mut records = schema();
        let (target, target_id) = posting(
            if mutation == 9 { 2 } else { 1 },
            3,
            b"target",
            &[leg("1000", true, 100)],
            None,
            None,
        );
        let mut payer = leg("1000", false, 50);
        let mut reference = application(&target, target_id, 0, 25);
        let predicate = match mutation {
            0 => {
                reference.target ^= 1;
                "application_target"
            }
            1 => {
                reference.digest[0] ^= 1;
                "application_target"
            }
            2 => {
                reference.ordinal = 7;
                "application_target"
            }
            3 => {
                reference.unit = 0;
                "application_shape"
            }
            4 => {
                reference.amount = 0;
                "application_shape"
            }
            5 => {
                payer.code = "3000";
                "application_target"
            }
            6 => {
                payer.debit = true;
                "application_target"
            }
            7 => {
                payer.dimensions.push((1, 9));
                "supported_report"
            }
            8 => {
                payer.settles.push(reference.clone());
                "application_shape"
            }
            9 => "application_target",
            10 => {
                payer.dimensions.push((2, 9));
                "application_target"
            }
            _ => unreachable!(),
        };
        payer.settles.push(reference);
        let (payment, _) = posting(1, 4, b"payer", &[payer], None, None);
        records.extend([target, payment]);
        assert_eq!(
            verify(&records, 4, &report(None, vec![]))
                .unwrap_err()
                .predicate,
            predicate,
            "mutation {mutation}"
        );
    }
}

#[test]
fn future_targets_and_over_application_cannot_be_hidden_by_later_undo() {
    let mut records = schema();
    let (future, future_id) = posting(1, 4, b"future", &[leg("1000", true, 100)], None, None);
    let mut early = leg("1000", false, 20);
    early.settles.push(application(&future, future_id, 0, 20));
    let (early, _) = posting(1, 3, b"early", &[early], None, None);
    records.extend([early, future]);
    assert_eq!(
        verify(&records, 4, &report(None, vec![]))
            .unwrap_err()
            .predicate,
        "application_target"
    );
    let mut records = schema();
    let (target, target_id) = posting(1, 3, b"target", &[leg("1000", true, 100)], None, None);
    let mut excessive = leg("1000", false, 120);
    excessive
        .settles
        .push(application(&target, target_id, 0, 110));
    let (payment, payment_id) = posting(1, 4, b"excessive", &[excessive.clone()], None, None);
    let (undo, _) = reverse(&payment, payment_id, 5, b"undo", &[excessive]);
    records.extend([target, payment, undo]);
    assert_eq!(
        verify(&records, 5, &report(None, vec![]))
            .unwrap_err()
            .predicate,
        "application_capacity"
    );
}

#[test]
fn reversing_an_item_with_live_inbound_applications_is_refused() {
    let mut records = schema();
    let target_legs = [leg("1000", true, 100)];
    let (target, target_id) = posting(1, 3, b"target", &target_legs, None, None);
    let mut payer = leg("1000", false, 40);
    payer.settles.push(application(&target, target_id, 0, 40));
    let (payment, _) = posting(1, 4, b"payment", &[payer], None, None);
    let (undo, _) = reverse(&target, target_id, 5, b"undo", &target_legs);
    records.extend([target, payment, undo]);
    assert_eq!(
        verify(&records, 5, &report(None, vec![]))
            .unwrap_err()
            .predicate,
        "application_capacity"
    );
}

#[test]
fn canonical_replacement_items_verify_but_legacy_identity_aliases_are_not_guessed() {
    let mut records = schema();
    let original_legs = [leg("1000", true, 100)];
    let (original, original_id) = posting(1, 3, b"original", &original_legs, None, None);
    let (undo, _) = reverse(&original, original_id, 4, b"undo", &original_legs);
    let (replacement, replacement_id) = posting(
        5,
        4,
        b"replacement",
        &[leg("1000", true, 125)],
        Some((original_id, original.envelope.record_digest, 2)),
        None,
    );
    let mut paid = leg("1000", false, 25);
    paid.settles
        .push(application(&replacement, replacement_id, 0, 25));
    let (payment, payment_id) = posting(1, 5, b"payment", &[paid.clone()], None, None);
    records.extend([original, undo, replacement, payment]);
    let expected = report(
        Some(account_id("1000")),
        vec![
            item(
                replacement_id,
                0,
                "1000",
                true,
                4,
                125,
                25,
                0,
                100,
                vec![VerifiedApplication {
                    entry: payment_id,
                    ordinal: 0,
                    amount: 25,
                    recorded_at: 5,
                    live: true,
                }],
            ),
            item(payment_id, 0, "1000", false, 5, 25, 0, 25, 0, vec![]),
        ],
    );
    assert_eq!(
        verify(&records, 5, &expected).unwrap().open_items,
        Some(expected)
    );
    let mut framed = Writer::default();
    framed
        .bytes(&BOOK)
        .bytes(&PRINCIPAL.to_le_bytes())
        .bytes(b"replacement");
    let hash = hash_parts(b"fa:vid:entry:v1", &[&framed.buf]);
    paid.settles[0].target = u128::from_le_bytes(hash[..16].try_into().unwrap());
    records[5] = posting(1, 5, b"legacy target", &[paid], None, None).0;
    let error = verify(&records, 5, &report(None, vec![])).unwrap_err();
    assert_eq!(error.predicate, "supported_report");
    assert!(error.detail.contains("legacy key-derived replacement"));
}

#[test]
fn resealed_amount_history_identity_and_account_metadata_changes_are_refused() {
    let mut records = schema();
    let (original, id) = posting(
        1,
        3,
        b"original",
        &[leg("1000", true, i128::MAX)],
        None,
        None,
    );
    records.push(original);
    let expected = report(
        Some(account_id("1000")),
        vec![item(
            id,
            0,
            "1000",
            true,
            3,
            i128::MAX,
            0,
            0,
            i128::MAX,
            vec![],
        )],
    );
    assert_eq!(
        verify(&records, 3, &expected).unwrap().open_items,
        Some(expected.clone())
    );
    for mutation in 0..9 {
        let mut altered = expected.clone();
        match mutation {
            0 => altered.items[0].open -= 1,
            1 => altered.items[0].entry ^= 1,
            2 => altered.items[0].recorded_at += 1,
            3 => altered.items[0].applications.push(VerifiedApplication {
                entry: 9,
                ordinal: 0,
                amount: 1,
                recorded_at: 3,
                live: false,
            }),
            4 => altered.accounts.get_mut(&account_id("1000")).unwrap().name = "fabricated".into(),
            5 => {
                altered
                    .accounts
                    .get_mut(&account_id("1000"))
                    .unwrap()
                    .normal_balance = 1
            }
            6 => {
                altered
                    .accounts
                    .get_mut(&account_id("1000"))
                    .unwrap()
                    .created_at += 1
            }
            7 => {
                altered
                    .accounts
                    .get_mut(&account_id("1000"))
                    .unwrap()
                    .unit_policy = OpenItemUnitPolicy::AnyUnit
            }
            8 => altered.items.clear(),
            _ => unreachable!(),
        }
        assert_eq!(
            verify(&records, 3, &altered).unwrap_err().predicate,
            "report_recomputation",
            "mutation {mutation}"
        );
    }
}

#[test]
fn empty_selection_proves_account_metadata_and_unknown_account_absence() {
    let records = schema();
    let expected = report(Some(account_id("1000")), vec![]);
    let verified = verify(&records, 2, &expected).unwrap();
    assert_eq!(verified.open_items, Some(expected));
    let unknown = VerifiedOpenItems {
        account_filter: Some(44),
        accounts: BTreeMap::new(),
        items: vec![],
    };
    assert_eq!(
        verify(&records, 2, &unknown).unwrap_err().predicate,
        "account_metadata"
    );
}

#[test]
fn account_close_promotion_and_native_subledger_bind_the_correct_row_version() {
    for kind in [3, 4, 15] {
        let mut records = schema();
        let mut body = Writer::default();
        if kind == 15 {
            body.fixed(b"fa:native-subledger:v1")
                .bytes(b"AR")
                .bytes(b"Receivables")
                .u8(1)
                .u128(account_id("1000"));
        } else {
            body.bytes(b"1000").i32(20);
        }
        records.push(record(
            17,
            3,
            0,
            b"account update",
            0,
            Some((kind, &body.buf)),
            None,
            None,
        ));
        let mut expected = report(Some(account_id("1000")), vec![]);
        let account = expected.accounts.get_mut(&account_id("1000")).unwrap();
        account.created_at = 3;
        account.is_leaf = kind != 4;
        assert_eq!(
            verify(&records, 3, &expected).unwrap().open_items,
            Some(expected)
        );
        let historical = report(Some(account_id("1000")), vec![]);
        assert_eq!(
            verify(&records, 2, &historical).unwrap().open_items,
            Some(historical)
        );
    }
}

#[test]
fn chart_limits_unit_policies_and_added_accounts_are_reconstructed_from_controls() {
    let mut chart = Writer::default();
    chart.count(2);
    for (code, name, typ, normal, policy) in
        [("1000", "Cash", 1, 0, 1i64), ("3000", "Equity", 3, 1, -1)]
    {
        chart
            .bytes(code.as_bytes())
            .bytes(name.as_bytes())
            .u8(typ)
            .u8(normal)
            .u8(1)
            .fixed(&policy.to_le_bytes())
            .u8(0);
    }
    chart
        .count(1)
        .bytes(b"1000")
        .u8(1)
        .i128(0)
        .u8(1)
        .i128(1_000)
        .count(1)
        .bytes(b"1000");
    let mut records = vec![record(
        17,
        1,
        0,
        b"limited chart",
        0,
        Some((1, &chart.buf)),
        None,
        None,
    )];
    let mut expected = report(Some(account_id("1000")), vec![]);
    expected
        .accounts
        .get_mut(&account_id("1000"))
        .unwrap()
        .limit = Some(OpenItemBalanceLimit {
        lower: Some(0),
        upper: Some(1_000),
        period_scoped: true,
    });
    assert_eq!(
        verify(&records, 1, &expected).unwrap().open_items,
        Some(expected)
    );
    let mut currency = report(Some(account_id("3000")), vec![]);
    currency
        .accounts
        .get_mut(&account_id("3000"))
        .unwrap()
        .unit_policy = OpenItemUnitPolicy::AnyCurrency;
    assert_eq!(
        verify(&records, 1, &currency).unwrap().open_items,
        Some(currency)
    );
    let mut added = Writer::default();
    added
        .bytes(b"2000")
        .bytes(b"Inventory quantities")
        .u8(7)
        .u8(0)
        .u8(1)
        .fixed(&(-2i64).to_le_bytes())
        .u8(0)
        .u8(0)
        .i32(0)
        .u8(0);
    records.push(record(
        17,
        2,
        0,
        b"add account",
        0,
        Some((2, &added.buf)),
        None,
        None,
    ));
    let id = account_id("2000");
    let added = VerifiedOpenItems {
        account_filter: Some(id),
        accounts: BTreeMap::from([(
            id,
            VerifiedOpenItemAccount {
                account: id,
                code: "2000".into(),
                name: "Inventory quantities".into(),
                account_type: 7,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: OpenItemUnitPolicy::AnyUnit,
                limit: None,
                created_at: 2,
            },
        )]),
        items: vec![],
    };
    assert_eq!(verify(&records, 2, &added).unwrap().open_items, Some(added));
}

#[test]
fn registry_authority_and_native_v3_selector_boundaries_fail_closed() {
    let records = schema();
    let expected = report(Some(account_id("1000")), vec![]);
    let (bytes, anchor, pin) = pack(&records, 2, &expected);
    assert_eq!(
        verify_report_with(&bytes, &[], None, None, None, |_, _| Ok(anchor.clone()))
            .unwrap_err()
            .predicate,
        "report_input_authority"
    );
    assert_eq!(
        verify_report_with_inputs(&bytes, &[], None, None, Some(&pin), Some(&[1]), |_, _| Ok(
            anchor.clone()
        ))
        .unwrap_err()
        .predicate,
        "supported_report"
    );
    let mut legacy = bytes.clone();
    let major = 4 + REPORT_BUNDLE_FORMAT.len();
    legacy[major..major + 2].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        verify_report_with(&legacy, &[], None, None, Some(&pin), |_, _| Ok(
            anchor.clone()
        ))
        .unwrap_err()
        .predicate,
        "registry_closure"
    );
    let mut cert = Reader::new(&bytes);
    cert.bytes(64, "format").unwrap();
    cert.u16("major").unwrap();
    cert.u16("minor").unwrap();
    let mut unsupported = cert
        .bytes(MAX_REPORT_BUNDLE_BYTES, "certificate")
        .unwrap()
        .to_vec();
    let selector = 24
        + (4 + b"fa-fold-over-prefix".len())
        + (4 + b"embedded-owner".len())
        + (4 + b"fa:open-items:v1".len())
        + 16
        + 16
        + 8;
    unsupported[selector] = 0; // ExplainBalance is a distinct, unsupported v3 selector.
    assert_eq!(
        certificate(&unsupported).err().unwrap().predicate,
        "supported_report"
    );
}

#[test]
fn instant_open_items_prove_the_tick_bucket_and_exclude_later_applications() {
    let mut records = schema();
    records.push(super::temporal::tick(3, 100, false));
    let (invoice, invoice_id) = posting(1, 4, b"invoice", &[leg("1000", true, 120)], None, None);
    let mut paid = leg("1000", false, 40);
    paid.settles.push(application(&invoice, invoice_id, 0, 40));
    let (payment, _) = posting(1, 6, b"later payment", &[paid], None, None);
    records.extend([
        invoice,
        super::temporal::tick(5, 200, true),
        payment,
        super::temporal::tick(7, 300, true),
    ]);
    let expected = report(
        Some(account_id("1000")),
        vec![item(invoice_id, 0, "1000", true, 4, 120, 0, 0, 120, vec![])],
    );
    let (bytes, anchor, _) = pack(&records, 4, &expected);
    let time = super::temporal::selection(150, 7, 4, (3, 100, false), Some((5, 200, true)));
    let (instant, pin) = super::temporal::with_time(&bytes, &time);
    let verified = verify_report_with(&instant, &[], None, None, Some(&pin), |_, _| {
        Ok(anchor.clone())
    })
    .unwrap();
    assert_eq!(verified.time_selection.as_ref(), Some(&time));
    assert_eq!(verified.open_items, Some(expected));
    let mut forged = time;
    forged.upper_entry = Some(99);
    let (forged, pin) = super::temporal::with_time(&bytes, &forged);
    assert_eq!(
        verify_report_with(&forged, &[], None, None, Some(&pin), |_, _| Ok(anchor))
            .unwrap_err()
            .predicate,
        "time_selection"
    );
}

#[path = "aging.rs"]
mod aging;

#[path = "roll_forward.rs"]
mod roll_forward;
