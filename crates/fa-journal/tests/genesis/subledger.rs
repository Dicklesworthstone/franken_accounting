use super::*;

fn spec(h: &Harness) -> NativeSubledgerSpec {
    NativeSubledgerSpec {
        code: "AR".into(),
        name: "Trade receivables".into(),
        kind: NativeSubledgerKind::Receivables,
        control_account: h.receivable,
    }
}

fn register(
    h: &mut Harness,
    spec: &NativeSubledgerSpec,
    key: &[u8],
    salt: u8,
) -> Result<NativeSubledgerRecorded, Refusal> {
    let cx = h.ctx();
    let day = h.day();
    let description = Erasable::seal(
        &"native subledger".to_string(),
        None,
        &h.book.seal_key,
        [salt; 32],
        [salt; 24],
    );
    h.runtime
        .block_on(create_native_subledger(
            &mut h.db,
            &cx,
            &h.book,
            spec,
            PRINCIPAL,
            day,
            key,
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
}

fn party(h: &mut Harness, code: &str) -> VId {
    let cx = h.ctx();
    let day = h.day();
    let name = Erasable::seal(
        &code.to_string(),
        None,
        &h.book.seal_key,
        [31; 32],
        [32; 24],
    );
    let description = Erasable::seal(
        &"party".to_string(),
        None,
        &h.book.seal_key,
        [33; 32],
        [34; 24],
    );
    let spec = fa_model::PartySpec {
        code: code.into(),
        kind: fa_model::PartyKind::Customer,
        name,
        identifiers: Vec::new(),
        external_ids: Vec::new(),
    };
    h.runtime
        .block_on(create_party(
            &mut h.db,
            &cx,
            &h.book,
            &spec,
            PRINCIPAL,
            day,
            code.as_bytes(),
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    fa_model::party_value_vid(h.book.book_id, code)
}

fn tagged_invoice(h: &Harness, party: VId, key: &[u8]) -> EntryPayload {
    let mut invoice = h.invoice(10_000, key);
    invoice.legs[0].dimension_set = vec![(fa_model::PARTY_DIMENSION, party)];
    invoice
}

#[test]
fn designation_is_journaled_historical_and_semantically_idempotent() {
    let mut h = harness();
    let before = h.db.frontier().unwrap();
    let definition = spec(&h);
    let first = register(&mut h, &definition, b"native-register", 41).unwrap();
    assert!(!first.already_recorded);
    assert_eq!(
        first.subledger.vid,
        native_subledger_vid(h.book.book_id, h.receivable)
    );
    assert!(
        native_subledgers_at(&h.db, &h.book, before)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        native_subledgers_at(&h.db, &h.book, first.subledger.recorded_at).unwrap(),
        vec![first.subledger.clone()]
    );
    assert!(fa_journal::chart::read_at(&h.db, &h.book, first.subledger.recorded_at).is_ok());
    let retry = register(&mut h, &definition, b"native-register", 42).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.subledger, first.subledger);
    assert_eq!(h.db.frontier().unwrap(), first.subledger.recorded_at);
    let mut changed = definition.clone();
    changed.name = "Different".into();
    assert_eq!(
        register(&mut h, &changed, b"native-register", 43)
            .unwrap_err()
            .code,
        "FA-REF-032"
    );
    assert_eq!(
        register(&mut h, &definition, b"native-other-key", 44)
            .unwrap_err()
            .code,
        "FA-REF-100"
    );
}

#[test]
fn control_leaf_requires_real_party_detail_without_partial_publication() {
    let mut h = harness();
    let customer = party(&mut h, "CUST-A");
    let definition = spec(&h);
    register(&mut h, &definition, b"native-register", 45).unwrap();
    let head = h.db.frontier().unwrap();
    let refusal = h
        .post(h.request(h.invoice(10_000, b"anonymous"), &["post"]))
        .unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-005", exit::REFUSAL));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(
        read_entry(
            &h.db,
            entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), b"anonymous")
        )
        .unwrap()
        .is_none()
    );
    let invalid = tagged_invoice(&h, VId(9999), b"unknown-party");
    assert_eq!(
        h.post(h.request(invalid, &["post"])).unwrap_err().code,
        "FA-REF-005"
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    let invoice = tagged_invoice(&h, customer, b"with-party");
    assert!(h.post(h.request(invoice, &["post"])).is_ok());
}

#[test]
fn adoption_requires_entire_historical_party_detail_and_correct_account_kind() {
    let mut h = harness();
    h.post(h.request(h.invoice(7, b"old-anonymous"), &["post"]))
        .unwrap();
    let head = h.db.frontier().unwrap();
    let definition = spec(&h);
    assert_eq!(
        register(&mut h, &definition, b"adopt-anonymous", 46)
            .unwrap_err()
            .code,
        "FA-REF-005"
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(
        native_subledgers_at(&h.db, &h.book, head)
            .unwrap()
            .is_empty()
    );

    let mut clean = harness();
    let customer = party(&mut clean, "CUST-A");
    let invoice = tagged_invoice(&clean, customer, b"old-detailed");
    clean.post(clean.request(invoice, &["post"])).unwrap();
    let mut definition = spec(&clean);
    definition.kind = NativeSubledgerKind::Payables;
    let head = clean.db.frontier().unwrap();
    assert_eq!(
        register(&mut clean, &definition, b"wrong-kind", 47)
            .unwrap_err()
            .code,
        "FA-REF-100"
    );
    assert_eq!(clean.db.frontier().unwrap(), head);
    definition.kind = NativeSubledgerKind::Receivables;
    register(&mut clean, &definition, b"adopt-detailed", 48).unwrap();
}

#[test]
fn prepared_anonymous_post_cannot_cross_subledger_registration() {
    let mut h = harness();
    let cx = h.ctx();
    let request = h.request(h.invoice(25, b"prepared-anonymous"), &["post"]);
    let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &cx, &h.book, request)
        .unwrap()
        .unwrap()
    else {
        panic!("expected a fresh prepared invoice")
    };
    let definition = spec(&h);
    register(&mut h, &definition, b"intervening-designation", 49).unwrap();
    let head = h.db.frontier().unwrap();
    let refusal = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &cx))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-030");
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn registered_control_cannot_be_promoted_or_hidden_by_a_redirected_pointer() {
    let mut h = harness();
    let customer = party(&mut h, "CUST-A");
    let definition = spec(&h);
    let registered = register(&mut h, &definition, b"designation", 50).unwrap();
    let head = h.db.frontier().unwrap();
    let cx = h.ctx();
    let description = Erasable::seal(
        &"promote".to_string(),
        None,
        &h.book.seal_key,
        [51; 32],
        [51; 24],
    );
    let day = h.day();
    let refusal = h
        .runtime
        .block_on(promote_to_summary(
            &mut h.db,
            &cx,
            &h.book,
            "1200",
            day,
            PRINCIPAL,
            day,
            b"promote-native",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-002");
    assert_eq!(h.db.frontier().unwrap(), head);

    let mut txn = h.db.begin(&cx.txn()).unwrap();
    let old = txn
        .vertex_property(&h.db, h.receivable, property::TARGET_REF)
        .unwrap();
    let mut change = fgdb::WriteBatch::new(relation::IN_BOOK);
    change.compare_and_set_vertex_property(
        h.receivable,
        property::TARGET_REF,
        old,
        fa_journal::rows::scalar_bytes("bad control_of", VId(999).0.to_le_bytes().to_vec())
            .unwrap(),
        fgdb::WriteMismatchPolicy::AbortWrite,
    );
    txn.write_ordered(&mut h.db, vec![change]).unwrap();
    h.runtime
        .block_on(txn.commit(&mut h.db, &cx.commit()))
        .unwrap();
    assert!(native_subledgers_at(&h.db, &h.book, h.db.frontier().unwrap()).is_err());
    let request = h.request(tagged_invoice(&h, customer, b"corrupt-pointer"), &["post"]);
    assert!(
        h.runtime
            .block_on(post(&mut h.db, &cx, &h.book, request))
            .is_err()
    );
    assert!(native_subledgers_at(&h.db, &h.book, registered.subledger.recorded_at).is_ok());
}

#[test]
fn schema_authority_is_required_and_codec_refuses_malformed_specs() {
    let mut h = harness();
    let definition = spec(&h);
    let cx = h.ctx();
    let day = h.day();
    let before = h.db.frontier().unwrap();
    let description = Erasable::seal(
        &"registration".to_string(),
        None,
        &h.book.seal_key,
        [52; 32],
        [52; 24],
    );
    let refusal = h
        .runtime
        .block_on(create_native_subledger(
            &mut h.db,
            &cx,
            &h.book,
            &definition,
            PRINCIPAL,
            day,
            b"not-authorized",
            description,
            &Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-011");
    assert_eq!(h.db.frontier().unwrap(), before);
    let bytes = definition.encode().unwrap();
    assert_eq!(NativeSubledgerSpec::decode(&bytes).unwrap(), definition);
    let mut extra = bytes;
    extra.push(0);
    assert!(NativeSubledgerSpec::decode(&extra).is_err());
    let mut empty = definition;
    empty.name.clear();
    assert!(NativeSubledgerSpec::decode(&empty.encode().unwrap()).is_err());
}
