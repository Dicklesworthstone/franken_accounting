//! Large canonical Entries exercise the production posting and batch paths.
//! Fragment boundaries must never split an accounting entry or change its legs.

use super::*;
use fa_journal::entry_storage;
use fa_model::symbols::label;

fn large_legs(h: &Harness) -> Vec<LegPayload> {
    (1..=256).flat_map(|amount| h.rent_legs(amount)).collect()
}

#[test]
fn large_entry_keeps_one_publication_exact_bytes_and_original_retry() {
    let mut h = harness();
    let proposal = h.proposal(large_legs(&h), b"large-fragmented", EntryClass::ORIGINAL);
    let canonical = proposal.clone().seal(Vec::new(), None).unwrap();
    let encoded = canonical.encode().unwrap();
    assert!(encoded.len() > 16_384);
    let before = h.db.frontier().unwrap();
    let posted = h.post(h.request(proposal.clone(), &["post"])).unwrap();
    let at = posted.recorded_at();
    assert_eq!(at.0, before.0 + 1);
    assert!(
        h.db.vertex_at(posted.entry_ref().vid, before)
            .unwrap()
            .is_none()
    );
    let root = h.db.vertex(posted.entry_ref().vid).unwrap().unwrap();
    let stored = fa_journal::rows::bytes(&root, property::FA_PAYLOAD, "entry root").unwrap();
    assert!(entry_storage::is_stored_entry_payload(&stored));
    assert_eq!(
        entry_storage::payload_at(&h.db, &root, at).unwrap(),
        encoded
    );
    assert_eq!(read_entry(&h.db, root.vid).unwrap().unwrap().0, canonical);
    assert_eq!(posted.entry_ref(), canonical.entry_ref(root.vid));
    assert!(entry_storage::mirrors_match(&root, &canonical).unwrap());

    let born =
        h.db.vertices_at(at)
            .unwrap()
            .into_iter()
            .filter(|row| row.created_at == at)
            .collect::<Vec<_>>();
    assert_eq!(
        born.iter()
            .filter(|row| row.labels == [label::ENTRY])
            .count(),
        1
    );
    assert_eq!(
        born.iter().filter(|row| row.labels == [label::LEG]).count(),
        512
    );
    let fragments = born
        .iter()
        .filter(|row| row.labels == [label::ENTRY_FRAGMENT])
        .collect::<Vec<_>>();
    assert_eq!(fragments.len(), encoded.len().div_ceil(4096));
    for fragment in fragments {
        assert_eq!(fragment.created_at, at);
        assert!(h.db.vertex_at(fragment.vid, before).unwrap().is_none());
        assert_eq!(fragment.props.len(), 3);
        assert!(
            fa_journal::rows::bytes(fragment, property::FA_PAYLOAD, "fragment")
                .unwrap()
                .len()
                <= 4096
        );
    }
    assert!(
        fa_journal::verify_projections(&h.db, &h.book, Some(at))
            .unwrap()
            .drift
            .is_empty()
    );
    fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, Some(at)).unwrap();

    let retry = h.post(h.request(proposal, &["post"])).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), at);
    assert_eq!(h.db.frontier().unwrap(), at);

    // A smaller payload cannot rebind a key whose recorded Entry now lives
    // in fragments. Its refusal must preserve the original publication.
    let changed = h.proposal(h.rent_legs(256), b"large-fragmented", EntryClass::ORIGINAL);
    let refusal = h.post(h.request(changed, &["post"])).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), at);
    assert_eq!(read_entry(&h.db, root.vid).unwrap().unwrap().0, canonical);
}

#[test]
fn atomic_large_pending_and_resolution_read_the_same_staged_fragments() {
    let mut h = harness();
    let legs = large_legs(&h);
    let mut pending = h.proposal(legs.clone(), b"large-hold", EntryClass::PENDING);
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let reference = h.member_ref(&pending);
    let resolution = h.resolution_posts(reference, legs, (0..512).collect(), b"large-resolution");
    let batch = h.batch(b"large-atomic-lifecycle", vec![pending, resolution]);
    let before = h.db.frontier().unwrap();
    let posted = h.post_batch(batch.clone()).unwrap();
    assert_eq!(posted.recorded_at.0, before.0 + 1);
    assert_eq!(posted.entries.len(), 2);
    for reference in &posted.entries {
        let (entry, at) = read_entry(&h.db, reference.vid).unwrap().unwrap();
        assert_eq!(at, posted.recorded_at);
        assert_eq!(entry.entry_ref(reference.vid), *reference);
        assert_eq!(entry.proposal.legs.len(), 512);
        assert!(entry.encode().unwrap().len() > 16_384);
    }
    assert!(
        fa_journal::verify_projections(&h.db, &h.book, None)
            .unwrap()
            .drift
            .is_empty()
    );
    fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, None).unwrap();
    let retry = h.post_batch(batch).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at);
}

#[test]
fn changed_fragment_and_identical_restoration_refuse_but_original_prefix_survives() {
    let mut h = harness();
    let proposal = h.proposal(large_legs(&h), b"fragment-corruption", EntryClass::ORIGINAL);
    let posted = h.post(h.request(proposal.clone(), &["post"])).unwrap();
    let intact = posted.recorded_at();
    let fragment =
        h.db.vertices_at(intact)
            .unwrap()
            .into_iter()
            .find(|row| row.labels == [label::ENTRY_FRAGMENT])
            .unwrap();
    let original = fa_journal::rows::bytes(&fragment, property::FA_PAYLOAD, "fragment").unwrap();
    let mut damaged = original.clone();
    damaged[0] ^= 1;
    let mut edit = fgdb::WriteBatch::new(relation::HAS_LEG);
    edit.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(damaged).unwrap()),
    );
    h.write_raw(edit);
    assert!(read_entry(&h.db, posted.entry_ref().vid).is_err());
    assert!(
        fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, None).is_err()
    );
    assert!(
        fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, Some(intact))
            .is_ok()
    );

    // Admission from request metadata must still win over the poisoned body.
    let before = h.db.frontier().unwrap();
    h.post(h.request(proposal, &["read"])).unwrap_err();
    assert_eq!(h.db.frontier().unwrap(), before);

    let mut restore = fgdb::WriteBatch::new(relation::HAS_LEG);
    restore.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(original).unwrap()),
    );
    h.write_raw(restore);
    assert!(read_entry(&h.db, posted.entry_ref().vid).is_err());
    assert!(
        fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, None).is_err()
    );
    let original_root =
        h.db.vertex_at(posted.entry_ref().vid, intact)
            .unwrap()
            .unwrap();
    assert_eq!(
        entry_storage::decode_at(&h.db, &original_root, intact)
            .unwrap()
            .entry_digest,
        posted.entry_ref().entry_digest
    );
}

#[test]
fn previous_native_inline_entries_above_four_kib_remain_readable() {
    let mut h = harness_legacy();
    let legs = (1..=48).flat_map(|amount| h.rent_legs(amount)).collect();
    let proposal = h.proposal(legs, b"legacy-inline-large", EntryClass::ORIGINAL);
    let canonical = proposal.clone().seal(Vec::new(), None).unwrap();
    let bytes = canonical.encode().unwrap();
    assert!(bytes.len() > 4096 && bytes.len() < 12_000);
    let reference = super::outcome_recovery_tests::write_legacy(&mut h, proposal.clone());
    let row = h.db.vertex(reference.vid).unwrap().unwrap();
    let at = row.created_at;
    assert_eq!(entry_storage::payload_at(&h.db, &row, at).unwrap(), bytes);
    assert!(entry_storage::mirrors_match(&row, &canonical).unwrap());
    assert!(!entry_storage::is_stored_entry_payload(
        &fa_journal::rows::bytes(&row, property::FA_PAYLOAD, "legacy root").unwrap()
    ));
    fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, Some(at)).unwrap();
    let retry = h.post(h.request(proposal, &["post"])).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), reference);
    assert_eq!(h.db.frontier().unwrap(), at);
}

fn large_chart(h: &Harness) -> Vec<AccountSpec> {
    let mut accounts = vec![AccountSpec {
        code: "bulk".into(),
        name: "Imported operating accounts".into(),
        account_type: 1,
        normal_balance: 0,
        is_leaf: false,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: None,
        limit: None,
    }];
    accounts.extend((0..512).map(|ordinal| AccountSpec {
        code: format!("bulk-{ordinal:04}"),
        name: format!("Imported subsidiary operating account {ordinal:04}"),
        account_type: 1,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: Some("bulk".into()),
        limit: None,
    }));
    accounts
}

fn install_large_chart(
    h: &mut Harness,
    accounts: &[AccountSpec],
    capability: &Capability,
) -> Result<Result<fa_journal::genesis::ChartInstalled, Refusal>, KernelError> {
    let ctx = h.ctx();
    let day = h.day();
    let description = h.statement("large chart import", 111);
    h.runtime.block_on(install_chart(
        &mut h.db,
        &ctx,
        &h.book,
        accounts,
        PRINCIPAL,
        day,
        b"large-chart",
        description,
        capability,
    ))
}

#[test]
fn large_chart_import_keeps_one_publication_and_replays_historical_accounts() {
    let mut h = harness();
    let accounts = large_chart(&h);
    let capability = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    let before = h.db.frontier().unwrap();
    let initial_count = fa_journal::chart::read_at(&h.db, &h.book, before)
        .unwrap()
        .accounts()
        .len();
    let installed = install_large_chart(&mut h, &accounts, &capability)
        .expect("large chart storage")
        .expect("chart admitted");
    let at = installed.recorded_at;
    assert_eq!(at.0, before.0 + 1);
    assert_eq!(installed.accounts, accounts.len());
    let (canonical, recorded_at) = read_entry(&h.db, installed.control_entry).unwrap().unwrap();
    assert_eq!(recorded_at, at);
    let encoded = canonical.encode().unwrap();
    assert!(
        encoded.len() > 16_384,
        "this chart must exceed the substrate's single-row limit"
    );
    let root = h.db.vertex(installed.control_entry).unwrap().unwrap();
    assert!(entry_storage::is_stored_entry_payload(
        &fa_journal::rows::bytes(&root, property::FA_PAYLOAD, "chart root").unwrap()
    ));
    assert_eq!(
        entry_storage::payload_at(&h.db, &root, at).unwrap(),
        encoded
    );
    assert!(entry_storage::mirrors_match(&root, &canonical).unwrap());

    let born =
        h.db.vertices_at(at)
            .unwrap()
            .into_iter()
            .filter(|row| row.created_at == at)
            .collect::<Vec<_>>();
    assert_eq!(
        born.iter()
            .filter(|row| row.labels == [label::ENTRY])
            .count(),
        1
    );
    assert_eq!(
        born.iter()
            .filter(|row| row.labels == [label::ACCOUNT])
            .count(),
        accounts.len()
    );
    let fragments = born
        .iter()
        .filter(|row| row.labels == [label::ENTRY_FRAGMENT])
        .collect::<Vec<_>>();
    assert_eq!(fragments.len(), encoded.len().div_ceil(4096));
    for fragment in fragments {
        assert!(h.db.vertex_at(fragment.vid, before).unwrap().is_none());
        assert!(
            fa_journal::rows::bytes(fragment, property::FA_PAYLOAD, "chart fragment")
                .unwrap()
                .len()
                <= 4096
        );
    }
    let old_chart = fa_journal::chart::read_at(&h.db, &h.book, before).unwrap();
    let current_chart = fa_journal::chart::read_at(&h.db, &h.book, at).unwrap();
    assert_eq!(old_chart.accounts().len(), initial_count);
    assert_eq!(
        current_chart.accounts().len(),
        initial_count + accounts.len()
    );
    let summary = account_vid(h.book.book_id, "bulk");
    assert_eq!(current_chart.leaves_under(summary).unwrap().len(), 512);
    for spec in &accounts {
        let vid = account_vid(h.book.book_id, &spec.code);
        assert!(!old_chart.accounts().contains_key(&vid));
        let account = &current_chart.accounts()[&vid];
        assert_eq!(account.code, spec.code);
        assert_eq!(account.name, spec.name);
        assert_eq!(account.is_leaf, spec.is_leaf);
    }

    let retry = install_large_chart(&mut h, &accounts, &capability)
        .unwrap()
        .unwrap();
    assert_eq!(retry.control_entry, installed.control_entry);
    assert_eq!(retry.recorded_at, at);
    assert_eq!(h.db.frontier().unwrap(), at);
    let mut changed = accounts.clone();
    changed.last_mut().unwrap().name.push_str(" changed");
    let refusal = install_large_chart(&mut h, &changed, &capability)
        .unwrap()
        .unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), at);

    // The newly installed chart must remain usable by the real posting
    // kernel, not merely decodable through its storage manifest.
    let mut legs = h.rent_legs(75);
    legs[0].account_ref = account_vid(h.book.book_id, "bulk-0000");
    let proposal = h.proposal(legs, b"large-chart-posting", EntryClass::ORIGINAL);
    h.post(h.request(proposal, &["post"])).unwrap();
    assert!(
        fa_journal::verify_projections(&h.db, &h.book, None)
            .unwrap()
            .drift
            .is_empty()
    );
    fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, None).unwrap();
    assert_eq!(
        entry_storage::payload_at(&h.db, &root, at).unwrap(),
        encoded
    );
}

#[test]
fn chart_fragments_refuse_tampering_without_losing_the_original_chart() {
    let mut h = harness();
    let accounts = large_chart(&h);
    let capability = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    let installed = install_large_chart(&mut h, &accounts, &capability)
        .unwrap()
        .unwrap();
    let intact = installed.recorded_at;
    let original_chart = fa_journal::chart::read_at(&h.db, &h.book, intact).unwrap();
    let fragment =
        h.db.vertices_at(intact)
            .unwrap()
            .into_iter()
            .find(|row| row.created_at == intact && row.labels == [label::ENTRY_FRAGMENT])
            .unwrap();
    let original =
        fa_journal::rows::bytes(&fragment, property::FA_PAYLOAD, "chart fragment").unwrap();
    let mut damaged = original.clone();
    damaged[0] ^= 1;
    let mut edit = fgdb::WriteBatch::new(relation::CHILD_OF);
    edit.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(damaged).unwrap()),
    );
    h.write_raw(edit);
    let damaged_head = h.db.frontier().unwrap();
    assert!(read_entry(&h.db, installed.control_entry).is_err());
    assert!(fa_journal::chart::read_at(&h.db, &h.book, damaged_head).is_err());
    assert_eq!(
        fa_journal::chart::read_at(&h.db, &h.book, intact)
            .unwrap()
            .accounts(),
        original_chart.accounts()
    );
    install_large_chart(
        &mut h,
        &accounts,
        &Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
    )
    .expect("authority refusal must precede reading the damaged fragments")
    .expect_err("read authority cannot install a chart");
    assert_eq!(h.db.frontier().unwrap(), damaged_head);

    let mut restore = fgdb::WriteBatch::new(relation::CHILD_OF);
    restore.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(original).unwrap()),
    );
    h.write_raw(restore);
    assert!(read_entry(&h.db, installed.control_entry).is_err());
    assert!(fa_journal::chart::read_at(&h.db, &h.book, h.db.frontier().unwrap()).is_err());
    assert_eq!(
        fa_journal::chart::read_at(&h.db, &h.book, intact)
            .unwrap()
            .accounts(),
        original_chart.accounts()
    );
}
