//! Large real import controls must outlive the substrate's per-row ceiling.

use super::*;
use fa_journal::migration::{read_run_body_at, verify_run_visibility_at};
use fa_journal::rows::{bytes, scalar_bytes};
use fa_model::symbols::{label, property, relation};

fn large_run(k: &mut Kernel) -> (RunSpec, Vec<(String, String)>) {
    let pairs = (0..100)
        .map(|index| {
            (
                format!("expense-{index:03}-{}", "x".repeat(50)),
                format!("offset-{index:03}-{}", "y".repeat(51)),
            )
        })
        .collect::<Vec<_>>();
    let accounts = pairs
        .iter()
        .flat_map(|(debit, credit)| [(debit, false), (credit, true)])
        .map(|(code, credit)| AccountSpec {
            code: code.clone(),
            name: "Published source category".into(),
            account_type: if credit { 3 } else { 5 },
            normal_balance: u8::from(credit),
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd()),
            parent_code: None,
            limit: None,
        })
        .collect::<Vec<_>>();
    // Each separately declared chart change fits the existing SchemaControl
    // envelope; the run's complete source trial balance remains one body.
    for (ordinal, accounts) in accounts.chunks(20).enumerate() {
        let ctx = k.ctx();
        let capability = capability(&["schema_change"]);
        let key = format!("large-source-chart-{ordinal}");
        let description = sealed(&k.book, "retain source chart categories");
        k.runtime
            .block_on(install_chart(
                &mut k.db,
                &ctx,
                &k.book,
                accounts,
                PRINCIPAL,
                opening_date(),
                key.as_bytes(),
                description,
                &capability,
            ))
            .unwrap()
            .unwrap();
    }
    let mut lines = pairs
        .iter()
        .flat_map(|(debit, credit)| {
            [
                (debit.clone(), usd().0, 100),
                (credit.clone(), usd().0, -100),
            ]
        })
        .collect::<Vec<_>>();
    lines.sort();
    (
        RunSpec {
            key: "large-retained-source".into(),
            opening_date: opening_date(),
            lines,
            periods: Vec::new(),
            full_detail: None,
        },
        pairs,
    )
}

#[test]
fn large_run_body_is_atomic_durable_historical_and_corruption_detecting() {
    let (mut k, _) = setup();
    let (spec, pairs) = large_run(&mut k);
    let body = body_of(&k, &spec);
    let canonical = body.canonical_bytes().unwrap();
    assert!(
        canonical.len() > 16_384,
        "exercise the former native row failure"
    );
    let before_open = k.db.frontier().unwrap();
    let opened = kernel_open(&mut k, &spec, "open-large-source", &["post", "migrate"])
        .expect("the complete declared run fits authenticated fragment storage");
    let run = opened.run;
    assert_eq!(opened.recorded_at.0, before_open.0 + 1);
    assert!(read_run_body_at(&k.db, run, before_open).unwrap().is_none());
    let fragments =
        k.db.vertices()
            .unwrap()
            .into_iter()
            .filter(|row| row.labels == [label::MIGRATION_RUN_FRAGMENT])
            .collect::<Vec<_>>();
    assert_eq!(fragments.len(), canonical.len().div_ceil(4096));
    assert!(
        fragments
            .iter()
            .all(|row| row.created_at == opened.recorded_at)
    );
    assert!(
        bytes(
            &k.db.vertex(run).unwrap().unwrap(),
            property::FA_PAYLOAD,
            "run manifest"
        )
        .unwrap()
        .len()
            < 128
    );
    k = crash_and_reopen(k);
    let observed = read_run(&k.db, run, None).unwrap().unwrap();
    assert_eq!(observed.body, body);
    assert_eq!(observed.body.canonical_bytes().unwrap(), canonical);
    assert_eq!(observed.body.digest().unwrap(), body.digest().unwrap());
    assert_eq!(observed.opened_at, opened.recorded_at);
    let before_retry = k.db.frontier().unwrap();
    assert!(
        kernel_open(&mut k, &spec, "open-large-source", &["post", "migrate"])
            .unwrap()
            .already_recorded
    );
    assert_eq!(k.db.frontier().unwrap(), before_retry);

    for (index, chunk) in pairs.chunks(10).enumerate() {
        let legs = chunk
            .iter()
            .flat_map(|(debit, credit)| {
                [
                    leg(fa_reference::Side::Debit, debit, 100),
                    leg(fa_reference::Side::Credit, credit, 100),
                ]
            })
            .collect();
        post_chunk(&mut k, run, &format!("large-source-{index}"), legs);
    }
    k = crash_and_reopen(k);
    let before_finalize = k.db.frontier().unwrap();
    assert!(
        fold_period_at(&k.db, &k.book, OPENING, None)
            .unwrap()
            .cells
            .is_empty()
    );
    let proposal = kernel_plan(&k, run, kind::FINALIZE, "finalize-large-source").unwrap();
    let finalized = kernel_transition(&mut k, proposal, true).unwrap();
    k = crash_and_reopen(k);
    let observed = read_run(&k.db, run, None).unwrap().unwrap();
    assert_eq!(observed.body, body);
    assert_eq!(observed.state, RunState::Finalized);
    assert_eq!(
        observed.opened_at, opened.recorded_at,
        "state version is not the fragment birth"
    );
    assert_eq!(
        read_run(&k.db, run, Some(before_finalize))
            .unwrap()
            .unwrap()
            .state,
        RunState::Open
    );
    assert!(
        fold_period_at(&k.db, &k.book, OPENING, Some(before_finalize))
            .unwrap()
            .cells
            .is_empty()
    );
    let folded = fold_period_at(&k.db, &k.book, OPENING, None).unwrap();
    let actual = folded
        .cells
        .iter()
        .map(|cell| (cell.key.account, cell.net().unwrap()))
        .collect::<BTreeMap<_, _>>();
    let expected = spec
        .lines
        .iter()
        .map(|(code, _, net)| (account_vid(k.book.book_id, code), *net))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(actual, expected);
    // A reopened low-level FGDB handle starts with its checkpoint frontier,
    // not a hydrated genesis delta cursor. The visibility verifier requires
    // the caller to load complete history first, as the production facade does.
    let ctx = k.ctx();
    let before_hydration = k.db.frontier().unwrap();
    k.runtime
        .block_on(fa_journal::scratch::ensure_history(&mut k.db, &ctx))
        .unwrap()
        .unwrap();
    assert_eq!(k.db.frontier().unwrap(), before_hydration);
    verify_run_visibility_at(&k.db, &k.book, finalized.recorded_at).unwrap();

    // Authoritative fragments survive accounting scratch replay together with
    // their root; the separate maintenance/certificate exclusions cannot drop
    // the run's source controls.
    let mut scratch = empty_scratch(&k);
    let map = replay(&mut k, &mut scratch, finalized.recorded_at).unwrap();
    verify(&k, &scratch, &map).unwrap();
    let scratch_run = read_run(&scratch, run, None).unwrap().unwrap();
    assert_eq!(scratch_run.body, body);
    assert_eq!(scratch_run.state, RunState::Finalized);

    let fragment = &fragments[0];
    let original = bytes(fragment, property::FA_PAYLOAD, "original fragment").unwrap();
    let mut damaged = original.clone();
    damaged[0] ^= 1;
    let mut edit = WriteBatch::new(relation::IN_MIGRATION_RUN);
    edit.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(scalar_bytes("damaged source body", damaged).unwrap()),
    );
    write_raw(&mut k, edit);
    assert!(read_run(&k.db, run, None).is_err());
    assert!(read_run_body_at(&k.db, run, k.db.frontier().unwrap()).is_err());
    assert!(verify_run_visibility_at(&k.db, &k.book, k.db.frontier().unwrap()).is_err());
    assert_eq!(
        read_run_body_at(&k.db, run, finalized.recorded_at).unwrap(),
        Some(body.clone())
    );

    let mut restore = WriteBatch::new(relation::IN_MIGRATION_RUN);
    restore.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(scalar_bytes("restored source body", original).unwrap()),
    );
    write_raw(&mut k, restore);
    k = crash_and_reopen(k);
    assert!(
        read_run(&k.db, run, None).is_err(),
        "rewritten bytes do not regain their original birth"
    );
    assert_eq!(
        read_run_body_at(&k.db, run, finalized.recorded_at).unwrap(),
        Some(body)
    );
}
