//! Independent wire fixtures: no producer codec or native kernel dependency.
//! These prove the outsider membership contract, not economic correctness.

use super::*;

const SOURCE_FORMAT: &[u8] = b"FA-MIGRATION-SOURCE\0";
const SOURCE_DOMAIN: &[u8] = b"fa:migration-source:v1";
type Citation = ([u8; 32], [u8; 32], u8);

fn commit(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut framed = Writer::default();
    for part in parts {
        framed.bytes(part);
    }
    hash_parts(domain, &[&framed.buf])
}

fn citations() -> Vec<Citation> {
    let mut values: Vec<_> = [[7; 32], [8; 32]]
        .into_iter()
        .map(|digest| {
            (
                commit(b"fa:oid:document:v1", &[&[1; 16], &digest]),
                digest,
                1,
            )
        })
        .collect();
    values.sort_unstable();
    values
}

fn entry(
    seq: u64,
    day: i32,
    key: u64,
    legs: &[(u8, u128, i128)],
    control: Option<(u8, [u8; 32], [u8; 32])>,
    evidence: &[Citation],
) -> Record {
    entry_in_unit(seq, day, key, 1, legs, control, evidence)
}

fn entry_in_unit(
    seq: u64,
    day: i32,
    key: u64,
    unit: u32,
    legs: &[(u8, u128, i128)],
    control: Option<(u8, [u8; 32], [u8; 32])>,
    evidence: &[Citation],
) -> Record {
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&[1; 16])
        .fixed(&[0; 16])
        .u16(if control.is_some() {
            CLASS_MIGRATION_CONTROL
        } else {
            CLASS_MIGRATION
        })
        .i32(day)
        .u8(0);
    sealed(&mut w);
    w.u8(0).count(legs.len());
    for (side, account, amount) in legs {
        w.u8(*side)
            .u128(*account)
            .u32(unit)
            .i128(*amount)
            .u8(0)
            .count(0)
            .u8(0)
            .count(0);
    }
    if let Some((kind, _, digest)) = control {
        w.u8(1).u8(10).u128(RUN).u8(kind).fixed(&digest);
    } else {
        w.u8(0);
    }
    w.count(usize::from(!legs.is_empty()));
    if !legs.is_empty() {
        let debits: i128 = legs
            .iter()
            .filter(|(side, _, _)| *side == 0)
            .map(|(_, _, value)| value)
            .sum();
        let credits: i128 = legs
            .iter()
            .filter(|(side, _, _)| *side == 1)
            .map(|(_, _, value)| value)
            .sum();
        w.u32(unit).i128(debits).i128(credits);
    }
    w.u8(0).bytes(&key.to_le_bytes());
    if let Some((_, body, _)) = control {
        w.u8(3).u16(9).fixed(&body);
    } else {
        w.u8(2).u128(RUN).bytes(b"legacy");
        sealed(&mut w);
        w.u8(0).u8(0).u8(0).fixed(&[0; 32]);
    }
    w.u128(1).u8(0).count(evidence.len());
    for (oid, digest, role) in evidence {
        w.fixed(oid).fixed(digest).u8(*role);
    }
    w.count(0).u8(0).count(0).count(0);
    let len = w.buf.len();
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let approval_envelope = [0; 5];
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &approval_envelope]);
    w.fixed(&approval_envelope)
        .fixed(&proposal_digest)
        .fixed(&digest);
    Record {
        envelope: envelope_of_entry(&w.buf, len, seq, 0).unwrap(),
        len,
        payload: w.buf,
    }
}

fn chunk(key: u64, seq: u64, day: i32, account: u128, reverse: bool) -> Record {
    entry(
        seq,
        day,
        key,
        &[
            (u8::from(reverse), account, 5000),
            (u8::from(!reverse), account + 10, 5000),
        ],
        None,
        &[],
    )
}

fn member(record: &Record) -> (u128, [u8; 32]) {
    match metadata(&record.envelope, &record.payload[..record.len], 0).unwrap() {
        Metadata::Chunk { vid, digest, .. } => (vid, digest),
        _ => panic!("fixture is not a migration member"),
    }
}

fn manifest(body: &[u8], chunks: &[Record]) -> Vec<u8> {
    let mut w = Writer::default();
    let source = [7; 32];
    let package = [8; 32];
    w.fixed(SOURCE_FORMAT)
        .u16(1)
        .fixed(&[1; 16])
        .u128(RUN)
        .fixed(&body_digest(body))
        .fixed(&commit(b"fa:oid:document:v1", &[&[1; 16], &source]))
        .fixed(&source)
        .fixed(&commit(b"fa:oid:document:v1", &[&[1; 16], &package]))
        .fixed(&package)
        .u64((chunks.len() * 2) as u64)
        .count(chunks.len());
    for chunk in chunks {
        let (vid, digest) = member(chunk);
        w.u128(vid).fixed(&digest);
    }
    w.buf
}

fn tie_out(body: &[u8], manifest: &[u8], chunks: &[Record]) -> [u8; 32] {
    let mut population: Vec<_> = chunks
        .iter()
        .map(|chunk| (chunk.envelope.commit_seq, member(chunk)))
        .collect();
    population.sort_unstable_by_key(|(sequence, (vid, _))| (*sequence, *vid));
    let mut w = Writer::default();
    w.count(population.len());
    for (_, (vid, digest)) in population {
        w.u128(vid).fixed(&digest);
    }
    commit(
        b"fa:migration-tie-out:v2",
        &[
            &body_digest(body),
            &commit(SOURCE_DOMAIN, &[manifest]),
            &w.buf,
        ],
    )
}

fn history(
    body: &[u8],
    manifest: &[u8],
    mut chunks: Vec<Record>,
    terminal: Option<u8>,
) -> Vec<Record> {
    let body_digest = body_digest(body);
    let mut records = vec![
        entry(1, 100, 900, &[], Some((0, body_digest, body_digest)), &[]),
        entry(
            2,
            100,
            901,
            &[],
            Some((3, body_digest, commit(SOURCE_DOMAIN, &[manifest]))),
            &citations(),
        ),
    ];
    for (index, chunk) in chunks.iter_mut().enumerate() {
        chunk.envelope = envelope_of_entry(&chunk.payload, chunk.len, index as u64 + 3, 0).unwrap();
    }
    let digest = tie_out(body, manifest, &chunks);
    records.extend(chunks);
    if let Some(kind) = terminal {
        records.push(entry(
            records.len() as u64 + 1,
            100,
            902,
            &[],
            Some((kind, body_digest, digest)),
            &[],
        ));
    }
    records
}

fn proof(
    records: &[Record],
    body: &[u8],
    manifest: Option<&[u8]>,
    debits: i128,
    credits: i128,
    through: Option<i32>,
    format: &[u8],
) -> (Vec<u8>, Checkpoint) {
    proof_for_scope(
        records,
        body,
        manifest,
        debits,
        credits,
        crate::BalanceScope {
            account: 10,
            unit: 1,
            effective_through: through,
        },
        format,
    )
}

fn proof_for_scope(
    records: &[Record],
    body: &[u8],
    manifest: Option<&[u8]>,
    debits: i128,
    credits: i128,
    scope: crate::BalanceScope,
    format: &[u8],
) -> (Vec<u8>, Checkpoint) {
    let checkpoint = Checkpoint {
        book_id: [1; 16],
        branch_id: [0; 16],
        through_seq: records
            .last()
            .map_or(0, |record| record.envelope.commit_seq),
        leaf_count: records.len() as u64,
        root: root_of(
            &records
                .iter()
                .map(|record| leaf_hash(&record.envelope.encode()))
                .collect::<Vec<_>>(),
        ),
    };
    let mut w = Writer::default();
    w.bytes(format)
        .fixed(&checkpoint.encode())
        .u128(scope.account)
        .u32(scope.unit);
    if let Some(day) = scope.effective_through {
        w.u8(1).i32(day);
    } else {
        w.u8(0);
    }
    w.i128(debits).i128(credits).count(records.len());
    for record in records {
        w.bytes(&record.envelope.encode());
    }
    w.count(records.len());
    for (index, record) in records.iter().enumerate() {
        w.u64(index as u64)
            .u32(record.len as u32)
            .bytes(&record.payload);
    }
    w.count(1).u64(0).bytes(body);
    if format == BALANCE_FORMAT_V4 {
        w.count(usize::from(manifest.is_some()));
        if let Some(manifest) = manifest {
            w.u64(1).bytes(manifest);
        }
    }
    (w.buf, checkpoint)
}

/// A complete v4 wire proof for public API tests: both offsetting chunks,
/// their source manifest and citations, and their Finalize tie-out are
/// authenticated by the checkpoint. The gross columns are each 5,000 even
/// though the net is zero; an empty prefix cannot canonically use v4.
pub(crate) fn source_bound_fixture(scope: crate::BalanceScope) -> (Vec<u8>, Checkpoint) {
    let body = body(0, false);
    let day = scope.effective_through.unwrap_or(100);
    let other_account = scope.account ^ 1;
    let chunks = vec![
        entry_in_unit(
            3,
            day,
            1,
            scope.unit,
            &[(0, scope.account, 5000), (1, other_account, 5000)],
            None,
            &[],
        ),
        entry_in_unit(
            4,
            day,
            2,
            scope.unit,
            &[(1, scope.account, 5000), (0, other_account, 5000)],
            None,
            &[],
        ),
    ];
    let manifest = manifest(&body, &chunks);
    let records = history(&body, &manifest, chunks, Some(1));
    proof_for_scope(
        &records,
        &body,
        Some(&manifest),
        5000,
        5000,
        scope,
        BALANCE_FORMAT_V4,
    )
}

fn accepted(
    records: &[Record],
    body: &[u8],
    manifest: &[u8],
    debit: i128,
    credit: i128,
) -> Balance {
    let (proof, anchor) = proof(
        records,
        body,
        Some(manifest),
        debit,
        credit,
        None,
        BALANCE_FORMAT_V4,
    );
    crate::verify_balance(&proof, &anchor).unwrap()
}

#[test]
fn exact_population_counts_gross_entries_and_preserves_out_of_source_order_staging() {
    let body = body(2, false);
    let chunks = vec![
        chunk(1, 3, 100, 10, false),
        chunk(2, 4, 100, 10, false),
        chunk(3, 5, 100, 10, true),
    ];
    let source = manifest(&body, &chunks);
    for order in [
        chunks.clone(),
        vec![chunks[2].clone(), chunks[0].clone(), chunks[1].clone()],
    ] {
        let records = history(&body, &source, order, Some(1));
        let report = accepted(&records, &body, &source, 10000, 5000);
        assert_eq!(report.scope, SCOPE_RECOMPUTATION);
        assert_eq!(report.contributing, vec![2, 3, 4]);
    }
}

#[test]
fn exact_offsetting_omission_fails_even_when_every_net_balance_is_unchanged() {
    let body = body(2, false);
    let chunks = vec![
        chunk(1, 3, 100, 10, false),
        chunk(2, 4, 100, 10, false),
        chunk(3, 5, 100, 10, true),
    ];
    let source = manifest(&body, &chunks);
    let full = history(&body, &source, chunks.clone(), Some(1));
    let report = accepted(&full, &body, &source, 10000, 5000);
    assert_eq!(report.claim.debits - report.claim.credits, 5000);
    // Recompute the final control honestly over the incomplete actual set.
    // Neither a matching net TB nor a self-consistent actual tie-out suffices.
    let omitted = history(&body, &source, vec![chunks[0].clone()], Some(1));
    let (proof, anchor) = proof(
        &omitted,
        &body,
        Some(&source),
        5000,
        0,
        None,
        BALANCE_FORMAT_V4,
    );
    assert!(crate::verify_balance(&proof, &anchor).is_err());
}

#[test]
fn chunk_substitution_duplicate_and_replay_fail_under_new_authentic_prefixes() {
    let body = body(2, false);
    let chunks = vec![chunk(1, 3, 100, 10, false), chunk(2, 4, 100, 10, true)];
    let source = manifest(&body, &chunks);
    let cases = [
        vec![chunks[0].clone(), chunk(99, 4, 100, 10, true)],
        vec![chunks[0].clone(), chunks[0].clone()],
        vec![chunks[0].clone(), chunks[1].clone(), chunks[1].clone()],
    ];
    for chunks in cases {
        let records = history(&body, &source, chunks, Some(1));
        let (proof, anchor) = proof(
            &records,
            &body,
            Some(&source),
            5000,
            5000,
            None,
            BALANCE_FORMAT_V4,
        );
        assert!(crate::verify_balance(&proof, &anchor).is_err());
    }
}

#[test]
fn cutoff_or_unrelated_account_cannot_hide_missing_source_members() {
    let body = body(2, false);
    let chunks = vec![chunk(1, 3, 100, 10, false), chunk(2, 4, 200, 30, false)];
    let source = manifest(&body, &chunks);
    let full = history(&body, &source, chunks.clone(), Some(1));
    let (complete, anchor) = proof(
        &full,
        &body,
        Some(&source),
        5000,
        0,
        Some(100),
        BALANCE_FORMAT_V4,
    );
    assert_eq!(
        crate::verify_balance(&complete, &anchor)
            .unwrap()
            .contributing,
        vec![2]
    );
    let omitted = history(&body, &source, vec![chunks[0].clone()], Some(1));
    let (proof, anchor) = proof(
        &omitted,
        &body,
        Some(&source),
        5000,
        0,
        Some(100),
        BALANCE_FORMAT_V4,
    );
    assert!(crate::verify_balance(&proof, &anchor).is_err());
}

#[test]
fn bound_manifest_cannot_be_omitted_reordered_substituted_or_downgraded() {
    let body = body(2, false);
    let chunks = vec![chunk(1, 3, 100, 10, false), chunk(2, 4, 100, 10, true)];
    let source = manifest(&body, &chunks);
    let records = history(&body, &source, chunks.clone(), Some(1));
    let reversed = manifest(&body, &[chunks[1].clone(), chunks[0].clone()]);
    let mut changed = source.clone();
    let source_commit_offset = SOURCE_FORMAT.len() + 2 + 16 + 16 + 32 + 32;
    changed[source_commit_offset] ^= 1;
    for witness in [None, Some(reversed.as_slice()), Some(changed.as_slice())] {
        let (proof, anchor) = proof(
            &records,
            &body,
            witness,
            5000,
            5000,
            None,
            BALANCE_FORMAT_V4,
        );
        assert!(crate::verify_balance(&proof, &anchor).is_err());
    }
    for format in [
        BALANCE_FORMAT_V2,
        BALANCE_FORMAT_V3,
        b"fa:acc-balance-proof:v5",
    ] {
        let (proof, anchor) = proof(&records, &body, None, 5000, 5000, None, format);
        assert!(crate::verify_balance(&proof, &anchor).is_err());
    }
}

#[test]
fn authenticated_manifest_shape_document_identity_and_source_citations_fail_closed() {
    let body = body(2, false);
    let chunks = vec![chunk(1, 3, 100, 10, false), chunk(2, 4, 100, 10, true)];
    let valid = manifest(&body, &chunks);
    let body_offset = SOURCE_FORMAT.len() + 2 + 16 + 16;
    let rows_offset = body_offset + 32 + 128;
    for changed in [
        {
            let mut bytes = valid.clone();
            bytes[SOURCE_FORMAT.len()] = 2;
            bytes
        },
        {
            let mut bytes = valid.clone();
            bytes[body_offset] ^= 1;
            bytes
        },
        {
            let mut bytes = valid.clone();
            bytes[body_offset + 32] ^= 1;
            bytes
        },
        {
            let mut bytes = valid.clone();
            bytes[rows_offset..rows_offset + 8].copy_from_slice(&1u64.to_le_bytes());
            bytes
        },
        manifest(&body, &[chunks[0].clone(), chunks[0].clone()]),
        {
            let mut bytes = valid.clone();
            bytes.push(0);
            bytes
        },
    ] {
        // The changed bytes are themselves committed by this new BindSource;
        // shape/identity validation must still reject them independently.
        let records = history(&body, &changed, chunks.clone(), Some(1));
        let (proof, anchor) = proof(
            &records,
            &body,
            Some(&changed),
            5000,
            5000,
            None,
            BALANCE_FORMAT_V4,
        );
        assert!(crate::verify_balance(&proof, &anchor).is_err());
    }
    let mut records = history(&body, &valid, chunks, Some(1));
    let mut wrong = citations();
    wrong[0].2 = 2;
    records[1] = entry(
        2,
        100,
        901,
        &[],
        Some((3, body_digest(&body), commit(SOURCE_DOMAIN, &[&valid]))),
        &wrong,
    );
    let (proof, anchor) = proof(
        &records,
        &body,
        Some(&valid),
        5000,
        5000,
        None,
        BALANCE_FORMAT_V4,
    );
    assert!(crate::verify_balance(&proof, &anchor).is_err());
}

#[test]
fn open_and_abandoned_partial_populations_remain_hidden_but_bound() {
    let body = body(2, false);
    let chunks = vec![chunk(1, 3, 100, 10, false), chunk(2, 4, 100, 10, true)];
    let source = manifest(&body, &chunks);
    for terminal in [None, Some(2)] {
        let records = history(&body, &source, vec![chunks[0].clone()], terminal);
        let report = accepted(&records, &body, &source, 0, 0);
        assert!(report.contributing.is_empty());
        let (proof, anchor) = proof(&records, &body, None, 0, 0, None, BALANCE_FORMAT_V4);
        assert!(crate::verify_balance(&proof, &anchor).is_err());
    }
}

#[test]
fn terminal_tieout_binds_actual_publication_order_and_cannot_use_legacy_digest() {
    let body = body(2, false);
    let chunks = vec![chunk(1, 3, 100, 10, false), chunk(2, 4, 100, 10, true)];
    let source = manifest(&body, &chunks);
    let mut records = history(
        &body,
        &source,
        vec![chunks[1].clone(), chunks[0].clone()],
        Some(1),
    );
    for wrong in [[9; 32], tie_out(&body, &source, &chunks)] {
        records[4] = entry(5, 100, 902, &[], Some((1, body_digest(&body), wrong)), &[]);
        let (proof, anchor) = proof(
            &records,
            &body,
            Some(&source),
            5000,
            5000,
            None,
            BALANCE_FORMAT_V4,
        );
        assert!(crate::verify_balance(&proof, &anchor).is_err());
    }
}

#[test]
fn report_frontiers_carry_both_immutable_witnesses_only_when_chunks_need_them() {
    let body = body(2, false);
    let chunks = vec![chunk(1, 3, 100, 10, false), chunk(2, 4, 100, 10, true)];
    let source = manifest(&body, &chunks);
    let history = history(&body, &source, chunks, Some(1));
    let envelopes: Vec<_> = history
        .iter()
        .map(|record| record.envelope.clone())
        .collect();
    let records: Vec<_> = history
        .iter()
        .map(|record| (record.len, record.payload.as_slice()))
        .collect();
    let witnesses =
        join_report_witnesses(&envelopes, &records, vec![(0, &body)], vec![(1, &source)]).unwrap();
    for known_at in 0..=5 {
        let selected = report_bodies_at(&envelopes, &records, &witnesses, known_at).unwrap();
        assert_eq!(selected.len(), if known_at >= 3 { 2 } else { 0 });
        let (visible, activations) =
            report_visibility_at(&envelopes, &records, &selected, known_at).unwrap();
        assert_eq!(visible.len(), if known_at == 5 { 2 } else { 0 });
        assert!(activations.values().all(|sequence| *sequence == 5));
    }
    assert!(
        join_report_witnesses(&envelopes, &records, vec![(0, &body), (1, &source)], vec![])
            .is_err()
    );
    assert!(report_visibility_at(&envelopes, &records, &[(0, &body)], 5).is_err());
}

#[test]
fn late_duplicate_or_same_commit_binding_never_manufactures_completeness() {
    let body = body(2, false);
    let chunks = vec![chunk(1, 3, 100, 10, false)];
    let source = manifest(&body, &chunks);
    let valid = history(&body, &source, chunks, Some(1));
    let mut same_commit = valid.clone();
    same_commit[1].envelope =
        envelope_of_entry(&same_commit[1].payload, same_commit[1].len, 1, 1).unwrap();
    let mut late = valid.clone();
    late.swap(1, 2);
    for (index, record) in late.iter_mut().enumerate() {
        record.envelope =
            envelope_of_entry(&record.payload, record.len, index as u64 + 1, 0).unwrap();
    }
    let mut duplicate = valid.clone();
    duplicate.insert(2, valid[1].clone());
    for (index, record) in duplicate.iter_mut().enumerate() {
        record.envelope =
            envelope_of_entry(&record.payload, record.len, index as u64 + 1, 0).unwrap();
    }
    for records in [same_commit, late, duplicate] {
        let (proof, anchor) = proof(
            &records,
            &body,
            Some(&source),
            5000,
            0,
            None,
            BALANCE_FORMAT_V4,
        );
        assert!(crate::verify_balance(&proof, &anchor).is_err());
    }
}
