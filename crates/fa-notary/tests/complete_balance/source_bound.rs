use super::*;
use fa_journal::migration::{SourceChunk, SourceManifest};
use fa_model::{EvidenceRef, Writer, domain_digest, migration_entry_vid};
use fa_notary::migration_balance::MigrationInputs;
use std::collections::BTreeMap;

type Record = (VId, Entry, CommitSeq);

fn reverse(mut record: Record) -> Record {
    let mut p = record.1.proposal;
    for leg in &mut p.legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
    }
    p.unit_totals = EntryPayload::fold_unit_totals(&p.legs).unwrap();
    record.1 = p.seal(vec![], None).unwrap();
    record
}

fn population(run: &RunBody, records: &[Record]) -> SourceManifest {
    let source_commit = [0x71; 32];
    let package_commit = [0x72; 32];
    SourceManifest {
        book_id: BOOK,
        run_ref: run.vid(),
        run_body_digest: run.digest().unwrap(),
        source_oid: Oid(domain_digest(
            b"fa:oid:document:v1",
            &[&BOOK.0, &source_commit],
        )),
        source_commit,
        package_oid: Oid(domain_digest(
            b"fa:oid:document:v1",
            &[&BOOK.0, &package_commit],
        )),
        package_commit,
        source_rows: records.len() as u64 * 2,
        chunks: records
            .iter()
            .map(|(_, entry, _)| SourceChunk {
                entry_vid: migration_entry_vid(BOOK, run.vid(), &entry.proposal.idempotency_key),
                proposal_digest: entry.proposal_digest,
            })
            .collect(),
    }
}

fn journal(
    run: &RunBody,
    source: &SourceManifest,
    chunks: Vec<Record>,
    terminal: Option<u8>,
) -> Journal {
    let mut binding = control(run, kind::BIND_SOURCE, 2);
    let mut p = binding.1.proposal;
    p.control = Some(ControlPayload::MigrationControl {
        run_ref: run.vid(),
        kind: kind::BIND_SOURCE,
        tie_out_digest: source.digest().unwrap(),
    });
    p.evidence = vec![
        EvidenceRef {
            document_oid: source.source_oid,
            doc_commit: source.source_commit,
            role: 1,
        },
        EvidenceRef {
            document_oid: source.package_oid,
            doc_commit: source.package_commit,
            role: 1,
        },
    ];
    p.evidence.sort_unstable();
    binding.1 = p.seal(vec![], None).unwrap();
    let mut records = vec![control(run, kind::OPEN, 1), binding];
    let mut chunks: Vec<_> = chunks
        .into_iter()
        .enumerate()
        .map(|(index, (_, entry, _))| {
            (
                migration_entry_vid(BOOK, run.vid(), &entry.proposal.idempotency_key),
                entry,
                CommitSeq(index as u64 + 3),
            )
        })
        .collect();
    chunks.sort_by_key(|(vid, _, seq)| (*seq, *vid));
    let mut list = Writer::new();
    list.list(&chunks, |writer, (vid, entry, _)| {
        writer.u128(vid.0).fixed(&entry.proposal_digest);
    });
    let digest = domain_digest(
        b"fa:migration-tie-out:v2",
        &[
            &run.digest().unwrap(),
            &source.digest().unwrap(),
            &list.finish().unwrap(),
        ],
    );
    records.extend(chunks);
    if let Some(kind) = terminal {
        let seq = records.len() as u64 + 1;
        let mut last = control(run, kind, seq);
        let mut p = last.1.proposal;
        p.control = Some(ControlPayload::MigrationControl {
            run_ref: run.vid(),
            kind,
            tie_out_digest: digest,
        });
        last.1 = p.seal(vec![], None).unwrap();
        records.push(last);
    }
    Journal::from_records(BOOK, records.last().unwrap().2, records).unwrap()
}

#[test]
fn producer_v4_and_independent_reader_agree_on_exact_out_of_order_population() {
    let run = body(RunMode::FullDetail, false, "source-bound");
    let chunks = vec![
        posting(Some(&run), 3, 100, 1),
        posting(Some(&run), 4, 100, 1),
        reverse(posting(Some(&run), 5, 100, 1)),
    ];
    let manifest = population(&run, &chunks);
    let inputs = MigrationInputs {
        bodies: BTreeMap::from([(run.vid(), run.clone())]),
        manifests: BTreeMap::from([(run.vid(), manifest.clone())]),
    };
    for chunks in [
        chunks.clone(),
        vec![chunks[2].clone(), chunks[0].clone(), chunks[1].clone()],
    ] {
        let journal = journal(&run, &manifest, chunks, Some(kind::FINALIZE));
        let proof = journal
            .balance_proof_complete_auto(CASH, 1, None, &inputs)
            .unwrap()
            .unwrap();
        assert_eq!(
            fa_model::Reader::new(&proof).bytes(128, "format").unwrap(),
            fa_verify::migration_balance::BALANCE_FORMAT_V4
        );
        let result = fa_verify::verify_balance(&proof, &anchor(&journal)).unwrap();
        assert_eq!((result.claim.debits, result.claim.credits), (10000, 5000));
        assert_eq!(
            journal
                .balance_proof_auto(CASH, 1, None, &inputs)
                .unwrap()
                .unwrap(),
            proof
        );
        assert!(
            journal
                .balance_proof_complete(CASH, 1, None, std::slice::from_ref(&run))
                .unwrap()
                .is_err()
        );
        assert!(
            journal
                .balance_proof_with_migrations(CASH, 1, None, std::slice::from_ref(&run))
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn producer_refuses_offsetting_omission_and_source_substitution_without_activating_partial_runs() {
    let run = body(RunMode::FullDetail, false, "source-bound-partial");
    let chunks = vec![
        posting(Some(&run), 3, 100, 1),
        posting(Some(&run), 4, 100, 1),
        reverse(posting(Some(&run), 5, 100, 1)),
    ];
    let manifest = population(&run, &chunks);
    let inputs = MigrationInputs {
        bodies: BTreeMap::from([(run.vid(), run.clone())]),
        manifests: BTreeMap::from([(run.vid(), manifest.clone())]),
    };
    for terminal in [None, Some(kind::ABANDON), Some(kind::FINALIZE)] {
        let journal = journal(&run, &manifest, vec![chunks[0].clone()], terminal);
        let proof = journal
            .balance_proof_complete_auto(CASH, 1, None, &inputs)
            .unwrap();
        if terminal == Some(kind::FINALIZE) {
            assert!(
                proof.is_err(),
                "net 5000 still agrees, but two declared chunks are missing"
            );
        } else {
            let result = fa_verify::verify_balance(&proof.unwrap(), &anchor(&journal)).unwrap();
            assert_eq!((result.claim.debits, result.claim.credits), (0, 0));
        }
    }
    let journal = journal(&run, &manifest, chunks, Some(kind::FINALIZE));
    let mut changed = inputs.clone();
    changed
        .manifests
        .get_mut(&run.vid())
        .unwrap()
        .chunks
        .reverse();
    assert!(
        journal
            .balance_proof_complete_auto(CASH, 1, None, &changed)
            .unwrap()
            .is_err()
    );
    assert!(
        journal
            .balance_proof_complete_auto(CASH, 1, None, &inputs.bodies)
            .unwrap()
            .is_err()
    );
}
