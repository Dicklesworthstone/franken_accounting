//! Native report transport closure for an independently encoded bound run.
use super::*;

fn framed(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut w = Writer::default();
    for part in parts {
        w.bytes(part);
    }
    hash_parts(domain, &[&w.buf])
}

fn run() -> u128 {
    u128::from_le_bytes(
        framed(b"fa:vid:migration-run:v1", &[&BOOK, b"source-import"])[..16]
            .try_into()
            .unwrap(),
    )
}

fn body() -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(1)
        .fixed(&BOOK)
        .bytes(b"source-import")
        .bytes(b"legacy")
        .u8(2)
        .fixed(&[0; 32])
        .i32(10)
        .count(0)
        .count(0)
        .count(0)
        .u8(0);
    w.buf
}

fn entry(
    seq: u64,
    body: &[u8],
    control: Option<(u8, [u8; 32])>,
    evidence: &[([u8; 32], [u8; 32])],
) -> Record {
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(if control.is_some() { 22 } else { 12 })
        .i32(10)
        .u8(0);
    erasable(&mut w);
    w.u8(0).count(if control.is_some() { 0 } else { 2 });
    if control.is_none() {
        for (code, side) in [("1000", 0), ("3000", 1)] {
            w.u8(side)
                .u128(account_id(code))
                .u32(1)
                .i128(125)
                .u8(0)
                .count(0)
                .u8(0)
                .count(0);
        }
    }
    if let Some((kind, digest)) = control {
        w.u8(1).u8(10).u128(run()).u8(kind).fixed(&digest);
    } else {
        w.u8(0);
    }
    w.count(0).u8(0);
    if control.is_some() {
        w.bytes(&seq.to_le_bytes());
    } else {
        w.bytes(b"source-post");
    }
    if control.is_some() {
        w.u8(3)
            .u16(9)
            .fixed(&framed(b"fa:migration-run-body:v1", &[body]));
    } else {
        w.u8(2).u128(run()).bytes(b"legacy");
        erasable(&mut w);
        w.u8(0).u8(0).u8(0).fixed(&[0; 32]);
    }
    w.u128(PRINCIPAL).u8(0).count(evidence.len());
    for (oid, commit) in evidence {
        w.fixed(oid).fixed(commit).u8(1);
    }
    w.count(0).u8(0).count(0).count(0);
    let len = w.buf.len();
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    w.fixed(&proposal).fixed(&digest);
    Record {
        envelope: envelope_of_entry(&w.buf, len, seq, 0).unwrap(),
        len,
        bytes: w.buf,
    }
}

fn fixture() -> (Vec<Record>, Vec<u8>, Vec<u8>) {
    let body = body();
    let chunk = entry(5, &body, None, &[]);
    let chunk_vid = u128::from_le_bytes(
        framed(
            b"fa:vid:migration-entry:v1",
            &[&BOOK, &run().to_le_bytes(), b"source-post"],
        )[..16]
            .try_into()
            .unwrap(),
    );
    let chunk_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&chunk.bytes[..chunk.len]]);
    let source_commit = [7; 32];
    let package_commit = [8; 32];
    let source_oid = framed(b"fa:oid:document:v1", &[&BOOK, &source_commit]);
    let package_oid = framed(b"fa:oid:document:v1", &[&BOOK, &package_commit]);
    let body_digest = framed(b"fa:migration-run-body:v1", &[&body]);
    let mut manifest = Writer::default();
    manifest
        .fixed(b"FA-MIGRATION-SOURCE\0")
        .u16(1)
        .fixed(&BOOK)
        .u128(run())
        .fixed(&body_digest)
        .fixed(&source_oid)
        .fixed(&source_commit)
        .fixed(&package_oid)
        .fixed(&package_commit)
        .u64(1)
        .count(1)
        .u128(chunk_vid)
        .fixed(&chunk_digest);
    let manifest_digest = framed(b"fa:migration-source:v1", &[&manifest.buf]);
    let mut evidence = vec![(source_oid, source_commit), (package_oid, package_commit)];
    evidence.sort_unstable();
    let mut population = Writer::default();
    population.count(1).u128(chunk_vid).fixed(&chunk_digest);
    let tie_out = framed(
        b"fa:migration-tie-out:v2",
        &[&body_digest, &manifest_digest, &population.buf],
    );
    let mut records = schema();
    records.extend([
        entry(3, &body, Some((0, body_digest)), &[]),
        entry(4, &body, Some((3, manifest_digest)), &evidence),
        chunk,
        entry(6, &body, Some((1, tie_out)), &[]),
    ]);
    (records, body, manifest.buf)
}

fn pack(
    records: &[Record],
    body: &[u8],
    manifest: &[u8],
    minor: u16,
    inputs: usize,
    include_source: bool,
) -> (Vec<u8>, SignedCheckpoint) {
    let (mut bytes, anchor) =
        bundle_with_native_inputs(records, 6, Selection::AsOf(20), &rows(125, 0), inputs);
    // The old bundle ends with its empty Open-body list. Retain all signed
    // prefix/certificate fields and replace only the transport witness lists.
    bytes.truncate(bytes.len() - 4);
    let minor_offset = 4 + REPORT_BUNDLE_FORMAT.len() + 2;
    bytes[minor_offset..minor_offset + 2].copy_from_slice(&minor.to_le_bytes());
    let mut suffix = Writer::default();
    suffix.count(1).u64(2).bytes(body);
    if minor == 1 {
        suffix.count(usize::from(include_source));
        if include_source {
            suffix.u64(3).bytes(manifest);
        }
    }
    bytes.extend(suffix.buf);
    (bytes, anchor)
}

#[test]
fn minor_one_source_report_requires_manifest_and_exact_native_storage_profile() {
    let (records, body, manifest) = fixture();
    for inputs in [9, 10] {
        let (bytes, anchor) = pack(&records, &body, &manifest, 1, inputs, true);
        let report = verify_fixture(&bytes, anchor).unwrap();
        assert_eq!(report.rows, rows(125, 0));
    }
    for (minor, inputs, include_source) in [
        (0, 9, false),
        (1, 9, false),
        (1, 7, true),
        (1, 8, true),
        (1, 11, true),
        (2, 9, true),
    ] {
        let (bytes, anchor) = pack(&records, &body, &manifest, minor, inputs, include_source);
        assert!(
            verify_fixture(&bytes, anchor).is_err(),
            "minor={minor}, inputs={inputs}, source={include_source}"
        );
    }
}

#[test]
fn bound_frontier_before_first_chunk_needs_native_source_storage_but_no_population_witnesses() {
    let (records, _, _) = fixture();
    for known_at in [3, 4] {
        let inputs = if known_at == 4 { 9 } else { 7 };
        let (bytes, anchor) =
            bundle_with_native_inputs(&records, known_at, Selection::AsOf(20), &[], inputs);
        assert!(verify_fixture(&bytes, anchor).unwrap().rows.is_empty());
        let (wrong, anchor) = bundle_with_native_inputs(
            &records,
            known_at,
            Selection::AsOf(20),
            &[],
            if inputs == 9 { 7 } else { 9 },
        );
        assert!(verify_fixture(&wrong, anchor).is_err());
    }
}
