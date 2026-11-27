//! Independent gross-amount fixtures. Expected accounting columns are literal;
//! resealed mutations change source semantics, not merely a public checksum.

use super::*;
use crate::envelope::{
    ENTRY_DIGEST_DOMAIN, KIND_ATTESTATION, KIND_ENTRY, KIND_IMPORT_RECEIPT, PROPOSAL_DIGEST_DOMAIN,
    check_record, envelope_of_record,
};

const BOOK: [u8; 16] = [3; 16];
const CONTROL: u128 = 11;
const OFFSET: u128 = 22;
const DIMENSION: (u32, u128) = (12, 111);

struct Record {
    bytes: Vec<u8>,
    len: usize,
    envelope: LeafEnvelope,
}

fn field(w: &mut Writer) {
    w.fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(&[]);
}

fn leg(account: u128, credit: bool, amount: i128) -> VerifiedExternalFeedSummaryLeg {
    VerifiedExternalFeedSummaryLeg {
        account,
        unit: 1,
        credit,
        amount,
        dimension_set: vec![DIMENSION],
    }
}

fn detail(debit: i128, credit: i128, day: i32, key: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"fa:external-subledger-detail:v1")
        .fixed(&BOOK)
        .bytes(b"ERP:AR")
        .bytes(key.as_bytes())
        .i32(day)
        .count(3);
    for (digest, row) in [
        (1, leg(CONTROL, false, debit)),
        (2, leg(CONTROL, true, credit)),
        (3, leg(OFFSET, true, 60)),
    ] {
        w.fixed(&[digest; 32])
            .u128(row.account)
            .u8(u8::from(row.credit))
            .u32(row.unit)
            .i128(row.amount);
        dimensions(&mut w, &row.dimension_set);
    }
    w.buf
}

fn seal(kind: u8, seq: u64, mut w: Writer) -> Record {
    let len = w.buf.len();
    if kind == KIND_ENTRY {
        let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
        let entry = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
        w.fixed(&proposal).fixed(&entry);
    } else {
        let domain: &[u8] = if kind == KIND_ATTESTATION {
            b"fa:attestation:v1"
        } else {
            b"fa:custody:v1"
        };
        let digest = framed_digest(domain, &[&w.buf]);
        w.fixed(&digest);
        if kind == KIND_ATTESTATION {
            w.u8(0).u8(0).fixed(&[0; 32]);
        }
    }
    let envelope = envelope_of_record(kind, &w.buf, len, seq, 0).unwrap();
    check_record(&envelope, &w.buf, len).unwrap();
    Record {
        bytes: w.buf,
        len,
        envelope,
    }
}

fn citation(body: &[u8]) -> ([u8; 32], [u8; 32]) {
    let commit = crate::document::doc_commit(21, body);
    (
        framed_digest(b"fa:oid:document:v1", &[&BOOK, &commit]),
        commit,
    )
}

fn intake(body: &[u8], seq: u64) -> Record {
    let (oid, commit) = citation(body);
    let mut w = Writer::default();
    w.u16(1)
        .fixed(&BOOK)
        .fixed(&oid)
        .u32(0)
        .fixed(&[0; 32])
        .u8(1)
        .u8(1)
        .u128(7)
        .u128(7)
        .fixed(&commit)
        .u8(0)
        .count(0);
    seal(KIND_IMPORT_RECEIPT, seq, w)
}

fn review(body: &[u8], seq: u64, principal: u128) -> Record {
    let (oid, _) = citation(body);
    let mut w = Writer::default();
    w.u16(1)
        .fixed(&BOOK)
        .u8(2)
        .count(0)
        .count(1)
        .u8(1)
        .fixed(&oid)
        .u128(principal)
        .count(0);
    seal(KIND_ATTESTATION, seq, w)
}

#[allow(clippy::too_many_arguments)]
fn entry(
    class: u16,
    seq: u64,
    day: i32,
    key: &[u8],
    legs: &[VerifiedExternalFeedSummaryLeg],
    body: Option<&[u8]>,
    target: Option<(u128, [u8; 32])>,
    resolution: Option<(u128, [u8; 32])>,
) -> Record {
    let mut w = Writer::default();
    w.u16(1)
        .u16(1)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(class)
        .i32(day)
        .u8(0);
    field(&mut w);
    w.u8(0).count(legs.len());
    for leg in legs {
        w.u8(u8::from(leg.credit))
            .u128(leg.account)
            .u32(leg.unit)
            .i128(leg.amount)
            .u8(0);
        dimensions(&mut w, &leg.dimension_set);
        w.u8(0).count(0);
    }
    w.u8(0)
        .count(0)
        .u8(0)
        .bytes(key)
        .u8(0)
        .fixed(&[0; 32])
        .u16(1)
        .u128(7)
        .u8(0)
        .count(usize::from(body.is_some()));
    if let Some(body) = body {
        let (oid, commit) = citation(body);
        w.fixed(&oid).fixed(&commit).u8(1);
    }
    w.count(usize::from(target.is_some()));
    if let Some((id, digest)) = target {
        w.u128(id).fixed(&digest).u8(1).u16(1);
    }
    if class == 2 || resolution.is_some() {
        w.u8(1).u8(0).u8(u8::from(resolution.is_some()));
        if let Some((id, digest)) = resolution {
            w.u128(id).fixed(&digest).u8(1).u8(1);
        } else {
            w.u8(0);
        }
    } else {
        w.u8(0);
    }
    w.count(0).count(0).count(usize::from(body.is_some()));
    if let Some(body) = body {
        w.u16(30).bytes(body);
    }
    seal(KIND_ENTRY, seq, w)
}

fn entry_ref(record: &Record) -> (u128, [u8; 32]) {
    let info = metadata::entry_info(&record.bytes[..record.len], &record.envelope).unwrap();
    (info.identity, record.envelope.record_digest)
}

fn stock_source(known_at: u64, cutoff: i32) -> super::super::Certificate<'static> {
    super::super::Certificate {
        book: BOOK,
        branch: [0; 16],
        known_at,
        time_selection: None,
        selection: Selection::AsOf(cutoff),
        dimension: None,
        functional: false,
        source_storage: false,
        registry_digest: [0; 32],
        journal_root: [0; 32],
        leaves: 0,
        output: &[],
        output_digest: [0; 32],
        digest: [9; 32],
    }
}

fn outer<'a>(output: &'a [u8], known_at: u64, cutoff: i32) -> Certificate<'a> {
    Certificate {
        source: super::super::CERTIFICATE_FORMAT,
        request: ExternalFeedRequest {
            feed: "ERP:AR".into(),
            control_account: CONTROL,
            effective_through: cutoff,
            known_at,
        },
        registry_digest: [0; 32],
        output,
        digest: [8; 32],
    }
}

fn expected_batch(body: &[u8], original: &Record) -> VerifiedExternalFeedBatch {
    let (oid, commit) = citation(body);
    VerifiedExternalFeedBatch {
        entry: entry_ref(original).0,
        entry_digest: original.envelope.record_digest,
        recorded_at: original.envelope.commit_seq,
        feed: "ERP:AR".into(),
        batch_key: "batch-1".into(),
        effective_date: original.envelope.effective_day.unwrap(),
        document_oid: oid,
        doc_commit: commit,
        evidence_role: 1,
        review_attestation: metadata::framed_identity(
            b"fa:vid:attestation-review:v1",
            &[&BOOK, &oid],
        ),
        reviewer: 8,
        detail_rows: 3,
        summary_legs: vec![
            leg(CONTROL, false, 100),
            leg(CONTROL, true, 40),
            leg(OFFSET, true, 60),
        ],
        reconciled: true,
    }
}

fn expected(
    records: &[Record],
    body: &[u8],
    known_at: u64,
    cutoff: i32,
    posted: [i128; 2],
    detail: [i128; 2],
    pending: i128,
) -> VerifiedExternalFeed {
    let original = &records[2];
    let original_ref = entry_ref(original);
    let mut contributions = Vec::new();
    let mut unattributed = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.envelope.kind == KIND_ENTRY && r.envelope.commit_seq <= known_at)
    {
        let seq = record.envelope.commit_seq;
        if record.envelope.effective_day.unwrap() > cutoff || seq == 7 && known_at >= 8 {
            continue;
        }
        let (id, digest) = entry_ref(record);
        if (3..=5).contains(&seq) {
            contributions.push(VerifiedExternalFeedContribution {
                entry: id,
                entry_digest: digest,
                source: original_ref.0,
                source_digest: original_ref.1,
                recorded_at: seq,
                effective_date: record.envelope.effective_day.unwrap(),
                reversed: seq == 4,
            });
        } else if seq == 6 || seq == 7 {
            unattributed.push(VerifiedExternalFeedLeg {
                entry: id,
                entry_digest: digest,
                ordinal: 0,
                unit: 1,
                credit: false,
                amount: if seq == 6 { 25 } else { 9 },
                dimension_set: vec![DIMENSION],
                pending: seq == 7,
            });
        }
    }
    contributions.sort_by_key(|r| r.entry);
    unattributed.sort_by_key(|r| (r.entry, r.ordinal));
    let reconciled = unattributed.is_empty() && posted == detail && pending == 0;
    VerifiedExternalFeed {
        manifest_review: None,
        book_id: BOOK,
        known_at,
        effective_through: cutoff,
        source_certificate_digest: [9; 32],
        feed: "ERP:AR".into(),
        control_account: CONTROL,
        batches: vec![expected_batch(body, original)],
        contributions,
        unattributed,
        rows: vec![VerifiedExternalFeedRow {
            unit_id: 1,
            dimension_set: vec![DIMENSION],
            detail_debits: detail[0],
            detail_credits: detail[1],
            control_debits: posted[0],
            control_credits: posted[1],
            pending_debits: pending,
            pending_credits: 0,
        }],
        totals: vec![VerifiedExternalFeedTotal {
            unit_id: 1,
            detail_debits: detail[0],
            detail_credits: detail[1],
            control_debits: posted[0],
            control_credits: posted[1],
            pending_debits: pending,
            pending_credits: 0,
            register_debits: posted[0],
            register_credits: posted[1],
            register_debits_pending: pending,
            register_credits_pending: 0,
        }],
        reconciled,
    }
}

fn verify(
    records: &[Record],
    expected: &VerifiedExternalFeed,
) -> Result<VerifiedExternalFeed, ReportError> {
    let envelopes: Vec<_> = records.iter().map(|r| r.envelope.clone()).collect();
    let payloads: Vec<_> = records
        .iter()
        .map(|r| (r.len, r.bytes.as_slice()))
        .collect();
    let mut infos = BTreeMap::new();
    let mut legs = Vec::new();
    for (index, record) in records.iter().enumerate() {
        legs.push(check_record(&record.envelope, &record.bytes, record.len).unwrap());
        if record.envelope.kind == KIND_ENTRY && record.envelope.commit_seq <= expected.known_at {
            infos.insert(
                index,
                metadata::entry_info(&record.bytes[..record.len], &record.envelope)?,
            );
        }
    }
    let mut schema = metadata::Schema::default();
    schema.accounts.insert(
        CONTROL,
        metadata::Account {
            code: "1100".into(),
            name: "Control".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: 1,
            limit: None,
            created_at: 0,
        },
    );
    let mut resolved = BTreeSet::new();
    for (id, digest) in infos.values().filter_map(|info| info.resolution) {
        for (&index, info) in &infos {
            if info.matches_identity(id) && envelopes[index].record_digest == digest {
                resolved.insert(index);
            }
        }
    }
    let total = &expected.totals[0];
    let control_rows = [ReportRow {
        account: CONTROL,
        code: "1100".into(),
        name: "Control".into(),
        account_type: 1,
        unit: 1,
        debits: total.register_debits,
        credits: total.register_credits,
        debits_pending: total.register_debits_pending,
        credits_pending: total.register_credits_pending,
    }];
    let output = encode(expected)?;
    replay(
        &outer(&output, expected.known_at, expected.effective_through),
        &stock_source(expected.known_at, expected.effective_through),
        &[1],
        &schema,
        &envelopes,
        &payloads,
        &infos,
        &legs,
        &BTreeSet::new(),
        &resolved,
        &control_rows,
        None,
    )
    .map(|(report, _)| report)
}

fn fixture(with_extra: bool, source_day: i32) -> (Vec<Record>, Vec<u8>) {
    let body = detail(100, 40, source_day, "batch-1");
    let original_legs = vec![
        leg(CONTROL, false, 100),
        leg(CONTROL, true, 40),
        leg(OFFSET, true, 60),
    ];
    let mut reverse = original_legs.clone();
    for row in &mut reverse {
        row.credit = !row.credit;
    }
    let original = entry(
        1,
        3,
        source_day,
        b"source",
        &original_legs,
        Some(&body),
        None,
        None,
    );
    let reversal = entry(
        4,
        4,
        12,
        b"reverse",
        &reverse,
        None,
        Some(entry_ref(&original)),
        None,
    );
    let undo = entry(
        4,
        5,
        13,
        b"undo",
        &original_legs,
        None,
        Some(entry_ref(&reversal)),
        None,
    );
    let mut records = vec![
        intake(&body, 1),
        review(&body, 2, 8),
        original,
        reversal,
        undo,
    ];
    if with_extra {
        records.push(entry(
            1,
            6,
            14,
            b"uncovered",
            &[leg(CONTROL, false, 25), leg(OFFSET, true, 25)],
            None,
            None,
            None,
        ));
        let pending = entry(
            2,
            7,
            15,
            b"pending",
            &[leg(CONTROL, false, 9), leg(OFFSET, true, 9)],
            None,
            None,
            None,
        );
        let resolution = entry(
            3,
            8,
            40,
            b"resolution",
            &[],
            None,
            None,
            Some(entry_ref(&pending)),
        );
        records.push(pending);
        records.push(resolution);
    }
    (records, body)
}

#[test]
fn external_feed_replays_gross_reversal_ancestry_and_uncovered_pending_population() {
    let (records, body) = fixture(true, 10);
    let want = expected(&records, &body, 7, 20, [265, 180], [240, 180], 9);
    assert_eq!(verify(&records, &want).unwrap(), want);
    assert_eq!(want.unattributed.len(), 2);
    assert!(!want.reconciled);
    // A resolution published later retires pending even though its effective
    // date is outside the selected stock cutoff. The old prefix remains exact.
    let later = expected(&records, &body, 8, 20, [265, 180], [240, 180], 0);
    assert_eq!(verify(&records, &later).unwrap(), later);
}

#[test]
fn external_feed_uses_original_source_outside_effective_cutoff() {
    let (records, body) = fixture(false, 30);
    let want = expected(&records, &body, 4, 12, [40, 100], [40, 100], 0);
    assert_eq!(verify(&records, &want).unwrap(), want);
    assert!(want.reconciled);
    assert_eq!(want.batches[0].effective_date, 30);
}

#[test]
fn external_feed_rejects_resealed_equal_net_detail_and_false_reconciled_output() {
    let (mut records, body) = fixture(true, 10);
    let want = expected(&records, &body, 7, 20, [265, 180], [240, 180], 9);
    let mut hidden = want.clone();
    hidden.unattributed.clear();
    hidden.reconciled = true;
    assert_eq!(
        verify(&records, &hidden).unwrap_err().predicate,
        "report_recomputation"
    );
    // Both debit and credit grow by 30, leaving the net at 60. Rebuild the
    // Workpaper/evidence/entry commitments; exact gross summary equality fails.
    let changed = detail(130, 70, 10, "batch-1");
    records[0] = intake(&changed, 1);
    records[1] = review(&changed, 2, 8);
    records[2] = entry(
        1,
        3,
        10,
        b"source",
        &[
            leg(CONTROL, false, 100),
            leg(CONTROL, true, 40),
            leg(OFFSET, true, 60),
        ],
        Some(&changed),
        None,
        None,
    );
    assert_eq!(
        verify(&records, &want).unwrap_err().predicate,
        "external_feed_source"
    );
}

#[test]
fn external_feed_requires_original_distinct_review_before_summary() {
    let (records, body) = fixture(false, 10);
    let want = expected(&records, &body, 3, 20, [100, 40], [100, 40], 0);
    assert_eq!(verify(&records, &want).unwrap(), want);
    for (seq, reviewer) in [(6, 8), (2, 7)] {
        let mut changed = fixture(false, 10).0;
        changed[1] = review(&body, seq, reviewer);
        assert_eq!(
            verify(&changed, &want).unwrap_err().predicate,
            "external_feed_source"
        );
    }
    let changed: Vec<_> = records
        .into_iter()
        .filter(|r| r.envelope.kind != KIND_IMPORT_RECEIPT)
        .collect();
    assert_eq!(
        verify(&changed, &want).unwrap_err().predicate,
        "external_feed_source"
    );
}

#[test]
fn external_feed_reversal_preserves_dimensions_and_immutable_target() {
    let (mut records, body) = fixture(false, 10);
    let want = expected(&records, &body, 4, 20, [140, 140], [140, 140], 0);
    assert_eq!(verify(&records, &want).unwrap(), want);
    let mut changed = vec![
        leg(CONTROL, true, 100),
        leg(CONTROL, false, 40),
        leg(OFFSET, false, 60),
    ];
    changed[0].dimension_set[0].1 = 112;
    records[3] = entry(
        4,
        4,
        12,
        b"reverse",
        &changed,
        None,
        Some(entry_ref(&records[2])),
        None,
    );
    assert_eq!(
        verify(&records, &want).unwrap_err().predicate,
        "external_feed_source"
    );
    changed[0].dimension_set[0].1 = 111;
    let (id, mut digest) = entry_ref(&records[2]);
    digest[0] ^= 1;
    records[3] = entry(
        4,
        4,
        12,
        b"reverse",
        &changed,
        None,
        Some((id, digest)),
        None,
    );
    assert_eq!(
        verify(&records, &want).unwrap_err().predicate,
        "external_feed_source"
    );
}

#[test]
fn external_feed_same_commit_reversal_does_not_infer_execution_from_leaf_order() {
    for (original_ordinal, reversal_ordinal) in [(0, 1), (1, 0)] {
        let (mut records, body) = fixture(false, 10);
        let mut want = expected(&records, &body, 4, 20, [140, 140], [140, 140], 0);
        want.known_at = 3;
        for contribution in &mut want.contributions {
            contribution.recorded_at = 3;
        }
        for (index, ordinal) in [(2, original_ordinal), (3, reversal_ordinal)] {
            records[index].envelope = envelope_of_record(
                KIND_ENTRY,
                &records[index].bytes,
                records[index].len,
                3,
                ordinal,
            )
            .unwrap();
        }
        assert_eq!(verify(&records, &want).unwrap(), want);
    }
}

#[test]
fn external_feed_certificate_and_recipient_question_are_independent() {
    assert_eq!(
        bind_source(&outer(&[], 0, 365), &stock_source(0, 365))
            .unwrap_err()
            .predicate,
        "external_feed_request"
    );
    let expected = outer(&[], 12, 365).request;
    let mut output = Writer::default();
    output.bytes(OUTPUT_FORMAT);
    let mut w = Writer::default();
    w.bytes(CERTIFICATE_FORMAT)
        .bytes(b"nested native source")
        .count(4);
    for _ in 0..4 {
        w.bytes(b"native graph assertion remains unjudged");
    }
    w.bytes(expected.feed.as_bytes())
        .u128(expected.control_account)
        .i32(expected.effective_through)
        .u64(expected.known_at)
        .fixed(&[1; 32])
        .u128(7)
        .fixed(&[2; 32])
        .bytes(&output.buf);
    let digest = framed_digest(CERTIFICATE_DIGEST, &[&w.buf]);
    w.fixed(&digest);
    let certificate = decode(&w.buf).unwrap();
    bind_request(&certificate, &expected).unwrap();
    for wrong in [
        ExternalFeedRequest {
            feed: "ERP:AP".into(),
            ..expected.clone()
        },
        ExternalFeedRequest {
            control_account: 33,
            ..expected.clone()
        },
        ExternalFeedRequest {
            effective_through: 366,
            ..expected.clone()
        },
        ExternalFeedRequest {
            known_at: 13,
            ..expected.clone()
        },
    ] {
        assert_eq!(
            bind_request(&certificate, &wrong).unwrap_err().predicate,
            "external_feed_request"
        );
    }
    for end in 0..w.buf.len() {
        assert!(decode(&w.buf[..end]).is_err());
    }
    let last = w.buf.len() - 1;
    w.buf[last] ^= 1;
    assert_eq!(
        decode(&w.buf).err().unwrap().predicate,
        "certificate_digest"
    );
}

#[test]
fn parent_workpaper_review_uses_exact_subject_distinct_principals_and_prefix_order() {
    let parent = b"parent workpaper";
    let (oid, commit) = citation(parent);
    let verify = |intake: Record, review: Record, known_at: u64| {
        let envelopes = [intake.envelope, review.envelope];
        let payloads = [
            (intake.len, intake.bytes.as_slice()),
            (review.len, review.bytes.as_slice()),
        ];
        let evidence = source::Evidence::read(&envelopes, &payloads, &BOOK, known_at).unwrap();
        evidence.manifest_review(oid, commit)
    };
    let receipt = verify(intake(parent, 2), review(parent, 4, 8), 4).unwrap();
    assert_eq!((receipt.received_by, receipt.reviewed_by), (7, 8));
    assert_eq!(
        (receipt.intake_position, receipt.review_position),
        ((2, 0), (4, 0))
    );
    for refused in [
        verify(intake(parent, 2), review(parent, 4, 8), 3),
        verify(intake(parent, 2), review(parent, 4, 7), 4),
        verify(intake(parent, 4), review(parent, 2, 8), 4),
        verify(intake(b"other", 2), review(parent, 4, 8), 4),
        verify(intake(parent, 2), review(b"other", 4, 8), 4),
    ] {
        assert_eq!(
            refused.unwrap_err().predicate,
            "external_feed_manifest_review"
        );
    }
    let mut later = review(parent, 4, 8);
    later.envelope.within_commit_ordinal = 1;
    assert_eq!(
        verify(intake(parent, 4), later, 4).unwrap().review_position,
        (4, 1)
    );
    let mut late_intake = intake(parent, 4);
    late_intake.envelope.within_commit_ordinal = 1;
    assert_eq!(
        verify(late_intake, review(parent, 4, 8), 4)
            .unwrap_err()
            .predicate,
        "external_feed_manifest_review"
    );
}
