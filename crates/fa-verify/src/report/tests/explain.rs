//! Independently encoded complete-prefix explanations. Expected cells and
//! history are explicit; expected wire bytes never call the production encoder.
use super::statements::{closure, registries as common_registries};
use super::*;
use crate::envelope::Leg;

fn identity(key: &[u8]) -> u128 {
    let mut w = Writer::default();
    w.bytes(&BOOK).bytes(&PRINCIPAL.to_le_bytes()).bytes(key);
    let h = hash_parts(b"fa:vid:entry:v1", &[&w.buf]);
    u128::from_le_bytes(h[..16].try_into().unwrap())
}
fn target_id(domain: &[u8], target: u128) -> u128 {
    let h = hash_parts(domain, &[&target.to_le_bytes()]);
    u128::from_le_bytes(h[..16].try_into().unwrap())
}
fn seal(mut w: Writer, at: u64) -> Record {
    let len = w.buf.len();
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    w.fixed(&proposal).fixed(&digest);
    let envelope = envelope_of_entry(&w.buf, len, at, 0).unwrap();
    Record {
        bytes: w.buf,
        len,
        envelope,
    }
}
fn input_leg(code: &str, debit: bool, amount: i128) -> Leg {
    Leg {
        account: account_id(code),
        debit,
        unit: 1,
        mantissa: amount,
    }
}
#[allow(clippy::too_many_arguments)]
fn posting(
    class: u16,
    at: u64,
    day: i32,
    key: &[u8],
    legs: &[Leg],
    supersession: Option<(u128, [u8; 32], u8, u16)>,
    pending: Option<(u128, [u8; 32])>,
    evidence: &[([u8; 32], [u8; 32], u8)],
) -> Record {
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(class)
        .i32(day)
        .u8(0);
    erasable(&mut w);
    w.u8(0).count(legs.len());
    for leg in legs {
        w.u8(u8::from(!leg.debit))
            .u128(leg.account)
            .u32(leg.unit)
            .i128(leg.mantissa)
            .u8(0)
            .count(0)
            .u8(0)
            .count(0);
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
        .count(evidence.len());
    for (oid, commit, role) in evidence {
        w.fixed(oid).fixed(commit).u8(*role);
    }
    w.count(usize::from(supersession.is_some()));
    if let Some((target, digest, kind, reason)) = supersession {
        w.u128(target).fixed(&digest).u8(kind).u16(reason);
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
                w.u8(1);
            } else {
                w.u8(3).count(legs.len());
                for i in 0..legs.len() {
                    w.u16(i as u16);
                }
            }
        }
    }
    w.count(0).count(0);
    seal(w, at)
}
fn canonical_text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}
fn reason_document(rows: &[(u16, &str, &str, &str)]) -> Vec<u8> {
    let mut out = b"fa:registry-document:v1".to_vec();
    out.extend_from_slice(&1u64.to_le_bytes());
    canonical_text(&mut out, "schema_version");
    out.push(2);
    out.extend_from_slice(&1i128.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    canonical_text(&mut out, "reason");
    out.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    for (code, scope, name, meaning) in rows {
        out.extend_from_slice(&4u64.to_le_bytes());
        canonical_text(&mut out, "code");
        out.push(2);
        out.extend_from_slice(&i128::from(*code).to_le_bytes());
        for (key, value) in [("meaning", *meaning), ("name", *name), ("scope", *scope)] {
            canonical_text(&mut out, key);
            out.push(1);
            canonical_text(&mut out, value);
        }
    }
    out
}
fn reason_rows() -> Vec<(u16, &'static str, &'static str, &'static str)> {
    vec![
        (
            1,
            "manual_assertion",
            "NoDocument",
            "No document was issued",
        ),
        (
            1,
            "supersession",
            "ArchivedCorrection",
            "The meaning retained when the certificate was produced",
        ),
        (
            2,
            "supersession",
            "AnotherCorrection",
            "A second registered correction",
        ),
        (
            1,
            "period_control",
            "Scheduled",
            "Scheduled period transition",
        ),
        (
            1,
            "period_reopen",
            "ErrorCorrection",
            "Reopened to correct an error",
        ),
        (
            1,
            "adjustment_pass",
            "Other",
            "Passed for a recorded reason",
        ),
    ]
}
fn registries() -> Vec<(String, Vec<u8>)> {
    let mut docs = common_registries();
    docs.push(("reason_codes".into(), reason_document(&reason_rows())));
    docs
}
fn account() -> VerifiedReportAccount {
    VerifiedReportAccount {
        account: account_id("1000"),
        code: "1000".into(),
        name: "Cash".into(),
        account_type: 1,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: OpenItemUnitPolicy::Single(1),
        limit: None,
        created_at: 1,
    }
}
fn cell(code: &str, debit: i128, credit: i128, count: u64) -> ExplanationCell {
    ExplanationCell {
        account: account_id(code),
        unit_id: 1,
        period: "P1".into(),
        debits: debit,
        credits: credit,
        entry_count: count,
    }
}
fn change(at: u64, debit: i128, credit: i128, pending: i128) -> ExplanationCellChange {
    ExplanationCellChange {
        recorded_at: at,
        unit_id: 1,
        debits: debit,
        credits: credit,
        debits_pending: pending,
        credits_pending: 0,
    }
}
fn contribution(
    record: &Record,
    id: u128,
    ordinal: u16,
    debit: bool,
    amount: i128,
    column: ExplanationColumn,
) -> ExplanationContribution {
    ExplanationContribution {
        entry: id,
        entry_digest: record.envelope.record_digest,
        class: record.envelope.class,
        effective_date: record.envelope.effective_day.unwrap(),
        recorded_at: record.envelope.commit_seq,
        visible_at: record.envelope.commit_seq,
        ordinal,
        debit,
        unit_id: 1,
        mantissa: amount,
        column,
        released_at: None,
        resolves: None,
        supersedes: vec![],
        evidence: vec![],
    }
}
fn write_cells(w: &mut Writer, cells: &[ExplanationCell]) {
    w.count(cells.len());
    for c in cells {
        w.u128(c.account)
            .u32(c.unit_id)
            .bytes(c.period.as_bytes())
            .i128(c.debits)
            .i128(c.credits)
            .u64(c.entry_count);
    }
}
/// Independent frozen-format transcript, fed explicit native entry identities
/// and full-period legs by each scenario, not by the verifier's metadata parser.
fn expected_fold(
    period: &str,
    watermark: Option<u64>,
    posted: &[(u64, u128, Vec<Leg>)],
    holds: &[(u64, u128, Vec<Leg>)],
    mut cells: Vec<ExplanationCell>,
    mut pending: Vec<ExplanationCell>,
) -> [u8; 32] {
    fn legs_hash(mut previous: [u8; 32], seq: u64, id: u128, legs: &[Leg]) -> [u8; 32] {
        for (ordinal, leg) in legs.iter().enumerate() {
            let mut bytes = b"fa:register-leg-contribution:v1".to_vec();
            bytes.extend_from_slice(&previous);
            bytes.extend_from_slice(&seq.to_le_bytes());
            bytes.extend_from_slice(&id.to_le_bytes());
            bytes.extend_from_slice(&(ordinal as u16).to_le_bytes());
            bytes.extend_from_slice(&leg.account.to_le_bytes());
            bytes.extend_from_slice(&leg.unit.to_le_bytes());
            bytes.push(u8::from(!leg.debit));
            bytes.extend_from_slice(&leg.mantissa.to_le_bytes());
            previous = crate::blake3::hash(&bytes);
        }
        previous
    }
    let mut posted: Vec<_> = posted.iter().collect();
    posted.sort_by_key(|(seq, id, _)| (*seq, *id));
    let mut chain = [0; 32];
    for (seq, id, legs) in posted {
        chain = legs_hash(chain, *seq, *id, legs);
    }
    let mut holds: Vec<_> = holds.iter().collect();
    holds.sort_by_key(|(seq, id, _)| (*seq, *id));
    cells.sort_by_key(|c| (c.account, c.unit_id));
    pending.sort_by_key(|c| (c.account, c.unit_id));
    let mut w = Writer::default();
    w.bytes(period.as_bytes()).u8(u8::from(watermark.is_some()));
    if let Some(at) = watermark {
        w.u64(at);
    }
    w.fixed(&chain).count(holds.len());
    for (seq, id, legs) in holds {
        w.u64(*seq)
            .u128(*id)
            .fixed(&legs_hash([0; 32], *seq, *id, legs));
    }
    write_cells(&mut w, &cells);
    write_cells(&mut w, &pending);
    hash_parts(b"fa:register-fold:v2", &[&w.buf])
}
fn expected(
    known_at: u64,
    fold_digest: [u8; 32],
    watermark: Option<u64>,
    cells: Vec<ExplanationCell>,
    pending: Vec<ExplanationCell>,
    contributions: Vec<ExplanationContribution>,
    history: Vec<ExplanationCellChange>,
) -> VerifiedBalanceExplanation {
    VerifiedBalanceExplanation {
        account: account_id("1000"),
        account_row: account(),
        period: "P1".into(),
        known_at,
        fold_digest,
        watermark,
        cells,
        pending,
        contributions,
        history,
        supersession_reasons: reason_rows()
            .into_iter()
            .filter(|row| row.1 == "supersession")
            .map(|(code, _, name, meaning)| {
                (
                    code,
                    ExplanationReason {
                        code,
                        name: name.into(),
                        meaning: meaning.into(),
                    },
                )
            })
            .collect(),
    }
}
fn output_bytes(report: &VerifiedBalanceExplanation) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"fa:balance-explanation:v1").u128(report.account);
    let a = &report.account_row;
    w.u128(a.account)
        .bytes(a.code.as_bytes())
        .bytes(a.name.as_bytes())
        .u8(a.account_type)
        .u8(a.normal_balance)
        .u8(u8::from(a.is_leaf));
    match a.unit_policy {
        OpenItemUnitPolicy::Single(unit) => {
            w.u8(0).u32(unit);
        }
        OpenItemUnitPolicy::AnyCurrency => {
            w.u8(1);
        }
        OpenItemUnitPolicy::AnyUnit => {
            w.u8(2);
        }
    }
    w.u8(u8::from(a.limit.is_some()));
    if let Some(limit) = &a.limit {
        for value in [limit.lower, limit.upper] {
            w.u8(u8::from(value.is_some()));
            if let Some(value) = value {
                w.i128(value);
            }
        }
        w.u8(u8::from(limit.period_scoped));
    }
    w.u64(a.created_at)
        .bytes(report.period.as_bytes())
        .u64(report.known_at)
        .fixed(&report.fold_digest)
        .u8(u8::from(report.watermark.is_some()));
    if let Some(at) = report.watermark {
        w.u64(at);
    }
    write_cells(&mut w, &report.cells);
    write_cells(&mut w, &report.pending);
    w.count(report.contributions.len());
    for c in &report.contributions {
        w.u128(c.entry)
            .fixed(&c.entry_digest)
            .u16(c.class)
            .i32(c.effective_date)
            .u64(c.recorded_at)
            .u64(c.visible_at)
            .u16(c.ordinal)
            .u8(u8::from(!c.debit))
            .u32(c.unit_id)
            .i128(c.mantissa)
            .u8(match c.column {
                ExplanationColumn::Posted => 0,
                ExplanationColumn::Pending => 1,
                ExplanationColumn::Released => 2,
            })
            .u8(u8::from(c.released_at.is_some()));
        if let Some(at) = c.released_at {
            w.u64(at);
        }
        w.u8(u8::from(c.resolves.is_some()));
        if let Some(id) = c.resolves {
            w.u128(id);
        }
        w.count(c.supersedes.len());
        for lineage in &c.supersedes {
            w.u128(lineage.target)
                .fixed(&lineage.entry_digest)
                .u8(lineage.kind)
                .u16(lineage.reason_code);
        }
        w.count(c.evidence.len());
        for evidence in &c.evidence {
            w.fixed(&evidence.document_oid)
                .fixed(&evidence.doc_commit)
                .u8(evidence.role);
        }
    }
    w.count(report.history.len());
    for h in &report.history {
        w.u64(h.recorded_at)
            .u32(h.unit_id)
            .i128(h.debits)
            .i128(h.credits)
            .i128(h.debits_pending)
            .i128(h.credits_pending);
    }
    w.buf
}
fn pack(
    records: &[Record],
    expected: &VerifiedBalanceExplanation,
    docs: &[(String, Vec<u8>)],
    bodies: &[(u64, Vec<u8>)],
) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
    let mut previous = None;
    let mut ordinal = 0;
    let envelopes: Vec<_> = records
        .iter()
        .map(|record| {
            if previous != Some(record.envelope.commit_seq) {
                previous = Some(record.envelope.commit_seq);
                ordinal = 0;
            }
            let mut e = record.envelope.clone();
            e.within_commit_ordinal = ordinal;
            ordinal += 1;
            e
        })
        .collect();
    let hashes: Vec<_> = envelopes.iter().map(|e| leaf_hash(&e.encode())).collect();
    let checkpoint = Checkpoint {
        book_id: BOOK,
        branch_id: [0; 16],
        through_seq: envelopes.last().unwrap().commit_seq,
        leaf_count: envelopes.len() as u64,
        root: root_of(&hashes),
    };
    let mut prefix = Writer::default();
    prefix
        .bytes(PREFIX_FORMAT)
        .fixed(&checkpoint.encode())
        .count(envelopes.len());
    for e in &envelopes {
        prefix.bytes(&e.encode());
    }
    let historical: Vec<_> = envelopes
        .iter()
        .zip(&hashes)
        .filter(|(e, _)| e.commit_seq <= expected.known_at)
        .map(|(_, h)| *h)
        .collect();
    let output = output_bytes(expected);
    let mut cert = Writer::default();
    cert.fixed(OPEN_ITEMS_CERTIFICATE_FORMAT)
        .bytes(b"fa-fold-over-prefix")
        .bytes(b"embedded-owner")
        .bytes(b"fa:balance-explanation:v1")
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(expected.known_at)
        .u8(0)
        .u128(expected.account)
        .bytes(expected.period.as_bytes())
        .fixed(&closure(docs))
        .fixed(&root_of(&historical))
        .u64(historical.len() as u64)
        .count(7);
    for _ in 0..7 {
        cert.bytes(b"opaque native read");
    }
    cert.bytes(&output)
        .fixed(&hash_parts(b"fa:report-output:v1", &[&output]))
        .u8(0);
    let pin = hash_parts(OPEN_ITEMS_CERTIFICATE_FORMAT, &[&cert.buf]);
    cert.fixed(&pin);
    let mut w = Writer::default();
    w.bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(&cert.buf)
        .bytes(b"externally trusted fixture")
        .bytes(&prefix.buf)
        .count(records.len());
    for r in records {
        w.u32(r.len as u32).bytes(&r.bytes);
    }
    w.count(bodies.len());
    for (index, body) in bodies {
        w.u64(*index).bytes(body);
    }
    w.count(docs.len());
    for (name, bytes) in docs {
        w.bytes(name.as_bytes()).bytes(bytes);
    }
    (w.buf, signed(checkpoint), pin)
}
fn verify(
    records: &[Record],
    expected: &VerifiedBalanceExplanation,
) -> Result<VerifiedReport, ReportError> {
    verify_with(records, expected, &registries(), &[])
}
fn verify_with(
    records: &[Record],
    expected: &VerifiedBalanceExplanation,
    docs: &[(String, Vec<u8>)],
    bodies: &[(u64, Vec<u8>)],
) -> Result<VerifiedReport, ReportError> {
    let (bytes, anchor, pin) = pack(records, expected, docs, bodies);
    verify_report_with(&bytes, &[], None, None, Some(&pin), |_, _| Ok(anchor))
}

#[test]
fn whole_period_commitment_includes_other_accounts_and_counts_entries_once() {
    let mut records = schema();
    let first = vec![
        input_leg("1000", true, 40),
        input_leg("1000", true, 60),
        input_leg("3000", false, 100),
    ];
    let later = vec![input_leg("3000", true, 7), input_leg("3000", false, 7)];
    let original = posting(1, 3, 10, b"original", &first, None, None, &[]);
    let c = vec![
        contribution(
            &original,
            identity(b"original"),
            0,
            true,
            40,
            ExplanationColumn::Posted,
        ),
        contribution(
            &original,
            identity(b"original"),
            1,
            true,
            60,
            ExplanationColumn::Posted,
        ),
    ];
    records.extend([
        original,
        posting(7, 4, 10, b"other-account", &later, None, None, &[]),
    ]);
    let whole = vec![cell("1000", 100, 0, 1), cell("3000", 7, 107, 2)];
    let digest = expected_fold(
        "P1",
        Some(4),
        &[
            (3, identity(b"original"), first),
            (4, identity(b"other-account"), later),
        ],
        &[],
        whole,
        vec![],
    );
    let report = expected(
        4,
        digest,
        Some(4),
        vec![cell("1000", 100, 0, 1)],
        vec![],
        c,
        vec![change(3, 100, 0, 0)],
    );
    let verified = verify(&records, &report).unwrap();
    assert_eq!(verified.explanation.as_ref(), Some(&report));
    assert_eq!(verified.output, output_bytes(&report));
    assert_eq!(report.last_changed_at(), Some(3));
    let mut forged = report.clone();
    forged.watermark = Some(3);
    assert_eq!(
        verify(&records, &forged).unwrap_err().predicate,
        "report_recomputation"
    );
}

#[test]
fn pending_release_in_another_period_retains_birth_and_zero_history() {
    let mut records = schema();
    let hold_legs = vec![input_leg("1000", true, 50), input_leg("3000", false, 50)];
    let hold = posting(2, 3, 10, b"hold", &hold_legs, None, None, &[]);
    let hold_id = identity(b"hold");
    let pending = contribution(&hold, hold_id, 0, true, 50, ExplanationColumn::Pending);
    let release = posting(
        3,
        5,
        40,
        b"release",
        &[],
        None,
        Some((hold_id, hold.envelope.record_digest)),
        &[],
    );
    records.extend([hold, release]);
    let digest = expected_fold(
        "P1",
        Some(3),
        &[],
        &[(3, hold_id, hold_legs)],
        vec![],
        vec![cell("1000", 50, 0, 1), cell("3000", 0, 50, 1)],
    );
    let before = expected(
        3,
        digest,
        Some(3),
        vec![],
        vec![cell("1000", 50, 0, 1)],
        vec![pending.clone()],
        vec![change(3, 0, 0, 50)],
    );
    assert_eq!(
        verify(&records, &before).unwrap().explanation.as_ref(),
        Some(&before)
    );
    let mut released = pending;
    released.column = ExplanationColumn::Released;
    released.released_at = Some(5);
    let after = expected(
        5,
        expected_fold("P1", Some(5), &[], &[], vec![], vec![]),
        Some(5),
        vec![],
        vec![],
        vec![released],
        vec![change(3, 0, 0, 50), change(5, 0, 0, 0)],
    );
    assert_eq!(
        verify(&records, &after).unwrap().explanation.as_ref(),
        Some(&after)
    );
}

#[test]
fn same_commit_reordered_hold_and_release_keeps_zero_history_point() {
    let mut records = schema();
    let legs = vec![input_leg("1000", true, 20), input_leg("3000", false, 20)];
    let hold = posting(2, 3, 10, b"atomic-hold", &legs, None, None, &[]);
    let mut c = contribution(
        &hold,
        identity(b"atomic-hold"),
        0,
        true,
        20,
        ExplanationColumn::Released,
    );
    c.released_at = Some(3);
    let release = posting(
        3,
        3,
        40,
        b"atomic-release",
        &[],
        None,
        Some((c.entry, hold.envelope.record_digest)),
        &[],
    );
    records.extend([release, hold]);
    let expected = expected(
        3,
        expected_fold("P1", Some(3), &[], &[], vec![], vec![]),
        Some(3),
        vec![],
        vec![],
        vec![c],
        vec![change(3, 0, 0, 0)],
    );
    assert_eq!(
        verify(&records, &expected).unwrap().explanation.as_ref(),
        Some(&expected)
    );
}

#[test]
fn provenance_retains_registered_reason_and_evidence_heads_exactly() {
    let mut records = schema();
    let a = vec![input_leg("1000", true, 100), input_leg("3000", false, 100)];
    let b = vec![input_leg("1000", false, 100), input_leg("3000", true, 100)];
    let original = posting(
        1,
        3,
        10,
        b"source",
        &a,
        None,
        None,
        &[([7; 32], [8; 32], 2)],
    );
    let original_id = identity(b"source");
    let reversal_id = target_id(b"fa:vid:reversal:v1", original_id);
    let reversal = posting(
        4,
        4,
        10,
        b"reverse",
        &b,
        Some((original_id, original.envelope.record_digest, 1, 1)),
        None,
        &[],
    );
    let mut original_c = contribution(
        &original,
        original_id,
        0,
        true,
        100,
        ExplanationColumn::Posted,
    );
    original_c.evidence.push(ExplanationEvidence {
        document_oid: [7; 32],
        doc_commit: [8; 32],
        role: 2,
    });
    let mut reversal_c = contribution(
        &reversal,
        reversal_id,
        0,
        false,
        100,
        ExplanationColumn::Posted,
    );
    reversal_c.supersedes.push(ExplanationSupersession {
        target: original_id,
        entry_digest: original.envelope.record_digest,
        kind: 1,
        reason_code: 1,
    });
    records.extend([original, reversal]);
    let digest = expected_fold(
        "P1",
        Some(4),
        &[(3, original_id, a), (4, reversal_id, b)],
        &[],
        vec![cell("1000", 100, 100, 2), cell("3000", 100, 100, 2)],
        vec![],
    );
    let report = expected(
        4,
        digest,
        Some(4),
        vec![cell("1000", 100, 100, 2)],
        vec![],
        vec![original_c, reversal_c],
        vec![change(3, 100, 0, 0), change(4, 100, 100, 0)],
    );
    let result = verify(&records, &report).unwrap();
    assert_eq!(result.explanation.as_ref(), Some(&report));
    assert_eq!(
        result.explanation.unwrap().supersession_reasons[&1].name,
        "ArchivedCorrection"
    );
    for mutation in 0..9 {
        let mut bad = report.clone();
        match mutation {
            0 => bad.fold_digest[0] ^= 1,
            1 => bad.cells[0].entry_count += 1,
            2 => bad.contributions[0].evidence[0].doc_commit[0] ^= 1,
            3 => bad.contributions[1].supersedes[0].reason_code = 2,
            4 => bad.contributions[1].visible_at = 3,
            5 => bad.contributions[1].entry ^= 1,
            6 => bad.history[1].credits += 1,
            7 => {
                bad.contributions.pop();
            }
            _ => {
                bad.history.remove(0);
            }
        }
        assert_eq!(
            verify(&records, &bad).unwrap_err().predicate,
            "report_recomputation",
            "mutation {mutation}"
        );
    }
}

#[test]
fn five_document_registry_profile_and_reason_scopes_are_mandatory() {
    let records = schema();
    let expected = expected(
        2,
        expected_fold("P1", None, &[], &[], vec![], vec![]),
        None,
        vec![],
        vec![],
        vec![],
        vec![],
    );
    assert!(verify(&records, &expected).is_ok());
    let mut docs = registries();
    docs.pop();
    assert_eq!(
        verify_with(&records, &expected, &docs, &[])
            .unwrap_err()
            .predicate,
        "registry_closure"
    );
    for mutation in 0..5 {
        let mut rows = reason_rows();
        match mutation {
            0 => rows[0].0 = 0,
            1 => rows[1].1 = "unregistered_scope",
            2 => rows[2].0 = 1,
            3 => rows[2].2 = "ArchivedCorrection",
            _ => {
                rows.pop();
            }
        }
        let mut docs = registries();
        docs[4].1 = reason_document(&rows);
        assert_eq!(
            verify_with(&records, &expected, &docs, &[])
                .unwrap_err()
                .predicate,
            "registry_closure"
        );
    }
    let (bytes, anchor, _) = pack(&records, &expected, &registries(), &[]);
    assert_eq!(
        verify_report_with(&bytes, &[], None, None, None, |_, _| Ok(anchor))
            .unwrap_err()
            .predicate,
        "report_input_authority"
    );
}

#[test]
fn historical_account_lifecycle_is_reconstructed_and_summary_selection_refused() {
    let mut records = schema();
    let mut close = Writer::default();
    close.bytes(b"1000").i32(20);
    records.push(record(
        17,
        3,
        20,
        b"close",
        0,
        Some((3, &close.buf)),
        None,
        None,
    ));
    let mut expected = expected(
        3,
        expected_fold("P1", None, &[], &[], vec![], vec![]),
        None,
        vec![],
        vec![],
        vec![],
        vec![],
    );
    expected.account_row.created_at = 3;
    assert_eq!(
        verify(&records, &expected).unwrap().explanation.as_ref(),
        Some(&expected)
    );
    let mut promote = Writer::default();
    promote.bytes(b"1000").i32(21);
    records.push(record(
        17,
        4,
        21,
        b"promote",
        0,
        Some((4, &promote.buf)),
        None,
        None,
    ));
    expected.known_at = 4;
    assert_eq!(
        verify(&records, &expected).unwrap_err().predicate,
        "account_metadata"
    );
    expected.known_at = 2;
    expected.account_row.created_at = 1;
    assert!(verify(&records, &expected).is_ok());
}

#[test]
fn empty_accounts_still_bind_other_account_cells_and_unknown_selectors_refuse() {
    let mut records = schema();
    let legs = vec![input_leg("3000", true, 5), input_leg("3000", false, 5)];
    records.push(posting(1, 3, 10, b"elsewhere", &legs, None, None, &[]));
    let expected = expected(
        3,
        expected_fold(
            "P1",
            Some(3),
            &[(3, identity(b"elsewhere"), legs)],
            &[],
            vec![cell("3000", 5, 5, 1)],
            vec![],
        ),
        Some(3),
        vec![],
        vec![],
        vec![],
        vec![],
    );
    assert!(verify(&records, &expected).is_ok());
    let mut bad = expected.clone();
    bad.account ^= 1;
    assert_eq!(
        verify(&records, &bad).unwrap_err().predicate,
        "account_metadata"
    );
    let mut bad = expected;
    bad.period = "missing".into();
    assert_eq!(
        verify(&records, &bad).unwrap_err().predicate,
        "period_metadata"
    );
}

#[test]
fn fold_checks_unselected_account_arithmetic_and_registry_units() {
    for unit in [1, 777] {
        let mut records = schema();
        let mut first = input_leg("3000", true, i128::MAX);
        first.unit = unit;
        let mut next = input_leg("3000", true, 1);
        next.unit = unit;
        records.extend([
            posting(1, 3, 10, b"large", &[first], None, None, &[]),
            posting(1, 4, 10, b"overflow", &[next], None, None, &[]),
        ]);
        let expected = expected(4, [0; 32], Some(4), vec![], vec![], vec![], vec![]);
        assert_eq!(
            verify(&records, &expected).unwrap_err().predicate,
            if unit == 1 {
                "exact_arithmetic"
            } else {
                "registry_closure"
            }
        );
    }
}

#[test]
fn retained_instant_explanation_uses_its_historical_bucket() {
    let mut records = schema();
    records.push(super::temporal::tick(3, 100, false));
    let legs = vec![input_leg("1000", true, 25), input_leg("3000", false, 25)];
    let posted = posting(1, 4, 10, b"inside", &legs, None, None, &[]);
    let c = contribution(
        &posted,
        identity(b"inside"),
        0,
        true,
        25,
        ExplanationColumn::Posted,
    );
    records.extend([
        posted,
        super::temporal::tick(5, 200, true),
        posting(
            1,
            6,
            10,
            b"later",
            &[input_leg("1000", true, 99)],
            None,
            None,
            &[],
        ),
    ]);
    let report = expected(
        4,
        expected_fold(
            "P1",
            Some(4),
            &[(4, identity(b"inside"), legs)],
            &[],
            vec![cell("1000", 25, 0, 1), cell("3000", 0, 25, 1)],
            vec![],
        ),
        Some(4),
        vec![cell("1000", 25, 0, 1)],
        vec![],
        vec![c],
        vec![change(4, 25, 0, 0)],
    );
    let (bytes, anchor, _) = pack(&records, &report, &registries(), &[]);
    let time = super::temporal::selection(150, 6, 4, (3, 100, false), Some((5, 200, true)));
    let (bytes, pin) = super::temporal::with_time(&bytes, &time);
    let result =
        verify_report_with(&bytes, &[], None, None, Some(&pin), |_, _| Ok(anchor)).unwrap();
    assert_eq!(result.time_selection, Some(time));
    assert_eq!(result.explanation, Some(report));
}

pub(super) fn migration_body(mode: u8, sole: bool) -> (u128, Vec<u8>, [u8; 32]) {
    let mut id = Writer::default();
    id.bytes(&BOOK).bytes(b"migration-run");
    let hash = hash_parts(b"fa:vid:migration-run:v1", &[&id.buf]);
    let run = u128::from_le_bytes(hash[..16].try_into().unwrap());
    let mut body = Writer::default();
    body.u16(1)
        .fixed(&BOOK)
        .bytes(b"migration-run")
        .bytes(b"legacy")
        .u8(mode)
        .fixed(&[0; 32])
        .i32(10)
        .count(0);
    if mode != 0 {
        body.count(0);
    }
    if mode == 2 {
        body.count(0).u8(u8::from(sole));
    }
    let digest = hash_parts(
        b"fa:migration-run-body:v1",
        &[&(body.buf.len() as u32).to_le_bytes(), &body.buf],
    );
    (run, body.buf, digest)
}
pub(super) fn migration_record(
    run: u128,
    body: [u8; 32],
    kind: Option<u8>,
    at: u64,
    day: i32,
    legs: &[Leg],
) -> Record {
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(if kind.is_some() { 22 } else { 12 })
        .i32(day)
        .u8(0);
    erasable(&mut w);
    w.u8(0).count(legs.len());
    for leg in legs {
        w.u8(u8::from(!leg.debit))
            .u128(leg.account)
            .u32(leg.unit)
            .i128(leg.mantissa)
            .u8(0)
            .count(0)
            .u8(0)
            .count(0);
    }
    w.u8(u8::from(kind.is_some()));
    if let Some(kind) = kind {
        w.u8(10)
            .u128(run)
            .u8(kind)
            .fixed(if kind == 0 { &body } else { &[9; 32] });
    }
    w.count(0).u8(0).bytes(&at.to_le_bytes());
    if kind.is_some() {
        w.u8(3).u16(9).fixed(&body);
    } else {
        w.u8(2).u128(run).bytes(b"legacy");
        erasable(&mut w);
        w.u8(0).u8(0).u8(0).fixed(&[0; 32]);
    }
    w.u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(0)
        .u8(0)
        .count(0)
        .count(0);
    seal(w, at)
}
pub(super) fn migration_id(run: u128, seq: u64) -> u128 {
    let mut w = Writer::default();
    w.bytes(&BOOK)
        .bytes(&run.to_le_bytes())
        .bytes(&seq.to_le_bytes());
    let h = hash_parts(b"fa:vid:migration-entry:v1", &[&w.buf]);
    u128::from_le_bytes(h[..16].try_into().unwrap())
}
#[test]
fn migration_chunk_creation_and_finalize_visibility_are_distinct() {
    for (mode, sole, day, terminal, counts) in [
        (0, false, 9, 1, true),
        (1, false, 9, 1, true),
        (2, false, 9, 1, false),
        (2, true, 9, 1, true),
        (2, false, 10, 1, true),
        (0, false, 9, 2, false),
    ] {
        let (run, body, digest) = migration_body(mode, sole);
        let mut records = schema();
        let legs = vec![input_leg("1000", true, 35), input_leg("3000", false, 35)];
        let chunk = migration_record(run, digest, None, 4, day, &legs);
        let id = migration_id(run, 4);
        let mut c = contribution(&chunk, id, 0, true, 35, ExplanationColumn::Posted);
        c.visible_at = 6;
        records.extend([
            migration_record(run, digest, Some(0), 3, 10, &[]),
            chunk,
            migration_record(run, digest, Some(terminal), 6, 10, &[]),
        ]);
        let before = expected(
            4,
            expected_fold("P1", None, &[], &[], vec![], vec![]),
            None,
            vec![],
            vec![],
            vec![],
            vec![],
        );
        assert!(verify_with(&records, &before, &registries(), &[(2, body.clone())]).is_ok());
        let report = if counts {
            expected(
                6,
                expected_fold(
                    "P1",
                    Some(6),
                    &[(4, id, legs)],
                    &[],
                    vec![cell("1000", 35, 0, 1), cell("3000", 0, 35, 1)],
                    vec![],
                ),
                Some(6),
                vec![cell("1000", 35, 0, 1)],
                vec![],
                vec![c],
                vec![change(6, 35, 0, 0)],
            )
        } else {
            expected(
                6,
                expected_fold("P1", None, &[], &[], vec![], vec![]),
                None,
                vec![],
                vec![],
                vec![],
                vec![],
            )
        };
        let result = verify_with(&records, &report, &registries(), &[(2, body.clone())]).unwrap();
        assert_eq!(
            result.explanation.as_ref(),
            Some(&report),
            "mode {mode}, sole {sole}, day {day}, terminal {terminal}"
        );
        assert_eq!(
            verify_with(&records, &report, &registries(), &[])
                .unwrap_err()
                .predicate,
            "migration_visibility"
        );
        if counts {
            let mut bad = report.clone();
            bad.contributions[0].visible_at = 4;
            assert_eq!(
                verify_with(&records, &bad, &registries(), &[(2, body)])
                    .unwrap_err()
                    .predicate,
                "report_recomputation"
            );
        }
    }
}
#[test]
fn same_commit_fold_uses_derived_identity_order_and_retains_every_leg() {
    let mut records = schema();
    let a = vec![input_leg("1000", true, 9), input_leg("3000", false, 9)];
    let b = vec![input_leg("1000", false, 4), input_leg("3000", true, 4)];
    let first = posting(1, 3, 10, b"first", &a, None, None, &[]);
    let second = posting(1, 3, 10, b"second", &b, None, None, &[]);
    let mut contributions = vec![
        contribution(
            &first,
            identity(b"first"),
            0,
            true,
            9,
            ExplanationColumn::Posted,
        ),
        contribution(
            &second,
            identity(b"second"),
            0,
            false,
            4,
            ExplanationColumn::Posted,
        ),
    ];
    contributions.sort_by_key(|c| (c.recorded_at, c.entry, c.ordinal));
    records.extend([first, second]);
    let report = expected(
        3,
        expected_fold(
            "P1",
            Some(3),
            &[(3, identity(b"first"), a), (3, identity(b"second"), b)],
            &[],
            vec![cell("1000", 9, 4, 2), cell("3000", 4, 9, 2)],
            vec![],
        ),
        Some(3),
        vec![cell("1000", 9, 4, 2)],
        vec![],
        contributions,
        vec![change(3, 9, 4, 0)],
    );
    assert!(verify(&records, &report).is_ok());
    records.swap(2, 3);
    assert!(verify(&records, &report).is_ok());
}
#[test]
fn unregistered_reasons_and_wrong_lineage_digests_are_refused() {
    for (reason, wrong_digest, expected_predicate) in
        [(99, false, "registry_closure"), (1, true, "entry_lineage")]
    {
        let mut records = schema();
        let original = posting(
            1,
            3,
            10,
            b"lineage-source",
            &[input_leg("1000", true, 10)],
            None,
            None,
            &[],
        );
        let mut digest = original.envelope.record_digest;
        if wrong_digest {
            digest[0] ^= 1;
        }
        let reversal = posting(
            4,
            4,
            10,
            b"lineage-reversal",
            &[input_leg("1000", false, 10)],
            Some((identity(b"lineage-source"), digest, 1, reason)),
            None,
            &[],
        );
        records.extend([original, reversal]);
        let expected = expected(4, [0; 32], Some(4), vec![], vec![], vec![], vec![]);
        assert_eq!(
            verify(&records, &expected).unwrap_err().predicate,
            expected_predicate
        );
    }
}
