use super::*;
use fa_model::AccountType;
use fa_registers::TbRow;
use fa_time::DateDay;

fn row(account: u128, code: &str, unit_id: u32, debits: i128, credits: i128) -> TbRow {
    TbRow {
        account: VId(account),
        code: code.into(),
        name: code.into(),
        account_type: AccountType::ASSET,
        unit_id,
        debits,
        credits,
        debits_pending: 0,
        credits_pending: 0,
    }
}

fn tb(rows: Vec<TbRow>) -> TrialBalance {
    TrialBalance {
        periods: vec!["FY2026-P01".into()],
        known_at: CommitSeq(9),
        effective_through: Some(DateDay::from_ymd(2026, 1, 31).unwrap()),
        activity: false,
        rows,
        unit_totals: BTreeMap::new(),
        pending_unit_totals: BTreeMap::new(),
    }
}

#[test]
fn draft_difference_preserves_pending_release_gross_changes_and_separate_units() {
    let mut original_cash = row(1, "1000", 1, 500, 100);
    original_cash.debits_pending = 40;
    let mut revised_cash = row(1, "1000", 1, 650, 200);
    revised_cash.debits_pending = 10;
    let trunk = tb(vec![
        row(3, "5000", 1, 10, 10),
        original_cash,
        row(2, "3000", 1, 0, 400),
    ]);
    let draft = tb(vec![
        row(2, "3000", 1, 0, 450),
        row(1, "1000", 2, 7, 0),
        revised_cash,
        row(3, "5000", 1, 20, 20),
    ]);
    let rows = difference(&trunk, &draft).unwrap();
    let changes: Vec<_> = rows
        .iter()
        .map(|row| (row.code.as_str(), row.unit_id, row.delta, row.pending_delta))
        .collect();
    assert_eq!(
        changes,
        [
            ("1000", 1, 50, -30),
            ("1000", 2, 7, 0),
            ("3000", 1, -50, 0),
            ("5000", 1, 0, 0),
        ]
    );
    assert_eq!((rows[3].draft_debits, rows[3].draft_credits), (20, 20));
    assert!(difference(&trunk, &trunk).unwrap().is_empty());
}

#[test]
fn draft_difference_refuses_overflow_and_changed_source_metadata() {
    let trunk = tb(vec![row(1, "1000", 1, 0, i128::MAX)]);
    let draft = tb(vec![row(1, "1000", 1, i128::MAX, 0)]);
    assert!(
        difference(&trunk, &draft)
            .unwrap_err()
            .message
            .contains("exact i128")
    );
    let changed = tb(vec![row(1, "renamed", 1, 0, i128::MAX)]);
    assert!(
        difference(&trunk, &changed)
            .unwrap_err()
            .message
            .contains("metadata")
    );
}

#[test]
fn draft_output_requires_one_complete_atomic_rehearsal() {
    let mut report = DraftDiff {
        name: "review".into(),
        draft: VId(5),
        owner: VId(6),
        source_known_at: CommitSeq(9),
        source_digest: [7; 32],
        period: "FY2026-P01".into(),
        plans: 1,
        seq_map_digest: [8; 32],
        rehearsal_known_at: CommitSeq(10),
        batch_outcome: VId(11),
        entries: vec![EntryRef {
            vid: VId(12),
            entry_digest: [13; 32],
        }],
        rows: Vec::new(),
    };
    let bytes = report.canonical_bytes().unwrap();
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.str(64, "format").unwrap(), "fa:draft-diff:v1");
    report.plans = 2;
    assert!(
        report.canonical_bytes().is_err(),
        "partial member results refuse"
    );
    report.plans = 1;
    report.rehearsal_known_at = CommitSeq(11);
    assert!(
        report.canonical_bytes().is_err(),
        "sequential member commits refuse"
    );
}

#[test]
fn draft_certificate_decoder_refuses_foreign_version_and_truncated_source() {
    assert!(DraftDiffCertificate::decode(&[]).is_err());
    let mut writer = Writer::new();
    writer.bytes(b"fa:draft-diff-certificate:v2");
    assert!(DraftDiffCertificate::decode(&writer.finish().unwrap()).is_err());
    let mut writer = Writer::new();
    writer
        .bytes(DRAFT_DIFF_CERTIFICATE_FORMAT)
        .bytes(b"not a native certificate");
    assert!(DraftDiffCertificate::decode(&writer.finish().unwrap()).is_err());
}
