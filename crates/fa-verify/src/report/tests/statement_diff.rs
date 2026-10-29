//! A complete-prefix comparison with independently encoded source reports and
//! hand-calculated expectations. Repaired certificate/output hashes do not
//! excuse a false historical source or bridge.
use super::*;

struct Fixture {
    records: Vec<Record>,
    before: VerifiedStatement,
    after: VerifiedStatement,
    before_source: Vec<u8>,
    after_source: Vec<u8>,
    after_bundle: Vec<u8>,
    anchor: SignedCheckpoint,
    claim: VerifiedStatementDiff,
}

fn certificate_bytes(bundle: &[u8]) -> &[u8] {
    let mut r = Reader::new(bundle);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap()
}

fn replace_certificate(bundle: &[u8], certificate: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(bundle);
    r.bytes(64, "format").unwrap();
    let major = r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap();
    let suffix = &bundle[bundle.len() - r.remaining()..];
    let mut w = Writer::default();
    w.bytes(REPORT_BUNDLE_FORMAT)
        .u16(major)
        .u16(0)
        .bytes(certificate)
        .fixed(suffix);
    w.buf
}

fn mapping(w: &mut Writer, value: &StatementMapping) {
    w.u128(value.account)
        .bytes(value.code.as_bytes())
        .bytes(value.name.as_bytes())
        .u8(value.account_type)
        .u8(u8::from(value.is_leaf))
        .bytes(value.line_code.as_bytes());
}

fn bridge_output(claim: &VerifiedStatementDiff) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:statement-diff:v1")
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(claim.before_known_at)
        .u64(claim.after_known_at)
        .fixed(&claim.before_digest)
        .fixed(&claim.after_digest)
        .fixed(&claim.before.definition_digest)
        .count(claim.before.columns.len());
    for column in &claim.before.columns {
        w.bytes(column.label.as_bytes()).count(column.periods.len());
        for period in &column.periods {
            w.bytes(period.as_bytes());
        }
        w.u8(u8::from(column.effective_from.is_some()));
        if let Some(day) = column.effective_from {
            w.i32(day);
        }
        w.i32(column.effective_through);
    }
    w.count(claim.lines.len());
    for line in &claim.lines {
        w.bytes(line.code.as_bytes())
            .bytes(line.label.as_bytes())
            .u32(line.unit);
        for amounts in [&line.before, &line.after, &line.delta] {
            w.count(amounts.len());
            for amount in amounts {
                w.i128(*amount);
            }
        }
    }
    w.count(claim.mapping_changes.len());
    for change in &claim.mapping_changes {
        w.u128(change.account);
        for value in [&change.before, &change.after] {
            w.u8(u8::from(value.is_some()));
            if let Some(value) = value {
                mapping(&mut w, value);
            }
        }
    }
    w.buf
}

fn outer(before: &[u8], after: &[u8], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    w.bytes(b"fa:statement-diff-certificate:v1")
        .u128(PRINCIPAL)
        .fixed(&[8; 32])
        .bytes(before)
        .bytes(after)
        .bytes(output);
    let pin = hash_parts(
        b"fa:statement-diff-certificate-digest:v1",
        &[&(w.buf.len() as u32).to_le_bytes(), &w.buf],
    );
    w.fixed(&pin);
    (w.buf, pin)
}

impl Fixture {
    fn bundle_with(
        &self,
        before: &[u8],
        after: &[u8],
        claim: &VerifiedStatementDiff,
    ) -> (Vec<u8>, [u8; 32]) {
        let (outer, pin) = outer(before, after, &bridge_output(claim));
        (replace_certificate(&self.after_bundle, &outer), pin)
    }

    fn bundle(&self) -> (Vec<u8>, [u8; 32]) {
        self.bundle_with(&self.before_source, &self.after_source, &self.claim)
    }

    fn check(&self, bytes: &[u8], pin: [u8; 32]) -> Result<VerifiedReport, ReportError> {
        verify_statement_fixture(bytes, self.anchor.clone(), pin)
    }

    fn source(&self, statement: &VerifiedStatement, known_at: u64) -> Vec<u8> {
        let activity = statement.kind == "IncomeStatement";
        let definition = definition(activity);
        let docs = registries();
        let (bundle, _, _) = pack_at(
            &self.records,
            &definition,
            &output_bytes(statement, &definition, known_at),
            &docs,
            closure(&docs),
            known_at,
        );
        certificate_bytes(&bundle).to_vec()
    }
}

fn fixture(activity: bool) -> Fixture {
    let mut records = history();
    // Add a new zero-balance expense account, then retire another zero-balance
    // leaf into a summary. Both affect complete mapping coverage, not money.
    let mut chart = Writer::default();
    chart
        .count(1)
        .bytes(b"5002")
        .bytes(b"New zero expense")
        .u8(5)
        .u8(0)
        .u8(1)
        .fixed(&0i64.to_le_bytes())
        .u8(0);
    records.push(record(
        17,
        11,
        0,
        b"new-zero-leaf",
        0,
        Some((1, &chart.buf)),
        None,
        None,
    ));
    let mut promotion = Writer::default();
    promotion.bytes(b"5001").i32(0);
    records.push(record(
        17,
        12,
        0,
        b"zero-leaf-to-summary",
        0,
        Some((4, &promotion.buf)),
        None,
        None,
    ));
    records.push(make(
        1,
        13,
        40,
        b"after-both-frontiers",
        &[("1000", true, 200), ("4000", false, 200)],
        None,
    ));
    let before = expected(activity);
    let mut after = before.clone();
    for line in &mut after.lines {
        if line.unit != 0 {
            continue;
        }
        // The only new money at the later frontier is the literal 9,999 sale
        // at sequence 10. Closing and both reversal descendants are already
        // on the earlier side; they never enter income-statement activity.
        line.amounts[0] = match line.code.as_str() {
            "revenue" => 11_233,
            "net_income" => 10_999,
            "assets" | "total_equity" | "liabilities_and_equity" => 11_499,
            "unclosed_revenue" => 10_233,
            "unclosed_earnings" => 9_999,
            _ => line.amounts[0],
        };
    }
    let retired = after
        .mappings
        .iter()
        .find(|m| m.code == "5001")
        .unwrap()
        .clone();
    after.mappings.retain(|m| m.code != "5001");
    let added = StatementMapping {
        account: account_id("5002"),
        code: "5002".into(),
        name: "New zero expense".into(),
        account_type: 5,
        is_leaf: true,
        line_code: if activity {
            "expense"
        } else {
            "unclosed_expense"
        }
        .into(),
    };
    after.mappings.push(added.clone());
    let definition = definition(activity);
    let before_output = output_bytes(&before, &definition, 9);
    let after_output = output_bytes(&after, &definition, 12);
    let docs = registries();
    let (before_bundle, _, _) = pack_at(
        &records,
        &definition,
        &before_output,
        &docs,
        closure(&docs),
        9,
    );
    let (after_bundle, anchor, _) = pack_at(
        &records,
        &definition,
        &after_output,
        &docs,
        closure(&docs),
        12,
    );
    let mut mapping_changes = vec![
        StatementMappingChange {
            account: retired.account,
            before: Some(retired),
            after: None,
        },
        StatementMappingChange {
            account: added.account,
            before: None,
            after: Some(added),
        },
    ];
    mapping_changes.sort_by_key(|change| change.account);
    let lines = before
        .lines
        .iter()
        .zip(&after.lines)
        .map(|(old, new)| StatementLineChange {
            code: old.code.clone(),
            label: old.label.clone(),
            unit: old.unit,
            before: old.amounts.clone(),
            after: new.amounts.clone(),
            delta: vec![
                if old.unit == 0
                    && matches!(
                        old.code.as_str(),
                        "revenue"
                            | "net_income"
                            | "assets"
                            | "total_equity"
                            | "liabilities_and_equity"
                            | "unclosed_revenue"
                            | "unclosed_earnings"
                    )
                {
                    9_999
                } else {
                    0
                },
                0,
            ],
        })
        .collect();
    Fixture {
        records,
        before: before.clone(),
        after: after.clone(),
        before_source: certificate_bytes(&before_bundle).to_vec(),
        after_source: certificate_bytes(&after_bundle).to_vec(),
        after_bundle,
        anchor,
        claim: VerifiedStatementDiff {
            before_known_at: 9,
            after_known_at: 12,
            before_digest: hash_parts(
                b"fa:statement-diff-source:v1",
                &[&(before_output.len() as u32).to_le_bytes(), &before_output],
            ),
            after_digest: hash_parts(
                b"fa:statement-diff-source:v1",
                &[&(after_output.len() as u32).to_le_bytes(), &after_output],
            ),
            before,
            after,
            lines,
            mapping_changes,
        },
    }
}

#[test]
fn historical_statement_bridges_recompute_both_sources_and_zero_mapping_changes() {
    for activity in [false, true] {
        let f = fixture(activity);
        let (bundle, pin) = f.bundle();
        let verified = f.check(&bundle, pin).unwrap();
        assert_eq!(verified.statement_diff, Some(f.claim.clone()));
        assert!(verified.statement.is_none());
        assert_eq!(verified.output, bridge_output(&f.claim));
        assert_eq!(verified.certificate_digest, pin);
        assert_eq!(verified.known_at, 12);
        assert_eq!(verified.checkpoint.checkpoint.through_seq, 13);
        assert_eq!(verified.checked_records, 13);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        assert!(f.claim.lines.iter().all(|line| line.delta[1] == 0));
        assert_eq!(f.claim.mapping_changes.len(), 2);
        assert!(
            f.claim
                .lines
                .iter()
                .any(|line| line.unit == 12 && line.delta == [0, 0])
        );
    }
}

#[test]
fn resealed_false_earlier_or_later_statement_cannot_supply_a_bridge() {
    let f = fixture(true);
    for before in [true, false] {
        let mut false_statement = if before {
            f.before.clone()
        } else {
            f.after.clone()
        };
        false_statement.lines[0].amounts[0] += 1;
        let source = f.source(&false_statement, if before { 9 } else { 12 });
        let (bundle, pin) = f.bundle_with(
            if before { &source } else { &f.before_source },
            if before { &f.after_source } else { &source },
            &f.claim,
        );
        assert_eq!(
            f.check(&bundle, pin).unwrap_err().predicate,
            "report_recomputation"
        );
    }
}

#[test]
fn resealed_deltas_source_commitments_zero_rows_columns_and_mappings_are_checked() {
    let f = fixture(false);
    for mutation in 0..9 {
        let mut claim = f.claim.clone();
        match mutation {
            0 => claim.lines[0].delta[0] += 1,
            1 => claim.lines[0].before[0] += 1,
            2 => claim.lines[0].after[0] += 1,
            3 => claim.before_digest[0] ^= 1,
            4 => claim.after_digest[0] ^= 1,
            5 => claim.lines.retain(|line| line.unit != 12),
            6 => claim.before.columns.swap(0, 1),
            7 => claim.mapping_changes.clear(),
            8 => claim.mapping_changes.swap(0, 1),
            _ => unreachable!(),
        }
        let (bundle, pin) = f.bundle_with(&f.before_source, &f.after_source, &claim);
        assert_eq!(
            f.check(&bundle, pin).unwrap_err().predicate,
            "statement_diff_recomputation",
            "mutation {mutation} must be rejected even after replacing the outer pin"
        );
    }
}

#[test]
fn comparison_commitments_require_length_framed_model_domain_hashes() {
    let f = fixture(false);
    let (bundle, _) = f.bundle();
    let mut encoded = certificate_bytes(&bundle).to_vec();
    let end = encoded.len() - 32;
    let unframed = hash_parts(
        b"fa:statement-diff-certificate-digest:v1",
        &[&encoded[..end]],
    );
    encoded[end..].copy_from_slice(&unframed);
    assert_eq!(
        f.check(&replace_certificate(&bundle, &encoded), unframed)
            .unwrap_err()
            .predicate,
        "certificate_digest"
    );

    for before in [true, false] {
        let mut claim = f.claim.clone();
        let (statement, known_at) = if before {
            (&f.before, claim.before_known_at)
        } else {
            (&f.after, claim.after_known_at)
        };
        let output = output_bytes(statement, &definition(false), known_at);
        let unframed = hash_parts(b"fa:statement-diff-source:v1", &[&output]);
        if before {
            claim.before_digest = unframed;
        } else {
            claim.after_digest = unframed;
        }
        let (bundle, pin) = f.bundle_with(&f.before_source, &f.after_source, &claim);
        assert_eq!(
            f.check(&bundle, pin).unwrap_err().predicate,
            "statement_diff_recomputation"
        );
    }
}

#[test]
fn equal_frontier_empty_bridge_still_authenticates_complete_sources() {
    let f = fixture(true);
    let mut claim = f.claim.clone();
    claim.after_known_at = claim.before_known_at;
    claim.after = claim.before.clone();
    claim.after_digest = claim.before_digest;
    claim.mapping_changes.clear();
    for line in &mut claim.lines {
        line.after = line.before.clone();
        line.delta.fill(0);
    }
    let (bundle, pin) = f.bundle_with(&f.before_source, &f.before_source, &claim);
    let verified = f.check(&bundle, pin).unwrap();
    assert_eq!(verified.statement_diff.unwrap(), claim);

    let mut missing = claim;
    missing.lines.clear();
    let (bundle, pin) = f.bundle_with(&f.before_source, &f.before_source, &missing);
    assert_eq!(
        f.check(&bundle, pin).unwrap_err().predicate,
        "statement_diff_recomputation"
    );

    let mut false_statement = f.before.clone();
    false_statement.lines[0].amounts[0] += 7;
    let false_source = f.source(&false_statement, 9);
    let (bundle, pin) = f.bundle_with(&false_source, &false_source, &missing);
    assert_eq!(
        f.check(&bundle, pin).unwrap_err().predicate,
        "report_recomputation"
    );
}

#[test]
fn reversed_frontiers_cross_epoch_and_another_statement_question_are_refused() {
    let f = fixture(true);
    let (bundle, pin) = f.bundle_with(&f.after_source, &f.before_source, &f.claim);
    assert_eq!(
        f.check(&bundle, pin).unwrap_err().predicate,
        "statement_diff_selection"
    );

    let other = fixture(false);
    let (bundle, pin) = f.bundle_with(&f.before_source, &other.after_source, &f.claim);
    assert_eq!(
        f.check(&bundle, pin).unwrap_err().predicate,
        "statement_diff_selection"
    );

    let mut other_epoch = f.before_source.clone();
    let registry = closure(&registries());
    let at = other_epoch
        .windows(32)
        .position(|bytes| bytes == registry)
        .unwrap();
    other_epoch[at] ^= 1;
    let end = other_epoch.len() - 32;
    let digest = hash_parts(STATEMENT_CERTIFICATE_FORMAT, &[&other_epoch[..end]]);
    other_epoch[end..].copy_from_slice(&digest);
    let (bundle, pin) = f.bundle_with(&other_epoch, &f.after_source, &f.claim);
    assert_eq!(
        f.check(&bundle, pin).unwrap_err().predicate,
        "registry_closure"
    );
}

#[test]
fn a_statement_comparison_requires_its_outer_pin_complete_prefix_and_registry_profile() {
    let f = fixture(true);
    let (bundle, pin) = f.bundle();
    let after_pin = super::super::super::certificate(&f.after_source)
        .unwrap()
        .digest;
    assert_eq!(
        f.check(&bundle, after_pin).unwrap_err().predicate,
        "recipient_certificate"
    );
    assert_eq!(
        verify_fixture(&bundle, f.anchor.clone())
            .unwrap_err()
            .predicate,
        "report_input_authority"
    );

    let mut old_profile = bundle.clone();
    let major_offset = 4 + REPORT_BUNDLE_FORMAT.len();
    old_profile[major_offset..major_offset + 2].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        f.check(&old_profile, pin).unwrap_err().predicate,
        "registry_closure"
    );

    let mut corrupted = bundle.clone();
    let last = f.records.last().unwrap();
    let at = corrupted
        .windows(last.bytes.len())
        .position(|bytes| bytes == last.bytes)
        .unwrap();
    corrupted[at + 40] ^= 1;
    assert_eq!(
        f.check(&corrupted, pin).unwrap_err().predicate,
        "record_derivation"
    );
}

#[test]
fn statement_diff_refuses_functional_sources_recursive_wrappers_and_noncanonical_bytes() {
    let f = fixture(true);
    let (bundle, pin) = f.bundle();
    let encoded = certificate_bytes(&bundle);
    let functional = {
        let mut r = Reader::new(encoded);
        r.bytes(64, "format").unwrap();
        let rest = &encoded[encoded.len() - r.remaining()..];
        let mut w = Writer::default();
        w.bytes(b"fa:functional-statement-diff-certificate:v1")
            .fixed(rest);
        w.buf
    };
    assert_eq!(
        f.check(&replace_certificate(&bundle, &functional), pin)
            .unwrap_err()
            .predicate,
        "supported_report"
    );
    for before in [functional.as_slice(), encoded] {
        let (nested, pin) = outer(before, &f.after_source, &bridge_output(&f.claim));
        assert_eq!(
            f.check(&replace_certificate(&bundle, &nested), pin)
                .unwrap_err()
                .predicate,
            "supported_report"
        );
    }
    for end in [0, 4, encoded.len() - 1] {
        assert!(
            f.check(&replace_certificate(&bundle, &encoded[..end]), pin)
                .is_err()
        );
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_eq!(
        f.check(&replace_certificate(&bundle, &trailing), pin)
            .unwrap_err()
            .predicate,
        "canonical_encoding"
    );
}
