//! Hand-calculated two-frontier functional statements. The fixture adds a new
//! Rate and a zero leaf only after the earlier source, then a later backdate
//! beyond both sources. Every malformed output is resealed to exercise the
//! accounting predicates rather than only the outer hash check.

use super::*;
use crate::report::MAX_REPORT_BUNDLE_BYTES;

struct Fixture {
    records: Vec<Record>,
    rates: Vec<RateFixture>,
    before_request: Request,
    after_request: Request,
    before: VerifiedFunctionalStatement,
    after: VerifiedFunctionalStatement,
    claim: VerifiedStatementDiff,
}

fn source(bundle: &[u8]) -> &[u8] {
    let mut r = Reader::new(bundle);
    r.bytes(64, "bundle format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "source").unwrap()
}

fn replace_source(bundle: &[u8], certificate: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(bundle);
    r.bytes(64, "bundle format").unwrap();
    let major = r.u16("major").unwrap();
    let minor = r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "source").unwrap();
    let suffix = &bundle[bundle.len() - r.remaining()..];
    let mut w = Writer::default();
    w.bytes(REPORT_BUNDLE_FORMAT)
        .u16(major)
        .u16(minor)
        .bytes(certificate)
        .fixed(suffix);
    w.buf
}

fn inner_statement(output: &[u8]) -> &[u8] {
    let mut r = Reader::new(output);
    r.fixed::<{ b"fa:functional-statement:v1".len() }>("format")
        .unwrap();
    assert_eq!(r.bytes(64, "basis").unwrap(), b"retained-base-amounts");
    let bytes = r.bytes(64 * 1024 * 1024, "statement").unwrap();
    r.finish("functional output").unwrap();
    bytes
}

fn source_digest(bytes: &[u8]) -> [u8; 32] {
    let inner = inner_statement(bytes);
    hash_parts(
        b"fa:functional-statement-diff-source:v1",
        &[&(inner.len() as u32).to_le_bytes(), inner],
    )
}

fn bridge(claim: &VerifiedStatementDiff) -> Vec<u8> {
    let StatementDiffValuation::Functional { base_unit, .. } = claim.valuation else {
        panic!("functional fixture")
    };
    let mut w = Writer::default();
    w.bytes(b"fa:functional-statement-diff:v1")
        .u32(base_unit)
        .bytes(b"retained-base-amounts")
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
        if let Some(from) = column.effective_from {
            w.i32(from);
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
        for mapping in [&change.before, &change.after] {
            w.u8(u8::from(mapping.is_some()));
            if let Some(mapping) = mapping {
                w.u128(mapping.account)
                    .bytes(mapping.code.as_bytes())
                    .bytes(mapping.name.as_bytes())
                    .u8(mapping.account_type)
                    .u8(u8::from(mapping.is_leaf))
                    .bytes(mapping.line_code.as_bytes());
            }
        }
    }
    w.buf
}

fn outer(before: &[u8], after: &[u8], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    w.bytes(b"fa:functional-statement-diff-certificate:v1")
        .u128(PRINCIPAL)
        .fixed(&[8; 32])
        .bytes(before)
        .bytes(after)
        .bytes(output);
    let pin = hash_parts(
        b"fa:functional-statement-diff-certificate-digest:v1",
        &[&(w.buf.len() as u32).to_le_bytes(), &w.buf],
    );
    w.fixed(&pin);
    (w.buf, pin)
}

impl Fixture {
    fn source_bundle(
        &self,
        before: bool,
        result: &VerifiedFunctionalStatement,
    ) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
        let request = if before {
            &self.before_request
        } else {
            &self.after_request
        };
        pack_statement(
            &self.records,
            request,
            &book(&[]),
            &self.rates,
            &output(result, request),
        )
    }

    fn bundle_with(
        &self,
        before: &VerifiedFunctionalStatement,
        after: &VerifiedFunctionalStatement,
        claim: &VerifiedStatementDiff,
    ) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
        let (before_bundle, _, _) = self.source_bundle(true, before);
        let (after_bundle, signed, _) = self.source_bundle(false, after);
        let (certificate, pin) = outer(
            source(&before_bundle),
            source(&after_bundle),
            &bridge(claim),
        );
        (replace_source(&after_bundle, &certificate), signed, pin)
    }

    fn bundle(&self) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
        self.bundle_with(&self.before, &self.after, &self.claim)
    }
}

fn fixture(activity: bool) -> Fixture {
    let (mut records, mut rates) = history();
    let later_rate = rate_fixture(9, 4, 3, 58);
    records.push(intake(&later_rate, 14));
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
    // This is a second immutable schema declaration, so it needs its own
    // idempotency key rather than the bootstrap fixture's `chart` identity.
    let mut declaration = prefix(17, 0);
    declaration
        .count(0)
        .u8(1)
        .u8(1)
        .u16(1)
        .bytes(&chart.buf)
        .count(0)
        .u8(0)
        .bytes(b"comparison-zero-chart")
        .u8(3)
        .u16(1)
        .fixed(&[0; 32])
        .u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(0)
        .u8(0)
        .count(0)
        .count(0);
    records.push(finish(declaration, 15));
    records.push(entry(
        16,
        1,
        40,
        b"new-rate-sale",
        &valued_pair("1000", "4000", 100, 225),
        Some((3, &later_rate, None)),
        None,
        None,
    ));
    records.push(entry(
        17,
        1,
        40,
        b"after-both-frontiers",
        &valued_pair("1000", "4000", 200, 450),
        Some((3, &later_rate, None)),
        None,
        None,
    ));
    rates.push(later_rate);
    let before_request = request(activity);
    let mut after_request = request(activity);
    after_request.known_at = 16;
    let before = expected(&before_request, 0);
    // The old quote's later backdate contributes 9,990; the new quote adds
    // exactly 225. Neither the future 450 nor any close enters income.
    let mut after = expected(&after_request, 10_215);
    let zero = StatementMapping {
        account: id("5002"),
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
    after.statement.mappings.push(zero.clone());
    let lines = before
        .statement
        .lines
        .iter()
        .zip(&after.statement.lines)
        .map(|(old, new)| {
            let changed = if activity {
                matches!(old.code.as_str(), "revenue" | "net_income")
            } else {
                matches!(
                    old.code.as_str(),
                    "assets"
                        | "unclosed_revenue"
                        | "unclosed_earnings"
                        | "total_equity"
                        | "liabilities_and_equity"
                )
            };
            StatementLineChange {
                code: old.code.clone(),
                label: old.label.clone(),
                unit: 0,
                before: old.amounts.clone(),
                after: new.amounts.clone(),
                delta: vec![if changed { 10_215 } else { 0 }, 0],
            }
        })
        .collect();
    let claim = VerifiedStatementDiff {
        valuation: StatementDiffValuation::Functional {
            base_unit: 0,
            book_parameters_source: BOOK_PARAMETERS_SOURCE,
        },
        before_known_at: 11,
        after_known_at: 16,
        before_digest: source_digest(&output(&before, &before_request)),
        after_digest: source_digest(&output(&after, &after_request)),
        before: before.statement.clone(),
        after: after.statement.clone(),
        lines,
        mapping_changes: vec![StatementMappingChange {
            account: zero.account,
            before: None,
            after: Some(zero),
        }],
    };
    Fixture {
        records,
        rates,
        before_request,
        after_request,
        before,
        after,
        claim,
    }
}

#[test]
fn functional_comparison_replays_each_original_rate_set_and_historical_zero_mapping() {
    for activity in [false, true] {
        let f = fixture(activity);
        let (bytes, signed, pin) = f.bundle();
        let verified = verify(&bytes, &signed, &pin).unwrap();
        assert_eq!(verified.statement_diff, Some(f.claim.clone()));
        assert_eq!(verified.output, bridge(&f.claim));
        assert_eq!(verified.certificate_digest, pin);
        assert_eq!(verified.known_at, 16);
        assert!(verified.functional_statement.is_none());
        assert!(verified.statement.is_none());
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
    }
}

#[test]
fn resealed_functional_comparison_cannot_forge_sources_deltas_measure_or_zero_coverage() {
    let f = fixture(true);
    let mut mutations = Vec::new();
    let mut delta = f.claim.clone();
    delta.lines[0].delta[0] += 1;
    mutations.push(delta);
    let mut zero = f.claim.clone();
    zero.lines.remove(1);
    mutations.push(zero);
    let mut mapping = f.claim.clone();
    mapping.mapping_changes.clear();
    mutations.push(mapping);
    let mut measure = f.claim.clone();
    measure.valuation = StatementDiffValuation::Functional {
        base_unit: 1,
        book_parameters_source: BOOK_PARAMETERS_SOURCE,
    };
    mutations.push(measure);
    let mut commitment = f.claim.clone();
    commitment.before_digest[0] ^= 1;
    mutations.push(commitment);
    for claim in mutations {
        let (bytes, signed, pin) = f.bundle_with(&f.before, &f.after, &claim);
        assert_eq!(
            verify(&bytes, &signed, &pin).unwrap_err().predicate,
            "statement_diff_recomputation"
        );
    }
    for earlier in [true, false] {
        let mut before = f.before.clone();
        let mut after = f.after.clone();
        if earlier {
            before.statement.lines[0].amounts[0] += 1;
        } else {
            after.statement.lines[0].amounts[0] += 1;
        }
        let (bytes, signed, pin) = f.bundle_with(&before, &after, &f.claim);
        assert_eq!(
            verify(&bytes, &signed, &pin).unwrap_err().predicate,
            "report_recomputation"
        );
    }
}

#[test]
fn functional_comparison_requires_exact_rate_evidence_and_original_earlier_frontier() {
    let mut missing = fixture(true);
    missing.rates.pop();
    let (bytes, signed, pin) = missing.bundle();
    assert_eq!(
        verify(&bytes, &signed, &pin).unwrap_err().predicate,
        "functional_rates"
    );
    let mut padded = fixture(true);
    padded.rates.push(rate_fixture(17, 10, 3, 58));
    let (bytes, signed, pin) = padded.bundle();
    assert_eq!(
        verify(&bytes, &signed, &pin).unwrap_err().predicate,
        "functional_rates"
    );
    let mut late = fixture(true);
    // The earlier average quote must be present before use. Remove its import
    // entirely and reseal the complete checkpoint, so membership alone passes.
    late.records.remove(4);
    let (bytes, signed, pin) = late.bundle();
    assert_eq!(
        verify(&bytes, &signed, &pin).unwrap_err().predicate,
        "functional_rate_visibility"
    );
    let f = fixture(true);
    let (before, _, _) = f.source_bundle(true, &f.before);
    let (after, signed, _) = f.source_bundle(false, &f.after);
    let (outer, pin) = outer(source(&after), source(&before), &bridge(&f.claim));
    assert_eq!(
        verify(&replace_source(&after, &outer), &signed, &pin)
            .unwrap_err()
            .predicate,
        "statement_diff_selection"
    );
}

#[test]
fn functional_comparison_rejects_cross_epoch_sources_native_downgrades_and_nested_pins() {
    let f = fixture(false);
    let (bytes, signed, pin) = f.bundle();
    let (before, _, _) = f.source_bundle(true, &f.before);
    let (after, _, after_pin) = f.source_bundle(false, &f.after);
    assert_eq!(
        verify(&bytes, &signed, &after_pin).unwrap_err().predicate,
        "recipient_certificate"
    );
    let mut downgraded = bytes.clone();
    let offset = 4 + REPORT_BUNDLE_FORMAT.len();
    downgraded[offset..offset + 2].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        verify(&downgraded, &signed, &pin).unwrap_err().predicate,
        "supported_report"
    );
    let mut old = source(&before).to_vec();
    let registry = certificate(&old).unwrap().registry_digest;
    let index = old.windows(32).position(|bytes| bytes == registry).unwrap();
    old[index] ^= 1;
    let end = old.len() - 32;
    let digest = hash_parts(FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT, &[&old[..end]]);
    old[end..].copy_from_slice(&digest);
    let (outer, pin) = outer(&old, source(&after), &bridge(&f.claim));
    assert_eq!(
        verify(&replace_source(&after, &outer), &signed, &pin)
            .unwrap_err()
            .predicate,
        "registry_closure"
    );
}
