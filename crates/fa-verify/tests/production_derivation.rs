//! Regression tests for independent scope derivation (fa-n6fh).
#[path = "support/production.rs"]
mod fixture;

use fa_verify::envelope::RecordError;
use fa_verify::proof::{PREFIX_FORMAT, VerifyError, verify_prefix};
use fa_verify::proof::production::{ProductionError, ProductionScope, verify_production_for};
use fa_verify::proof::production::derivation::verify_prefix_with_records;
use fixture::{Fixture, Wire, borrowed, record};

fn legacy(f: &Fixture) -> Vec<u8> {
    let mut w = Wire::default();
    w.bytes(PREFIX_FORMAT).fixed(&f.checkpoint.encode()).u32(f.records.len() as u32);
    for r in &f.records { w.bytes(&r.envelope.encode()); }
    w.0
}

fn all(f: &Fixture) -> ProductionScope {
    ProductionScope { first_seq: 0, known_at: f.checkpoint.through_seq,
        account: None, effective_days: None }
}

#[test]
fn inconsistent_selectors_cannot_establish_an_empty_extract() {
    for day in 100..108 {
        let valid = Fixture::new(vec![record(1, 0, 1, day, Some(10))], 1);
        let scope = ProductionScope { account: Some(10),
            effective_days: Some((day, day)), ..all(&valid) };
        let selected = valid.inclusions(&[0]);
        assert_eq!(verify_production_for(&valid.prefix(), &borrowed(&selected),
            &valid.checkpoint, &scope).unwrap().entries.len(), 1);
        for field in 0..4 {
            let mut r = record(1, 0, 1, day, Some(10));
            match field {
                0 => r.envelope.account_vids = vec![11],
                1 => r.envelope.effective_day = Some(day + 1),
                2 => { r.envelope.class = 19; r.envelope.effective_day = None; }
                _ => r.envelope.effective_day = None,
            }
            // The root commits the inconsistent envelope, so rejecting only
            // stale roots would not detect this regression. No real book is used.
            let invalid = Fixture::new(vec![r], 1);
            let old = legacy(&invalid);
            assert!(verify_prefix(&old, &invalid.checkpoint).is_ok());
            assert_eq!(verify_production_for(&old, &[], &invalid.checkpoint, &scope),
                Err(ProductionError::ScopeDerivationRequired { index: 0 }));
            assert_eq!(verify_production_for(&invalid.prefix(), &[], &invalid.checkpoint, &scope),
                Err(ProductionError::Prefix(VerifyError::Record(RecordError::Envelope))));
        }
    }
}

#[test]
fn legacy_complete_sets_remain_valid_without_claiming_unproven_exclusions() {
    for f in [Fixture::new(Vec::new(), 0), Fixture::mixed()] {
        let indexes: Vec<_> = (0..f.records.len()).collect();
        let records = f.inclusions(&indexes);
        let old = legacy(&f);
        assert_eq!(verify_production_for(&old, &borrowed(&records), &f.checkpoint,
            &all(&f)).unwrap().entries.len(), f.records.len());
        assert!(verify_prefix_with_records(&old, &f.checkpoint).is_err());
        let empty = ProductionScope { account: Some(999), ..all(&f) };
        assert!(verify_production_for(&f.prefix(), &[], &f.checkpoint, &empty)
            .unwrap().entries.is_empty());
        if !f.records.is_empty() {
            assert!(matches!(verify_production_for(&old, &[], &f.checkpoint, &empty),
                Err(ProductionError::ScopeDerivationRequired { .. })));
        }
    }
}
