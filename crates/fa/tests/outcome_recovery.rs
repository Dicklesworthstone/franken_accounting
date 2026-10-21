//! Recovery's prepared authority and exact source basis through the public facade.

use fa::{Book, BookKeys, Entropy};
use fa_journal::BookSpec;
use fa_model::Id128;
use fa_policy::{Capability, Op, Profile};
use fa_time::{DateDay, FiscalCalendar};
use fgdb_types::{CommitSeq, VId};

const PRINCIPAL: VId = VId(198);

fn book(id: u8) -> Book {
    Book::create_memory(
        BookKeys::for_development(id),
        BookSpec {
            book_id: Id128([id; 16]),
            name: "Outcome recovery facade".into(),
            base_unit: fa_money::UnitRegistry::embedded()
                .unwrap()
                .lookup("USD")
                .unwrap(),
            calendar: FiscalCalendar::monthly("fiscal", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(u64::from(id)),
    )
    .unwrap()
}

fn authority() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap()
}

#[test]
fn covered_recovery_still_requires_complete_current_authority() {
    let mut book = book(198);
    let head = book.head().unwrap();
    // An Agent can never hold the recovery authority: the capability itself
    // is refused before any book is asked.
    assert!(
        Capability::new(
            PRINCIPAL,
            Profile::Agent,
            &[Op::Read, Op::SchemaChange],
            PRINCIPAL,
        )
        .is_err()
    );
    for denied in [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        authority().expiring_at(head),
        authority().known_at_most(head),
        authority().for_accounts(&["1000"]).unwrap(),
        authority().for_periods(&["FY2026-P03"]).unwrap(),
        authority().for_books(&[Id128([199; 16])]).unwrap(),
    ] {
        assert!(
            book.prepare_outcome_rebuild(denied).unwrap().is_err(),
            "a no-op does not waive recovery authority"
        );
        assert_eq!(book.head().unwrap(), head);
    }
    let prepared = book.prepare_outcome_rebuild(authority()).unwrap().unwrap();
    assert!(prepared.preview().already_covered);
    assert_eq!(prepared.preview().basis, head);
    prepared.abort();
    assert_eq!(book.head().unwrap(), head);
    let rebuilt = book.rebuild_outcomes(authority()).unwrap().unwrap();
    assert!(!rebuilt.wrote);
    assert_eq!(rebuilt.basis, head);
    assert_eq!(rebuilt.outcomes_created, 0);
    assert_eq!(book.head().unwrap(), head);
}

#[test]
fn prepared_recovery_cannot_cross_books_or_outlive_its_authority() {
    let mut source = book(198);
    let mut other = book(199);
    let other_head = other.head().unwrap();
    let prepared = source
        .prepare_outcome_rebuild(authority())
        .unwrap()
        .unwrap();
    let refusal = other
        .publish_outcome_rebuild(prepared)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-034");
    assert_eq!(other.head().unwrap(), other_head);

    let original = authority().expiring_at(CommitSeq(u64::MAX));
    let prepared = source
        .prepare_outcome_rebuild(original.clone())
        .unwrap()
        .unwrap();
    source
        .revoke_capability(
            Capability::embedded(PRINCIPAL, &["issue_capability"]).unwrap(),
            original.commitment().unwrap(),
            DateDay::from_ymd(2026, 3, 20).unwrap(),
            b"revoke-outcome-recovery",
            "Revoke the prepared recovery's capability",
        )
        .unwrap()
        .unwrap();
    let revoked_at = source.head().unwrap();
    let refusal = source
        .publish_outcome_rebuild(prepared)
        .unwrap()
        .unwrap_err();
    assert!(refusal.message.contains("revoked"), "{refusal:?}");
    assert_eq!(source.head().unwrap(), revoked_at);
    assert!(source.prepare_outcome_rebuild(original).unwrap().is_err());
    assert_eq!(source.head().unwrap(), revoked_at);
}
