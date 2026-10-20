//! Native FX routes preserve the identity of each monetary exposure and its
//! accumulated carrying adjustment across effective dates and retained history.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::chart::{
    FxRevaluationRoute, FxRevaluationRoutes, FxRevaluationRoutesRecorded,
    FxRevaluationRoutesRequest, SCHEMA_CHANGE_FX_REVALUATION_ROUTES, fx_revaluation_routes_at,
    set_fx_revaluation_routes,
};
use fa_journal::evidence::{Document, add_document};
use fa_journal::post::read_entry;
use fa_journal::refusal::{Outcome, code};
use fa_journal::rows::book_root;
use fa_journal::{
    AccountSpec, BalanceLimit, BookContext, BookSpec, Capability, LimitScope, PostRequest, Posted,
    Refusal, RevocationRequest, UnitPolicy, close_account, create_book, create_periods,
    install_chart, post, revoke_capability, transition_period,
};
use fa_model::symbols::{property, relation};
use fa_model::{
    AccountType, ControlPayload, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef,
    Id128, LegPayload, Oid, Pending, SealKey, SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

const PRINCIPAL: VId = VId(7);

fn day(month: u8, day: u8) -> DateDay {
    DateDay::from_ymd(2026, month, day).unwrap()
}

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

fn authority() -> Capability {
    cap(&["read", "schema_change"])
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    evidence: EvidenceRef,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([211; 32], DatabaseSecurityNamespaceId([212; 32]), [213; 32]),
            ))
            .unwrap();
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let book = BookContext {
            book_id: Id128([211; 16]),
            calendar: FiscalCalendar::monthly("fx-routes", 1, 1).unwrap(),
            units,
            seal_key: SealKey([214; 32]),
            symbols: SymbolTable::compiled(),
        };
        runtime
            .block_on(create_book(
                &mut db,
                &cx,
                &BookSpec {
                    book_id: book.book_id,
                    name: "Registered monetary exposure routes".into(),
                    base_unit: usd,
                    calendar: book.calendar.clone(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                &book.units,
                &book.symbols,
            ))
            .unwrap();
        let accounts: Vec<_> = [
            ("1000", AccountType::ASSET, UnitPolicy::Single(usd)),
            ("1200", AccountType::ASSET, UnitPolicy::Single(eur)),
            ("1210", AccountType::ASSET, UnitPolicy::Single(eur)),
            ("1220", AccountType::ASSET, UnitPolicy::Single(eur)),
            ("1230", AccountType::ASSET, UnitPolicy::AnyCurrency),
            ("1240", AccountType::EXPENSE, UnitPolicy::Single(eur)),
            ("1250", AccountType::ASSET, UnitPolicy::Single(eur)),
            ("1260", AccountType::ASSET, UnitPolicy::Single(usd)),
            ("1290", AccountType::ASSET, UnitPolicy::Single(usd)),
            ("1291", AccountType::ASSET, UnitPolicy::Single(usd)),
            ("2200", AccountType::LIABILITY, UnitPolicy::Single(eur)),
            ("2290", AccountType::LIABILITY, UnitPolicy::Single(usd)),
            ("3000", AccountType::EQUITY, UnitPolicy::Single(usd)),
            ("4000", AccountType::REVENUE, UnitPolicy::Single(usd)),
            ("4010", AccountType::REVENUE, UnitPolicy::Single(usd)),
            ("6000", AccountType::EXPENSE, UnitPolicy::Single(usd)),
        ]
        .into_iter()
        .map(|(code, kind, unit_policy)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance: u8::from(matches!(
                kind,
                AccountType::LIABILITY | AccountType::EQUITY | AccountType::REVENUE
            )),
            is_leaf: code != "1220",
            unit_policy,
            parent_code: None,
            limit: matches!(code, "1250" | "1260" | "4010").then_some(BalanceLimit {
                lower: Some(0),
                upper: None,
                scope: LimitScope::Lifetime,
            }),
        })
        .collect();
        let description = |value: &str| {
            Erasable::seal(
                &value.to_owned(),
                None,
                &book.seal_key,
                [215; 32],
                [216; 24],
            )
        };
        runtime
            .block_on(install_chart(
                &mut db,
                &cx,
                &book,
                &accounts,
                PRINCIPAL,
                day(1, 1),
                b"fx-routes-chart",
                description("Declared source and valuation accounts"),
                &cap(&["schema_change"]),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(create_periods(
                &mut db,
                &cx,
                &book,
                2026,
                PRINCIPAL,
                description("Calendar"),
                &cap(&["schema_change"]),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(transition_period(
                &mut db,
                &cx,
                &book,
                "FY2026-P01",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                b"open-january",
                description("Open January"),
                &cap(&["close"]),
                &[],
            ))
            .unwrap()
            .unwrap();
        let document = Document {
            book_id: book.book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Retained transaction evidence for valuation-account vacancy".to_vec(),
        };
        runtime
            .block_on(add_document(&mut db, &cx, &book, &document))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            db,
            book,
            usd,
            evidence: document.evidence_ref(1),
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn account(&self, code: &str) -> VId {
        account_vid(self.book.book_id, code)
    }

    fn seal(&self, text: &str) -> Erasable<String> {
        Erasable::seal(
            &text.to_owned(),
            None,
            &self.book.seal_key,
            [217; 32],
            [218; 24],
        )
    }

    fn routes(&self, rows: &[(&str, &str, &str)]) -> BTreeMap<VId, FxRevaluationRoute> {
        rows.iter()
            .map(|(source, valuation, unrealized)| {
                (
                    self.account(source),
                    FxRevaluationRoute {
                        valuation_account: self.account(valuation),
                        unrealized_account: self.account(unrealized),
                    },
                )
            })
            .collect()
    }

    fn request(
        &self,
        rows: &[(&str, &str, &str)],
        effective_from: DateDay,
        key: &[u8],
    ) -> FxRevaluationRoutesRequest {
        FxRevaluationRoutesRequest {
            principal: PRINCIPAL,
            effective_from,
            routes: self.routes(rows),
            idempotency_key: key.to_vec(),
            description: self.seal("Reviewed monetary exposure assignment"),
        }
    }

    fn set(
        &mut self,
        capability: &Capability,
        request: FxRevaluationRoutesRequest,
    ) -> Outcome<FxRevaluationRoutesRecorded> {
        let cx = self.cx();
        self.runtime.block_on(set_fx_revaluation_routes(
            &mut self.db,
            &cx,
            &self.book,
            capability,
            request,
        ))
    }

    fn selected(&self, date: DateDay, prefix: CommitSeq) -> Option<FxRevaluationRoutes> {
        fx_revaluation_routes_at(&self.db, &self.book, date, prefix).unwrap()
    }

    fn assert_refused(&mut self, request: FxRevaluationRoutesRequest) -> Refusal {
        let before = self.db.frontier().unwrap();
        let refusal = self.set(&authority(), request).unwrap().unwrap_err();
        assert_eq!(refusal.code, code::STRUCTURE, "{refusal}");
        assert_eq!(refusal.exit, 2, "{refusal}");
        assert_eq!(self.db.frontier().unwrap(), before);
        refusal
    }

    fn post_on_valuation(&mut self, key: &[u8], debit: bool, pending: bool) -> Posted {
        let legs = vec![
            LegPayload::simple(
                if debit { Side::Debit } else { Side::Credit },
                self.account("1290"),
                Amount::new(self.usd, 10_000),
            ),
            LegPayload::simple(
                if debit { Side::Credit } else { Side::Debit },
                self.account("3000"),
                Amount::new(self.usd, 10_000),
            ),
        ];
        let proposal = EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class: if pending {
                EntryClass::PENDING
            } else {
                EntryClass::ORIGINAL
            },
            effective_date: day(1, 5),
            document_date: None,
            description: self.seal("Earlier use of a potential valuation account"),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([219; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![self.evidence],
            supersession: Vec::new(),
            pending: pending.then_some(Pending {
                timeout_ns: None,
                resolution_of: None,
                disposition: None,
            }),
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let cx = self.cx();
        self.runtime
            .block_on(post(
                &mut self.db,
                &cx,
                &self.book,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap(&["post"]),
                },
            ))
            .unwrap()
            .unwrap()
    }
}

#[test]
fn additive_asset_and_liability_routes_keep_effective_dates_and_recorded_prefixes() {
    let mut h = Harness::new();
    let before = h.db.frontier().unwrap();
    assert!(h.selected(day(3, 31), before).is_none());
    let first_request = h.request(&[("1200", "1290", "4000")], day(1, 1), b"first-map");
    let first = h.set(&authority(), first_request.clone()).unwrap().unwrap();
    assert!(!first.already_recorded);
    let first_map = h.selected(day(3, 31), first.recorded_at).unwrap();
    assert_eq!(first_map.base_unit, h.usd);
    assert_eq!(first_map.routes, first_request.routes);
    assert_eq!(first_map.digest, first.digest);
    assert_eq!(first_map.control_entry, first.control_entry);
    let (entry, recorded_at) = read_entry(&h.db, first.control_entry).unwrap().unwrap();
    assert_eq!(recorded_at, first.recorded_at);
    assert_eq!(entry.proposal.class, EntryClass::SCHEMA_CONTROL);
    assert!(entry.proposal.legs.is_empty());
    assert!(entry.proposal.effective_period.is_none());
    assert!(matches!(
        entry.proposal.control,
        Some(ControlPayload::SchemaChange {
            kind: SCHEMA_CHANGE_FX_REVALUATION_ROUTES,
            ..
        })
    ));

    let expanded_request = h.request(
        &[("1200", "1290", "4000"), ("2200", "2290", "6000")],
        day(3, 1),
        b"expanded-map",
    );
    let expanded = h
        .set(&authority(), expanded_request.clone())
        .unwrap()
        .unwrap();
    let head = h.db.frontier().unwrap();
    assert_eq!(h.selected(day(2, 28), head), Some(first_map.clone()));
    assert_eq!(h.selected(day(3, 31), first.recorded_at), Some(first_map));
    let selected = h.selected(day(3, 31), head).unwrap();
    assert_eq!(selected.routes, expanded_request.routes);
    assert_eq!(selected.recorded_at, expanded.recorded_at);
    assert_ne!(selected.digest, first.digest);
    assert!(
        h.selected(DateDay::from_ymd(2025, 12, 31).unwrap(), head)
            .is_none()
    );
    assert!(h.selected(day(3, 31), before).is_none());
    assert_eq!(
        h.db.frontier().unwrap(),
        head,
        "selection publishes nothing"
    );

    // The original map is no longer a complete new assignment, but its exact
    // immutable retry must return the original publication without reapplying it.
    let retried = h.set(&authority(), first_request).unwrap().unwrap();
    assert!(retried.already_recorded);
    assert_eq!(retried.control_entry, first.control_entry);
    assert_eq!(retried.recorded_at, first.recorded_at);
    assert_eq!(retried.digest, first.digest);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.selected(day(3, 31), head).unwrap(), selected);
}

#[test]
fn invalid_source_and_destination_maps_never_publish() {
    let mut h = Harness::new();
    let cases = [
        ("empty", vec![]),
        ("base-source", vec![("1000", "1290", "4000")]),
        ("any-currency-source", vec![("1230", "1290", "4000")]),
        ("expense-source", vec![("1240", "1290", "4000")]),
        ("summary-source", vec![("1220", "1290", "4000")]),
        ("limited-source", vec![("1250", "1290", "4000")]),
        ("undeclared-source", vec![("9999", "1290", "4000")]),
        ("foreign-valuation", vec![("1200", "1210", "4000")]),
        ("different-valuation-type", vec![("1200", "2290", "4000")]),
        ("limited-valuation", vec![("1200", "1260", "4000")]),
        ("equity-unrealized", vec![("1200", "1290", "3000")]),
        ("foreign-unrealized", vec![("1200", "1290", "1240")]),
        ("limited-unrealized", vec![("1200", "1290", "4010")]),
        ("same-destinations", vec![("1200", "1290", "1290")]),
        (
            "shared-valuation",
            vec![("1200", "1290", "4000"), ("1210", "1290", "4000")],
        ),
    ];
    for (name, rows) in cases {
        let request = h.request(&rows, day(1, 1), name.as_bytes());
        h.assert_refused(request);
    }
    assert!(h.selected(day(1, 31), h.db.frontier().unwrap()).is_none());
    let valid = h.request(
        &[("1200", "1290", "4000")],
        day(1, 1),
        b"valid-after-refusals",
    );
    h.set(&authority(), valid).unwrap().unwrap();
}

#[test]
fn established_routes_cannot_be_removed_reassigned_or_changed_by_reusing_a_key() {
    let mut h = Harness::new();
    let original = h.request(
        &[("1200", "1290", "4000"), ("2200", "2290", "6000")],
        day(3, 1),
        b"immutable-map",
    );
    let recorded = h.set(&authority(), original.clone()).unwrap().unwrap();
    let selected = h.selected(day(3, 31), recorded.recorded_at).unwrap();
    for (key, rows) in [
        ("remove-source", vec![("1200", "1290", "4000")]),
        (
            "move-valuation",
            vec![("1200", "1291", "4000"), ("2200", "2290", "6000")],
        ),
        (
            "move-unrealized",
            vec![("1200", "1290", "6000"), ("2200", "2290", "6000")],
        ),
    ] {
        // Backdating a new declaration cannot erase an established assignment.
        let request = h.request(&rows, day(1, 1), key.as_bytes());
        let refusal = h.assert_refused(request);
        assert!(refusal.message.contains("cannot remove or reassign"));
    }
    let mut changed = original;
    changed.effective_from = day(2, 1);
    let before = h.db.frontier().unwrap();
    let refusal = h.set(&authority(), changed).unwrap().unwrap_err();
    assert_eq!(refusal.code, code::IDEMPOTENCY_CONFLICT);
    assert_eq!(refusal.exit, 6);
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.selected(day(3, 31), before), Some(selected));
}

#[test]
fn new_valuation_accounts_require_no_prior_posted_net_zero_or_pending_history() {
    for mode in ["posted", "net-zero", "pending"] {
        let mut h = Harness::new();
        let first = h.post_on_valuation(b"earlier-usage", true, mode == "pending");
        let (stored, _) = read_entry(&h.db, first.entry_ref().vid).unwrap().unwrap();
        assert_eq!(stored.proposal.legs[0].account_ref, h.account("1290"));
        assert_eq!(stored.proposal.legs[0].amount.mantissa, 10_000);
        if mode == "net-zero" {
            let offset = h.post_on_valuation(b"offset-earlier-usage", false, false);
            let (offset, _) = read_entry(&h.db, offset.entry_ref().vid).unwrap().unwrap();
            assert_eq!(stored.proposal.legs[0].side, Side::Debit);
            assert_eq!(offset.proposal.legs[0].side, Side::Credit);
            assert_eq!(
                stored.proposal.legs[0].amount,
                offset.proposal.legs[0].amount
            );
        } else if mode == "pending" {
            assert_eq!(stored.proposal.class, EntryClass::PENDING);
            assert!(stored.proposal.pending.is_some());
        }
        let request = h.request(
            &[("1200", "1290", "4000")],
            day(1, 1),
            b"occupied-valuation",
        );
        let refusal = h.assert_refused(request);
        assert!(
            refusal.message.contains("already has posting history"),
            "{mode}: {refusal}"
        );
        let unused = h.request(&[("1200", "1291", "4000")], day(1, 1), b"unused-valuation");
        h.set(&authority(), unused).unwrap().unwrap();
    }
}

#[test]
fn account_effectivity_is_checked_at_the_declared_route_date() {
    let mut h = Harness::new();
    let cx = h.cx();
    let description = h.seal("Retire an unused valuation account");
    h.runtime
        .block_on(close_account(
            &mut h.db,
            &cx,
            &h.book,
            "1290",
            day(3, 1),
            PRINCIPAL,
            day(3, 1),
            b"retire-valuation",
            description,
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    let ineffective = h.request(&[("1200", "1290", "4000")], day(3, 1), b"inactive-route");
    h.assert_refused(ineffective);
    let historical = h.request(&[("1200", "1290", "4000")], day(2, 1), b"earlier-route");
    let recorded = h.set(&authority(), historical).unwrap().unwrap();
    assert_eq!(
        h.selected(day(2, 28), recorded.recorded_at)
            .unwrap()
            .effective_from,
        day(2, 1)
    );
}

#[test]
fn route_changes_and_exact_retries_require_current_whole_book_authority() {
    let mut h = Harness::new();
    let request = h.request(&[("1200", "1290", "4000")], day(1, 1), b"authorized-routes");
    h.set(&authority(), request.clone()).unwrap().unwrap();
    let before = h.db.frontier().unwrap();
    for denied in [
        cap(&["read"]),
        cap(&["schema_change"]),
        authority().for_accounts(&["1200", "1290", "4000"]).unwrap(),
        authority().for_books(&[Id128([99; 16])]).unwrap(),
        authority().known_at_most(before),
        authority().expiring_at(before),
        Capability::embedded(VId(99), &["read", "schema_change"]).unwrap(),
    ] {
        let refusal = h.set(&denied, request.clone()).unwrap().unwrap_err();
        assert_eq!(refusal.exit, 7, "{refusal}");
        assert_eq!(h.db.frontier().unwrap(), before);
    }
    let cx = h.cx();
    let revocation = RevocationRequest {
        capability: cap(&["issue_capability"]),
        revoked: authority().commitment().unwrap(),
        effective_date: day(1, 5),
        idempotency_key: b"revoke-route-authority".to_vec(),
        description: h.seal("Withdraw route configuration authority"),
    };
    h.runtime
        .block_on(revoke_capability(&mut h.db, &cx, &h.book, revocation))
        .unwrap()
        .unwrap();
    let revoked_at = h.db.frontier().unwrap();
    let refusal = h.set(&authority(), request).unwrap().unwrap_err();
    assert_eq!(refusal.code, "FA-REF-023");
    assert_eq!(h.db.frontier().unwrap(), revoked_at);
}

#[test]
fn denied_route_authority_does_not_decode_corrupt_book_contents() {
    let mut h = Harness::new();
    let request = h.request(
        &[("1200", "1290", "4000")],
        day(1, 1),
        b"denied-source-read",
    );
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        book_root(),
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(vec![255]).unwrap()),
    );
    let cx = h.cx();
    h.runtime
        .block_on(h.db.write(&cx.commit(), damage))
        .unwrap();
    let before = h.db.frontier().unwrap();
    let denied = cap(&["schema_change"]);
    let refusal = h.set(&denied, request.clone()).unwrap().unwrap_err();
    assert_eq!(refusal.exit, 7);
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(
        h.set(&authority(), request).is_err(),
        "authorized access reaches the damaged source"
    );
    assert_eq!(h.db.frontier().unwrap(), before);
}
