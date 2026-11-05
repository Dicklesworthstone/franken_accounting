use super::*;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_model::symbols::relation;
use fa_model::{EntryRef, Erasable, PeriodRef, SealKey, SymbolTable, account_vid, entry_vid};
use fa_money::{RoundingLaw, UnitRegistry};
use fa_time::{FiscalCalendar, PeriodTransition};
use fgdb::{DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::CanonicalScalar;
use fgdb_types::ids::DatabaseSecurityNamespaceId;

const PRINCIPAL: VId = VId(7);

fn day(value: u8) -> DateDay {
    DateDay::from_ymd(2026, 3, value).unwrap()
}

struct Fixture {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    eur: UnitId,
    source: VId,
    valuation: VId,
    source_entry: EntryRef,
    next_key: usize,
}

impl Fixture {
    fn new(unrelated: usize) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([51; 32], DatabaseSecurityNamespaceId([52; 32]), [53; 32]),
            ))
            .unwrap();
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let book = BookContext {
            book_id: Id128([54; 16]),
            calendar: FiscalCalendar::monthly("history-audit", 1, 1).unwrap(),
            units: units.clone(),
            seal_key: SealKey([55; 32]),
            symbols: SymbolTable::compiled(),
        };
        let spec = BookSpec {
            book_id: book.book_id,
            name: "Historical revaluation audit".into(),
            base_unit: usd,
            calendar: book.calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        runtime
            .block_on(crate::create_book(
                &mut db,
                &cx,
                &spec,
                &units,
                &book.symbols,
            ))
            .unwrap();
        let description = Erasable::seal(
            &"history fixture".to_string(),
            None,
            &book.seal_key,
            [56; 32],
            [57; 24],
        );
        let accounts = [
            ("1200", AccountType::ASSET, eur),
            ("4000", AccountType::REVENUE, eur),
            ("1290", AccountType::ASSET, usd),
            ("7090", AccountType::REVENUE, usd),
            ("1000", AccountType::ASSET, usd),
            ("6000", AccountType::EXPENSE, usd),
        ]
        .into_iter()
        .map(|(code, kind, unit)| crate::AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance: u8::from(kind == AccountType::REVENUE),
            is_leaf: true,
            unit_policy: UnitPolicy::Single(unit),
            parent_code: None,
            limit: None,
        })
        .collect::<Vec<_>>();
        runtime
            .block_on(crate::install_chart(
                &mut db,
                &cx,
                &book,
                &accounts,
                PRINCIPAL,
                day(1),
                b"chart",
                description.clone(),
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(crate::create_periods(
                &mut db,
                &cx,
                &book,
                2026,
                PRINCIPAL,
                description.clone(),
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(crate::transition_period(
                &mut db,
                &cx,
                &book,
                "FY2026-P03",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                b"open",
                description.clone(),
                &Capability::embedded(PRINCIPAL, &["close", "post"]).unwrap(),
                &[],
            ))
            .unwrap()
            .unwrap();
        let source = account_vid(book.book_id, "1200");
        let valuation = account_vid(book.book_id, "1290");
        runtime
            .block_on(crate::chart::set_fx_revaluation_routes(
                &mut db,
                &cx,
                &book,
                &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
                crate::chart::FxRevaluationRoutesRequest {
                    principal: PRINCIPAL,
                    effective_from: day(1),
                    routes: [(
                        source,
                        FxRevaluationRoute {
                            valuation_account: valuation,
                            unrealized_account: account_vid(book.book_id, "7090"),
                        },
                    )]
                    .into(),
                    idempotency_key: b"routes".to_vec(),
                    description,
                },
            ))
            .unwrap()
            .unwrap();
        let mut fixture = Self {
            runtime,
            root,
            db,
            book,
            usd,
            eur,
            source,
            valuation,
            source_entry: EntryRef {
                vid: VId(0),
                entry_digest: [0; 32],
            },
            next_key: 0,
        };
        let rate = fixture.rate(10, 3, FxRatePurpose::SpotClose, day(15));
        let proposal = fixture.proposal(
            vec![
                LegPayload::simple(Side::Debit, source, Amount::new(eur, 3)),
                LegPayload::simple(
                    Side::Credit,
                    account_vid(fixture.book.book_id, "4000"),
                    Amount::new(eur, 3),
                ),
            ],
            EntryClass::ORIGINAL,
        );
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        let proposal = crate::fx::value_proposal(
            &mut budget,
            proposal,
            &spec,
            &units,
            FxLawId::SpotClose,
            &[rate],
        )
        .unwrap();
        fixture.source_entry = fixture.append(proposal);
        fixture.unrelated(unrelated);
        fixture
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn write(&mut self, batch: WriteBatch) -> CommitSeq {
        let cx = self.cx();
        self.runtime
            .block_on(self.db.write(&cx.commit(), batch))
            .unwrap()
    }

    fn proposal(&mut self, legs: Vec<LegPayload>, class: EntryClass) -> EntryPayload {
        self.next_key += 1;
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class,
            effective_date: day(15),
            document_date: None,
            description: Erasable::seal(
                &"retained audit fixture".to_string(),
                None,
                &self.book.seal_key,
                [58; 32],
                [59; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: self.next_key.to_le_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([60; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    // Canonical native fixture births bypass posting deliberately: this suite
    // exercises historical readers and forged retained records, not writer
    // admission. Production genesis/chart/period/rate APIs supply metadata.
    fn append(&mut self, proposal: EntryPayload) -> EntryRef {
        let vid = entry_vid(
            self.book.book_id,
            &PRINCIPAL.0.to_le_bytes(),
            &proposal.idempotency_key,
        );
        let entry = proposal.seal(Vec::new(), None).unwrap();
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.create_vertex(
            vid,
            vec![label::ENTRY],
            fa_model::entry_mirrors(&entry).unwrap(),
        );
        self.write(batch);
        entry.entry_ref(vid)
    }

    fn unrelated(&mut self, count: usize) {
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        for _ in 0..count {
            let proposal = self.proposal(
                vec![
                    LegPayload::simple(
                        Side::Debit,
                        account_vid(self.book.book_id, "6000"),
                        Amount::new(self.usd, 1),
                    ),
                    LegPayload::simple(
                        Side::Credit,
                        account_vid(self.book.book_id, "1000"),
                        Amount::new(self.usd, 1),
                    ),
                ],
                EntryClass::ORIGINAL,
            );
            let vid = entry_vid(
                self.book.book_id,
                &PRINCIPAL.0.to_le_bytes(),
                &proposal.idempotency_key,
            );
            let entry = proposal.seal(Vec::new(), None).unwrap();
            batch.create_vertex(
                vid,
                vec![label::ENTRY],
                fa_model::entry_mirrors(&entry).unwrap(),
            );
        }
        if count != 0 {
            self.write(batch);
        }
    }

    fn rate(
        &mut self,
        numerator: u128,
        denominator: u128,
        purpose: FxRatePurpose,
        date: DateDay,
    ) -> FxRateDocument {
        let rate = FxRateDocument::new(
            crate::fx::FxRateTerms {
                base_unit: self.usd,
                quote_unit: self.eur,
                rate_num: numerator,
                rate_den: denominator,
                rounding: RoundingLaw::HalfEven,
            },
            date,
            1_700_000_000_000_000_100,
            purpose,
            "historical audit quote",
        )
        .unwrap();
        let doc = rate.document(self.book.book_id, PRINCIPAL, 3).unwrap();
        let cx = self.cx();
        self.runtime
            .block_on(crate::evidence::add_document(
                &mut self.db,
                &cx,
                &self.book,
                &doc,
            ))
            .unwrap()
            .unwrap();
        rate
    }

    fn request(&mut self, numerator: u128, allocated: bool) -> FxRevaluationRequest {
        let rate = self.rate(numerator, 3, FxRatePurpose::PeriodClose, day(31));
        FxRevaluationRequest {
            period: "FY2026-P03".into(),
            source_account: self.source,
            rate_document: rate.evidence_ref(self.book.book_id).unwrap().document_oid,
            entity: None,
            item_allocation: allocated,
        }
    }

    fn observe(
        &self,
        request: &FxRevaluationRequest,
        at: CommitSeq,
        history: Option<&AuthenticatedHistory>,
    ) -> Outcome<PreparedFxRevaluation> {
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        // These private synchronous observers run beneath a query caller in
        // production. Install that same purpose-bound context for their
        // carrying arithmetic rather than calling them from an ambient-free
        // unit-test thread.
        self.cx().query().with_restriction(|| match history {
            Some(history) => super::super::observe_using(
                &self.db,
                &self.cx(),
                &self.book,
                request,
                at,
                &mut budget,
                Some(history),
            )
            .map(|result| result.map(|observed| observed.prepared)),
            None => {
                super::super::observe(&self.db, &self.cx(), &self.book, request, at, &mut budget)
            }
        })
    }

    fn history(&self) -> AuthenticatedHistory {
        let proof = verify_prefix(
            &self.db,
            &self.cx(),
            &self.book,
            self.db.frontier().unwrap(),
        )
        .unwrap();
        AuthenticatedHistory::read_verified(&self.db, &self.cx(), &self.book, proof).unwrap()
    }
}

fn semantic(
    result: Outcome<PreparedFxRevaluation>,
) -> Result<Result<PreparedFxRevaluation, Refusal>, String> {
    result.map_err(|error| error.to_string()).map(|result| {
        result.map(|mut prepared| {
            prepared.population_work = crate::carrying::CarryingPopulationWork::default();
            prepared.history_work = RevaluationHistoryWork::default();
            prepared
        })
    })
}

#[test]
fn first_revaluation_skips_shared_history_construction_and_matches_the_literal_observer() {
    for allocated in [false, true] {
        for unrelated in [8, 128] {
            let mut f = Fixture::new(unrelated);
            let request = f.request(13, allocated);
            let at = f.db.frontier().unwrap();
            let literal = f.observe(&request, at, None).unwrap().unwrap();
            let stripped = Cx::detached_cancel_context();
            let mut budget =
                ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
            let verified = f
                .cx()
                .query()
                .with_restriction(|| {
                    super::super::observe_verified(
                        &f.db,
                        &f.cx(),
                        &f.book,
                        &request,
                        at,
                        &mut budget,
                    )
                })
                .unwrap()
                .unwrap();
            assert_eq!(
                verified, literal,
                "allocated={allocated}, unrelated={unrelated}"
            );
            assert_eq!(verified.history_work(), RevaluationHistoryWork::default());
            // The original allocated-population observation is still
            // required; only the redundant historical-audit index is absent.
            assert_eq!(
                verified.population_work().history_scans,
                usize::from(allocated)
            );
            assert_eq!(verified.target_base_net().mantissa, 13);
            assert_eq!(verified.delta().mantissa, 3);
        }
    }
}

#[test]
fn shared_history_matches_literal_observations_at_distinct_original_and_publication_prefixes() {
    for allocated in [false, true] {
        for (unrelated, publications) in [(16, 3), (128, 8)] {
            let mut f = Fixture::new(unrelated);
            let mut observations = Vec::new();
            let mut latest = None;
            for ordinal in 0..publications {
                let request = f.request(13 + ordinal as u128 * 3, allocated);
                let observed_at = f.db.frontier().unwrap();
                let prepared = f.observe(&request, observed_at, None).unwrap().unwrap();
                assert_eq!(
                    prepared.target_base_net().mantissa,
                    13 + ordinal as i128 * 3
                );
                let mut template = f.proposal(Vec::new(), EntryClass::REVALUATION);
                template.effective_date = day(31);
                template.effective_period = Some(PeriodRef {
                    calendar: f.book.calendar.id.clone(),
                    code: request.period.clone(),
                });
                let proposal = prepared.proposal(template).unwrap();
                // Deliberately distinct prefixes: this is not just reuse of
                // the two equal cutoffs of an immediate publication.
                f.unrelated(1);
                let before_publication = f.db.frontier().unwrap();
                assert_ne!(observed_at, before_publication);
                observations.push((request.clone(), observed_at, before_publication));
                f.append(proposal);
                latest = Some(request);
            }
            let history = f.history();
            let mut guard_entries = 0;
            for (request, observed_at, before) in &observations {
                for at in [*observed_at, *before] {
                    if allocated {
                        guard_entries +=
                            f.db.vertices_at(at)
                                .unwrap()
                                .iter()
                                .filter(|row| row.labels.contains(&label::ENTRY))
                                .count();
                    }
                    assert_eq!(
                        semantic(f.observe(request, at, Some(&history))),
                        semantic(f.observe(request, at, None)),
                        "allocated={allocated}, prefix={at:?}"
                    );
                }
            }
            let work = history.work();
            let entries =
                f.db.vertices_at(f.db.frontier().unwrap())
                    .unwrap()
                    .iter()
                    .filter(|row| row.labels.contains(&label::ENTRY))
                    .count();
            assert_eq!(work.shared_history_scans, 1);
            assert_eq!(work.shared_entries_decoded, entries);
            assert_eq!(work.shared_applications_indexed, 0);
            assert_eq!(work.historical_observations, publications * 2);
            assert_eq!(work.entry_history_proofs_reused, publications * 2);
            assert_eq!(
                work.source_entry_candidates,
                publications * (publications + 1)
            );
            assert_eq!(
                work.source_contributions_hashed,
                publications * (publications + 1)
            );
            assert_eq!(work.historical_route_reads, publications * 2);
            assert!(work.historical_route_reuses >= publications * (publications - 1));
            assert_eq!(work.historical_carrying.history_scans, 0);
            assert_eq!(work.historical_carrying.entries_decoded, 0);
            assert_eq!(work.historical_carrying.applications_indexed, 0);
            assert_eq!(work.historical_carrying.source_guard_entries, guard_entries);
            assert_eq!(
                work.historical_carrying.item_effect_entries,
                if allocated {
                    publications * (publications - 1)
                } else {
                    0
                }
            );
            // The complete production audit must reproduce those same
            // independently retained observations and expose honest counters.
            let stripped = Cx::detached_cancel_context();
            let mut budget =
                ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
            let verified = f
                .cx()
                .query()
                .with_restriction(|| {
                    super::super::observe_verified(
                        &f.db,
                        &f.cx(),
                        &f.book,
                        &latest.unwrap(),
                        f.db.frontier().unwrap(),
                        &mut budget,
                    )
                })
                .unwrap()
                .unwrap();
            assert_eq!(verified.history_work(), work);
        }
    }
}

#[test]
fn historical_period_damage_is_not_hidden_by_a_restored_head_projection() {
    let mut f = Fixture::new(8);
    let request = f.request(13, true);
    let intact = f.db.frontier().unwrap();
    let pvid = period_vid(&f.book.calendar.id, &request.period);
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        pvid,
        property::STATE,
        Some(CanonicalScalar::Int(i64::from(PeriodState::Closed.tag()))),
    );
    let damaged = f.write(damage);
    let mut restore = WriteBatch::new(relation::IN_BOOK);
    restore.set_vertex_property(
        pvid,
        property::STATE,
        Some(CanonicalScalar::Int(i64::from(PeriodState::Open.tag()))),
    );
    let restored = f.write(restore);
    assert!(f.observe(&request, restored, None).unwrap().is_ok());
    let history = f.history();
    for at in [intact, damaged, restored] {
        let literal = semantic(f.observe(&request, at, None));
        let indexed = semantic(f.observe(&request, at, Some(&history)));
        assert_eq!(indexed, literal);
        assert_eq!(indexed.is_err(), at == damaged);
    }
}

#[test]
fn rewriting_and_restoring_an_entry_cannot_issue_a_reusable_history_proof() {
    let mut f = Fixture::new(8);
    let request = f.request(13, true);
    let intact = f.db.frontier().unwrap();
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        f.source_entry.vid,
        property::FA_DIGEST,
        Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
    );
    f.write(damage);
    let mut restore = WriteBatch::new(relation::IN_BOOK);
    restore.set_vertex_property(
        f.source_entry.vid,
        property::FA_DIGEST,
        Some(CanonicalScalar::bytes(f.source_entry.entry_digest.to_vec()).unwrap()),
    );
    let restored = f.write(restore);
    assert!(f.observe(&request, intact, None).unwrap().is_ok());
    assert!(verify_prefix(&f.db, &f.cx(), &f.book, restored).is_err());
    let error = f.observe(&request, restored, None).unwrap_err();
    assert!(error.to_string().contains("modified"), "{error}");
}

#[test]
fn unrelated_reversals_remain_validated_and_later_duplicates_do_not_poison_earlier_views() {
    let mut f = Fixture::new(8);
    let request = f.request(13, true);
    let original = f.proposal(
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(f.book.book_id, "6000"),
                Amount::new(f.usd, 2),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(f.book.book_id, "1000"),
                Amount::new(f.usd, 2),
            ),
        ],
        EntryClass::ORIGINAL,
    );
    let target = f.append(original.clone());
    let before = f.db.frontier().unwrap();
    let reversed_legs: Vec<_> = original
        .legs
        .iter()
        .cloned()
        .map(|mut leg| {
            leg.side = leg.side.flipped();
            leg
        })
        .collect();
    let mut reversal = f.proposal(reversed_legs.clone(), EntryClass::REVERSAL);
    reversal.supersession = vec![fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    let undo = f.append(reversal.clone());
    let reversed = f.db.frontier().unwrap();
    let mut duplicate = f.proposal(reversed_legs, EntryClass::REVERSAL);
    duplicate.supersession = reversal.supersession;
    f.append(duplicate);
    let duplicated = f.db.frontier().unwrap();
    // Native Entry immutability still holds; the semantic reversal law must
    // refuse only the prefixes containing the second successor.
    let history = f.history();
    for at in [before, reversed, duplicated] {
        let literal = semantic(f.observe(&request, at, None));
        let indexed = semantic(f.observe(&request, at, Some(&history)));
        assert_eq!(indexed, literal);
        if at == duplicated {
            let refusal = indexed.unwrap().unwrap_err();
            assert!(refusal.message.contains("invalid exact reversal"));
        } else {
            assert!(indexed.unwrap().is_ok());
        }
    }
    let spec = crate::fx::book_spec_at(&f.db, &f.book, before).unwrap();
    let early = crate::carrying::CarryingHistory::from_index(
        spec.clone(),
        Rc::clone(history.index()),
        before,
        false,
    )
    .unwrap();
    assert!(early.original(undo.vid).is_none());
    assert!(early.is_live(&f.cx(), target.vid).unwrap());
    let once = crate::carrying::CarryingHistory::from_index(
        spec.clone(),
        Rc::clone(history.index()),
        reversed,
        false,
    )
    .unwrap();
    assert!(!once.is_live(&f.cx(), target.vid).unwrap());
    assert!(
        crate::carrying::CarryingHistory::from_index(
            spec,
            Rc::clone(history.index()),
            duplicated,
            false
        )
        .is_err()
    );
}

#[test]
fn cached_routes_are_pinned_to_both_date_and_recorded_prefix() {
    let mut f = Fixture::new(4);
    let old = f.db.frontier().unwrap();
    let cx = f.cx();
    let april = DateDay::from_ymd(2026, 4, 1).unwrap();
    f.runtime
        .block_on(crate::chart::set_fx_revaluation_routes(
            &mut f.db,
            &cx,
            &f.book,
            &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
            crate::chart::FxRevaluationRoutesRequest {
                principal: PRINCIPAL,
                effective_from: april,
                routes: [(
                    f.source,
                    FxRevaluationRoute {
                        valuation_account: f.valuation,
                        unrealized_account: account_vid(f.book.book_id, "7090"),
                    },
                )]
                .into(),
                idempotency_key: b"april-routes".to_vec(),
                description: Erasable::seal(
                    &"April routes".to_string(),
                    None,
                    &f.book.seal_key,
                    [61; 32],
                    [62; 24],
                ),
            },
        ))
        .unwrap()
        .unwrap();
    let head = f.db.frontier().unwrap();
    let history = f.history();
    let march = history
        .routes_at(&f.db, &f.book, day(31), head)
        .unwrap()
        .unwrap();
    let next = history
        .routes_at(&f.db, &f.book, april, head)
        .unwrap()
        .unwrap();
    let earlier = history
        .routes_at(&f.db, &f.book, april, old)
        .unwrap()
        .unwrap();
    assert_ne!(march.control_entry, next.control_entry);
    assert_eq!(march.control_entry, earlier.control_entry);
    for (date, at) in [(day(31), head), (april, head), (april, old)] {
        assert_eq!(
            history
                .routes_at(&f.db, &f.book, date, at)
                .unwrap()
                .as_deref(),
            crate::chart::fx_revaluation_routes_at(&f.db, &f.book, date, at)
                .unwrap()
                .as_ref()
        );
    }
    assert_eq!(history.work().historical_route_reads, 3);
    assert_eq!(history.work().historical_route_reuses, 3);
}
