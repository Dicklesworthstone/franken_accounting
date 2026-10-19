//! The actual native confirmation transaction: exact retained sources, unique
//! cash-leg claims, current authority, historical facts and first-committer wins.

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::bank::{
    BankMatchPreparation, BankMatchRequest, bank_match_vid, bank_matched_leg_vid,
    confirm_bank_match, prepare_bank_match, read_bank_match,
};
use fa_journal::blob::DurableDirectory;
use fa_journal::evidence::{Storage, document_record, fetch_document};
use fa_journal::import::{BankFormat, BankImportManifest, BankImportWitness};
use fa_journal::*;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable, Id128, IntakeSource,
    LegPayload, Oid, PeriodRef, SealKey, Supersession, SupersessionKind, SymbolTable, Writer,
    account_vid, domain_digest,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::{BenefitInterval, Capability, DecisionCandidate, DecisionFeature, Op, Profile};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_delta_types::DeltaRow;
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

const OWNER: VId = VId(7);
const CONFIRMER: VId = VId(8);
const LINE_DOMAIN: &[u8] = b"fa:bank-line-doc:v1";
const PROPOSAL_DOMAIN: &[u8] = b"fa:reconciliation-match:v1";

fn day() -> DateDay {
    DateDay::from_ymd(2026, 3, 15).unwrap()
}
fn cap(principal: VId) -> Capability {
    Capability::embedded(principal, &["read", "post", "reconcile", "privileged"]).unwrap()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    store: BlobStore<MemVfs>,
    book: BookContext,
    usd: UnitId,
    evidence: Document,
}

impl Harness {
    fn new() -> Self {
        Self::with_opening_date(None)
    }
    fn with_opening_date(opening_date: Option<DateDay>) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([101; 32], DatabaseSecurityNamespaceId([102; 32]), [103; 32]),
            ))
            .unwrap();
        let units = UnitRegistry::with_defaults();
        let usd = units.lookup("USD").unwrap();
        let calendar = FiscalCalendar::monthly("bank-confirm", 1, 1).unwrap();
        let symbols = SymbolTable::compiled();
        let book = BookContext {
            book_id: Id128([104; 16]),
            calendar: calendar.clone(),
            units: units.clone(),
            seal_key: SealKey([105; 32]),
            symbols: symbols.clone(),
        };
        let spec = BookSpec {
            book_id: book.book_id,
            name: "Native bank confirmations".into(),
            base_unit: usd,
            calendar,
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date,
        };
        runtime
            .block_on(create_book(&mut db, &cx, &spec, &units, &symbols))
            .unwrap();
        let schema = Capability::embedded(OWNER, &["schema_change"]).unwrap();
        let chart = [
            AccountSpec {
                code: "1000".into(),
                name: "Cash".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
            AccountSpec {
                code: "4000".into(),
                name: "Revenue".into(),
                account_type: 4,
                normal_balance: 1,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
        ];
        runtime
            .block_on(install_chart(
                &mut db,
                &cx,
                &book,
                &chart,
                OWNER,
                opening_date.map_or(day(), |_| DateDay::from_ymd(2026, 1, 1).unwrap()),
                b"chart",
                seal(&book, "chart"),
                &schema,
            ))
            .unwrap()
            .unwrap();
        let (_, periods) = runtime
            .block_on(create_periods(
                &mut db,
                &cx,
                &book,
                2026,
                OWNER,
                seal(&book, "periods"),
                &schema,
            ))
            .unwrap()
            .unwrap();
        let period = &periods
            .iter()
            .find(|period| period.kind == PeriodKind::Normal && period.contains(day()))
            .unwrap()
            .code;
        runtime
            .block_on(transition_period(
                &mut db,
                &cx,
                &book,
                period,
                PeriodTransition::Open,
                OWNER,
                1,
                day(),
                b"open",
                seal(&book, "open"),
                &Capability::embedded(OWNER, &["close"]).unwrap(),
                &[],
            ))
            .unwrap()
            .unwrap();
        let evidence = Document {
            book_id: book.book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: OWNER,
            bytes: b"Original receipt for native bank confirmation tests".to_vec(),
        };
        runtime
            .block_on(add_document(&mut db, &cx, &book, &evidence))
            .unwrap()
            .unwrap();
        let blob_vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let directory = runtime
            .block_on(DurableDirectory::create(
                &cx.commit(),
                blob_vfs,
                Path::new("blobs"),
            ))
            .unwrap();
        let store = BlobStore::open(1, directory).unwrap();
        Self {
            runtime,
            root,
            db,
            store,
            book,
            usd,
            evidence,
        }
    }
    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.db.frontier().unwrap()
    }
    fn entry(&mut self, amounts: &[i128], reference: &str, key: &[u8]) -> EntryRef {
        let request = PostRequest {
            proposal: self.entry_payload(amounts, reference, key),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: cap(OWNER),
        };
        let cx = self.cx();
        self.runtime
            .block_on(post(&mut self.db, &cx, &self.book, request))
            .unwrap()
            .unwrap()
            .entry_ref()
    }
    fn entry_payload(&self, amounts: &[i128], reference: &str, key: &[u8]) -> EntryPayload {
        let mut legs = Vec::new();
        for amount in amounts {
            let mut leg = LegPayload::simple(
                Side::Debit,
                account_vid(self.book.book_id, "1000"),
                Amount::new(self.usd, *amount),
            );
            leg.memo = Some(seal(&self.book, reference));
            legs.push(leg);
        }
        legs.push(LegPayload::simple(
            Side::Credit,
            account_vid(self.book.book_id, "4000"),
            Amount::new(self.usd, amounts.iter().sum()),
        ));
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(),
            document_date: None,
            description: seal(&self.book, "cash receipt"),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([106; 32]),
                intent_kind: 1,
            },
            principal_ref: OWNER,
            session_ref: None,
            evidence: vec![self.evidence.evidence_ref(1)],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }
    fn approve(&mut self, digest: [u8; 32]) -> Vec<ApprovalRef> {
        [VId(9), VId(10)]
            .into_iter()
            .map(|principal| {
                let request = ApprovalRequest {
                    capability: Capability::embedded(principal, &["approve"]).unwrap(),
                    approved_proposal_digest: digest,
                    role: 0,
                };
                let cx = self.cx();
                self.runtime
                    .block_on(record_approval(&mut self.db, &cx, &self.book, request))
                    .unwrap()
                    .unwrap()
                    .approval()
            })
            .collect()
    }
    fn imported(
        &mut self,
        reference: &str,
        cents: i128,
        key: &[u8],
    ) -> (BankImportWitness, Document) {
        let (witness, mut lines) = self.imported_lines(reference, &[cents], key);
        (witness, lines.remove(0))
    }
    fn imported_lines(
        &mut self,
        reference: &str,
        cents: &[i128],
        key: &[u8],
    ) -> (BankImportWitness, Vec<Document>) {
        self.imported_lines_at(reference, cents, key, day())
    }
    fn imported_lines_at(
        &mut self,
        reference: &str,
        cents: &[i128],
        key: &[u8],
        booking_date: DateDay,
    ) -> (BankImportWitness, Vec<Document>) {
        let policy = EvidencePolicy::embedded().unwrap();
        let kind = |name| policy.kind_by_name(name).unwrap().tag;
        let source = Document {
            book_id: self.book.book_id,
            kind: kind("BankStatement"),
            mime: "text/csv".into(),
            grade: 3,
            retrieved_by: OWNER,
            bytes: format!(
                "Exact statement {}; amounts {cents:?}; reference {reference}",
                String::from_utf8_lossy(key)
            )
            .into_bytes(),
        };
        let mut lines = Vec::new();
        for (index, amount) in cents.iter().enumerate() {
            let mut w = Writer::new();
            w.bytes(LINE_DOMAIN)
                .fixed(&source.oid().0)
                .u64(1)
                .u32(u32::try_from(index + 1).unwrap())
                .i32(booking_date.0)
                .i32(booking_date.0)
                .u8(1)
                .u32(self.usd.0)
                .i128(*amount)
                .str("Bank customer")
                .str(reference);
            lines.push(Document {
                book_id: self.book.book_id,
                kind: kind("Other"),
                mime: fa_journal::import::bank::BANK_LINE_MIME.into(),
                grade: 3,
                retrieved_by: OWNER,
                bytes: w.finish().unwrap(),
            });
        }
        let manifest = BankImportManifest {
            book_id: self.book.book_id,
            account: account_vid(self.book.book_id, "1000"),
            format: BankFormat::Csv,
            statement_oid: source.oid(),
            statement_commit: source.doc_commit(),
            unit: self.usd,
            sequence_number: 1,
            statement_date: booking_date,
            opening_balance: 0,
            closing_balance: cents.iter().sum(),
            line_oids: lines.iter().map(Document::oid).collect(),
            predecessor: None,
        };
        let document = Document {
            book_id: self.book.book_id,
            kind: kind("Workpaper"),
            mime: fa_journal::import::bank::BANK_MANIFEST_MIME.into(),
            grade: 3,
            retrieved_by: OWNER,
            bytes: manifest.canonical_bytes().unwrap(),
        };
        let mut documents = lines.clone();
        documents.extend([source, document.clone()]);
        let request = ImportRequest {
            principal: OWNER,
            source: IntakeSource::Upload { principal: OWNER },
            idempotency_key: key.to_vec(),
            effective_date: booking_date,
            description: seal(&self.book, "bank import"),
            documents,
        };
        let cx = self.cx();
        let receipt = self
            .runtime
            .block_on(fa_journal::import::import_run_in_store(
                &mut self.db,
                &cx,
                &self.book,
                &cap(OWNER),
                &self.store,
                request,
            ))
            .unwrap()
            .unwrap();
        let witness =
            BankImportWitness::capture(&self.db, self.book.book_id, &document, &receipt.receipt)
                .unwrap()
                .unwrap();
        (witness, lines)
    }
    fn request(
        &self,
        import: BankImportWitness,
        line: Document,
        entry_ref: EntryRef,
        leg_ordinal: u16,
    ) -> BankMatchRequest {
        let oid = Oid(domain_digest(LINE_DOMAIN, &[&line.bytes]));
        let candidate_ordinal = u64::from(leg_ordinal);
        let decision_card = fa_policy::decide_bank_match(
            None,
            [0; 32],
            oid.0,
            vec![DecisionCandidate {
                action: "match_entry_ordinal".into(),
                parameter: i128::from(candidate_ordinal),
                analytic_score: 1_500_000_000 - i128::from(candidate_ordinal),
            }],
            vec![
                DecisionFeature {
                    name: format!("cand.{candidate_ordinal}.date_delta_days"),
                    value: 0,
                    advisory: false,
                },
                DecisionFeature {
                    name: format!("cand.{candidate_ordinal}.ref_exact"),
                    value: 1,
                    advisory: false,
                },
                DecisionFeature {
                    name: format!("cand.{candidate_ordinal}.cp_exact"),
                    value: 0,
                    advisory: false,
                },
            ],
            BenefitInterval {
                lower_bps: 0,
                upper_bps: 2_000,
            },
        );
        let mut request = BankMatchRequest {
            import,
            predecessors: Vec::new(),
            lines: vec![line.clone()],
            line,
            entry_ref,
            leg_ordinal,
            source_known_at: self.head(),
            date_window_days: 3,
            candidate_ordinal,
            proposer: OWNER,
            proposal_digest: [0; 32],
            decision_card,
        };
        rebind(&mut request);
        request
    }
    fn confirm(
        &mut self,
        capability: &Capability,
        request: BankMatchRequest,
    ) -> Result<fa_journal::bank::BankMatchRecorded, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(confirm_bank_match(
                &mut self.db,
                &cx,
                &self.book,
                capability,
                request,
            ))
            .unwrap()
    }
    fn read(
        &mut self,
        vid: VId,
        at: Option<CommitSeq>,
    ) -> Result<Option<fa_journal::bank::BankMatchRecorded>, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(read_bank_match(
                &mut self.db,
                &cx,
                &self.book,
                &cap(CONFIRMER),
                vid,
                at,
                None,
            ))
            .unwrap()
    }
    fn write(&mut self, batch: WriteBatch) {
        let cx = self.cx();
        self.runtime
            .block_on(self.db.write(&cx.commit(), batch))
            .unwrap();
    }
    fn reverse(&mut self, target: EntryRef) -> EntryRef {
        let (original, _) = read_entry(&self.db, target.vid).unwrap().unwrap();
        let mut proposal = original.proposal.clone();
        proposal.class = EntryClass::REVERSAL;
        proposal.idempotency_key = b"reverse-cash".to_vec();
        proposal.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        for leg in &mut proposal.legs {
            leg.side = if leg.side == Side::Debit {
                Side::Credit
            } else {
                Side::Debit
            };
            leg.settles.clear();
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        let request = PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: cap(OWNER),
        };
        let cx = self.cx();
        self.runtime
            .block_on(post(&mut self.db, &cx, &self.book, request))
            .unwrap()
            .unwrap()
            .entry_ref()
    }
}

fn seal(book: &BookContext, text: &str) -> Erasable<String> {
    Erasable::seal(
        &text.to_string(),
        None,
        &book.seal_key,
        [107; 32],
        [108; 24],
    )
}

fn rebind(request: &mut BankMatchRequest) {
    let oid = Oid(domain_digest(LINE_DOMAIN, &[&request.line.bytes]));
    let card = request.decision_card.canonical_bytes().unwrap();
    let mut w = Writer::new();
    w.bytes(PROPOSAL_DOMAIN)
        .list(&[oid], |w, oid| {
            w.fixed(&oid.0);
        })
        .list(&[request.entry_ref], |w, entry| {
            w.u128(entry.vid.0).fixed(&entry.entry_digest);
        })
        .opt(Some(&request.candidate_ordinal), |w, ordinal| {
            w.u64(*ordinal);
        })
        .u8(0)
        .bytes(&card)
        .u128(request.proposer.0)
        .u8(0);
    request.proposal_digest = domain_digest(PROPOSAL_DOMAIN, &[&w.finish().unwrap()]);
}

#[test]
fn native_confirmation_retains_the_original_fact_across_retries_and_historical_reads() {
    let mut h = Harness::new();
    let entry = h.entry(&[10_000], "WIRE-17", b"cash");
    let (import, line) = h.imported(" wire-17 ", 10_000, b"statement");
    let source = h.head();
    let request = h.request(import, line, entry, 0);
    let recorded = h.confirm(&cap(CONFIRMER), request.clone()).unwrap();
    assert!(!recorded.already_recorded);
    assert_eq!(recorded.recorded_at.0, source.0 + 1);
    assert_eq!(recorded.confirmation.confirmed_by, CONFIRMER);
    assert_eq!(recorded.confirmation.proposer, OWNER);
    assert_eq!(recorded.confirmation.entry_ref, entry);
    assert_eq!(recorded.confirmation.source_known_at, source);
    let mut invalid_profile = recorded.confirmation.clone();
    invalid_profile.confirming_profile = Profile::System;
    assert!(
        fa_journal::bank::BankMatchConfirmation::decode(
            &invalid_profile.canonical_bytes().unwrap()
        )
        .is_err()
    );
    assert_eq!(
        recorded.match_vid,
        bank_match_vid(h.book.book_id, request.import.manifest().statement_oid, 1)
    );
    let publications: Vec<_> = h.db.delta_since(source).unwrap().collect();
    assert_eq!(publications.len(), 1, "one native publication");
    let mut vertices = 0;
    let mut matches = 0;
    let mut citations = 0;
    let mut memberships = 0;
    for coordinate in publications[0].coordinate_entries() {
        for row in &coordinate.rows {
            match row {
                DeltaRow::CreateVertex { .. } => vertices += 1,
                DeltaRow::CreateEdge { relation, .. } => match *relation {
                    relation::MATCHES => matches += 1,
                    relation::CITES => citations += 1,
                    relation::IN_BOOK => memberships += 1,
                    other => panic!("unexpected confirmation relation {other:?}"),
                },
                other => panic!("confirmation changed an existing native fact: {other:?}"),
            }
        }
    }
    assert_eq!(
        (vertices, matches, citations, memberships),
        (2, 1, 6, 2),
        "registered bank_match_confirmation effects: two vertices and nine edges"
    );
    let retry = h.confirm(&cap(VId(9)), request).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.confirmation, recorded.confirmation);
    assert_eq!(retry.match_digest, recorded.match_digest);
    assert_eq!(retry.recorded_at, recorded.recorded_at);
    assert_eq!(h.head(), recorded.recorded_at);
    assert_eq!(h.db.delta_since(recorded.recorded_at).unwrap().count(), 0);
    assert!(h.read(recorded.match_vid, Some(source)).unwrap().is_none());
    assert_eq!(h.read(recorded.match_vid, None).unwrap().unwrap(), recorded);
    assert_eq!(
        h.head(),
        recorded.recorded_at,
        "both reads are side effect free"
    );
}

#[test]
fn a_maximum_statement_confirms_with_a_compact_record_and_a_real_external_manifest() {
    let mut h = Harness::new();
    let entry = h.entry(&[10_000], "WIRE", b"cash");
    let amounts: Vec<_> = (0..fa_journal::import::bank::MAX_BANK_LINES)
        .map(|index| 10_000 + i128::try_from(index).unwrap())
        .collect();
    let (import, lines) = h.imported_lines("WIRE", &amounts, b"maximum-statement");
    assert_eq!(lines.len(), 1_022);
    let manifest = import.manifest().clone();
    let manifest_oid = import.manifest_oid();
    let manifest_bytes = manifest.canonical_bytes().unwrap();
    assert!(manifest_bytes.len() > 16 * 1_024);
    assert!(matches!(
        document_record(&h.db, &manifest_oid)
            .unwrap()
            .unwrap()
            .storage,
        Storage::External { .. }
    ));
    let retained = h
        .runtime
        .block_on(fetch_document(&h.db, &h.cx(), &h.store, &manifest_oid))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(retained.bytes, manifest_bytes);
    let mut request = h.request(import, lines[0].clone(), entry, 0);
    request.lines = lines;
    let before = h.head();
    let recorded = h.confirm(&cap(CONFIRMER), request.clone()).unwrap();
    assert_eq!(recorded.recorded_at.0, before.0 + 1);
    assert!(recorded.confirmation.canonical_bytes().unwrap().len() < 1_024);
    let cx = h.cx();
    let read = h
        .runtime
        .block_on(read_bank_match(
            &mut h.db,
            &cx,
            &h.book,
            &cap(CONFIRMER),
            recorded.match_vid,
            None,
            Some(&manifest),
        ))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(read, recorded);
    assert!(h.confirm(&cap(VId(9)), request).unwrap().already_recorded);
    assert_eq!(h.head(), recorded.recorded_at);
}

#[test]
fn separate_actual_cash_legs_can_confirm_but_one_cash_leg_cannot_be_spent_twice() {
    let mut h = Harness::new();
    let entry = h.entry(&[10_000, 20_000], "WIRE", b"two-legs");
    let (first_import, first_line) = h.imported("WIRE", 10_000, b"first");
    let first = h.request(first_import, first_line, entry, 0);
    h.confirm(&cap(CONFIRMER), first).unwrap();
    let (second_import, second_line) = h.imported("WIRE", 20_000, b"second");
    let second = h.request(second_import, second_line, entry, 1);
    let matched_second = h.confirm(&cap(CONFIRMER), second).unwrap();
    assert_eq!(matched_second.confirmation.leg_ordinal, 1);
    let (third_import, third_line) = h.imported("WIRE", 10_000, b"third");
    let third = h.request(third_import, third_line, entry, 0);
    let before = h.head();
    assert_eq!(
        h.confirm(&cap(CONFIRMER), third).unwrap_err().code,
        refusal::code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(h.head(), before);
}

#[test]
fn exact_native_eligibility_rejects_wrong_amount_reference_direction_ordinal_and_coordinate() {
    let mut h = Harness::new();
    let entry = h.entry(&[10_000], "WIRE", b"cash");
    let (import, line) = h.imported("WIRE", 10_001, b"bad-amount");
    let amount = h.request(import, line, entry, 0);
    let (import, line) = h.imported("OTHER", 10_000, b"bad-reference");
    let reference = h.request(import, line, entry, 0);
    let (import, line) = h.imported("WIRE", 10_000, b"correct");
    let valid = h.request(import, line, entry, 0);
    let mut missing_leg = valid.clone();
    missing_leg.leg_ordinal = 200;
    let mut non_cash = valid.clone();
    non_cash.leg_ordinal = 1;
    let mut future = valid.clone();
    future.source_known_at = CommitSeq(h.head().0 + 1);
    let mut digest = valid.clone();
    digest.proposal_digest[0] ^= 1;
    let before = h.head();
    for request in [amount, reference, missing_leg, non_cash, future, digest] {
        assert_eq!(
            h.confirm(&cap(CONFIRMER), request).unwrap_err().code,
            refusal::code::BANK_MATCH
        );
        assert_eq!(h.head(), before);
    }
    h.confirm(&cap(CONFIRMER), valid).unwrap();
}

#[test]
fn concurrent_preparations_cannot_confirm_the_same_cash_leg_for_two_statements() {
    let mut h = Harness::new();
    let entry = h.entry(&[10_000], "WIRE", b"cash");
    let (first_import, first_line) = h.imported("WIRE", 10_000, b"first");
    let (second_import, second_line) = h.imported("WIRE", 10_000, b"second");
    let first = h.request(first_import, first_line, entry, 0);
    let second = h.request(second_import, second_line, entry, 0);
    let cx = h.cx();
    let BankMatchPreparation::Ready(first) =
        prepare_bank_match(&mut h.db, &cx, &h.book, &cap(CONFIRMER), first)
            .unwrap()
            .unwrap()
    else {
        panic!("fresh first confirmation");
    };
    let BankMatchPreparation::Ready(second) =
        prepare_bank_match(&mut h.db, &cx, &h.book, &cap(CONFIRMER), second)
            .unwrap()
            .unwrap()
    else {
        panic!("fresh second confirmation");
    };
    let first = h
        .runtime
        .block_on(first.commit(&mut h.db, &cx))
        .unwrap()
        .unwrap();
    let failure = h
        .runtime
        .block_on(second.commit(&mut h.db, &cx))
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.code, refusal::code::CONFLICT);
    assert_eq!(h.head(), first.recorded_at);
}

#[test]
fn confirmation_and_claim_damage_fail_closed_without_rewriting_earlier_facts() {
    for attack in 0..4 {
        let mut h = Harness::new();
        let entry = h.entry(&[10_000], "WIRE", b"cash");
        let (import, line) = h.imported("WIRE", 10_000, b"statement");
        let request = h.request(import, line, entry, 0);
        let recorded = h.confirm(&cap(CONFIRMER), request.clone()).unwrap();
        let claim = bank_matched_leg_vid(h.book.book_id, entry.vid, 0);
        let mut damage = WriteBatch::new(relation::CITES);
        match attack {
            0 => {
                damage.delete_vertex(recorded.match_vid);
            }
            1 => {
                damage.set_vertex_label(recorded.match_vid, label::BANK_MATCH, false);
            }
            2 => {
                damage.delete_vertex(claim);
            }
            _ => {
                damage.set_vertex_property(
                    recorded.match_vid,
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
                );
            }
        }
        h.write(damage);
        let before = h.head();
        assert_eq!(
            h.read(recorded.match_vid, None).unwrap_err().code,
            refusal::code::BANK_MATCH_DRIFT
        );
        assert_eq!(
            h.read(recorded.match_vid, Some(recorded.recorded_at))
                .unwrap()
                .unwrap(),
            recorded
        );
        assert_eq!(h.head(), before);
        assert!(h.confirm(&cap(CONFIRMER), request).is_err());
        assert_eq!(h.head(), before);
    }
}

#[test]
fn a_confirmed_migration_leg_requires_its_run_at_the_selected_prefix() {
    for remove_run in [false, true] {
        // The opening period is natively born Locked before this book's
        // March go-live; the migration follows its real approved lifecycle.
        let mut h = Harness::with_opening_date(Some(DateDay::from_ymd(2026, 3, 1).unwrap()));
        let opening = DateDay::from_ymd(2026, 1, 1).unwrap();
        let evidence = Document {
            book_id: h.book.book_id,
            kind: EvidencePolicy::embedded()
                .unwrap()
                .kind_by_name("Spreadsheet")
                .unwrap()
                .tag,
            mime: "text/csv".into(),
            grade: 3,
            retrieved_by: OWNER,
            bytes: b"account,unit,mantissa\n1000,USD,30000\n4000,USD,-30000\n".to_vec(),
        };
        let cx = h.cx();
        h.runtime
            .block_on(add_document(&mut h.db, &cx, &h.book, &evidence))
            .unwrap()
            .unwrap();
        let body = RunBody {
            book_id: h.book.book_id,
            run_key: "bank-opening".into(),
            source_system: "legacy-bank".into(),
            mode: RunMode::OpeningOnly,
            trial_balance: evidence.oid(),
            opening_date: opening,
            lines: vec![
                TrialBalanceLine {
                    account_code: "1000".into(),
                    unit: h.usd,
                    mantissa: 30_000,
                },
                TrialBalanceLine {
                    account_code: "4000".into(),
                    unit: h.usd,
                    mantissa: -30_000,
                },
            ],
            periods: Vec::new(),
            detail_base: Vec::new(),
            sole_opening_source: false,
        };
        let migration_cap = Capability::embedded(OWNER, &["post", "migrate"]).unwrap();
        let open = RunControlRequest {
            proposal: open_proposal(
                &h.book,
                OWNER,
                &body,
                vec![evidence.evidence_ref(1)],
                b"open-bank-migration",
                seal(&h.book, "open bank migration"),
            )
            .unwrap(),
            capability: migration_cap.clone(),
            approvals: Vec::new(),
        };
        h.runtime
            .block_on(open_run(&mut h.db, &cx, &h.book, &body, open))
            .unwrap()
            .unwrap();
        let mut proposal = h.entry_payload(&[10_000, 20_000], "WIRE", b"migrated-cash");
        proposal.class = EntryClass::MIGRATION;
        proposal.effective_date = opening;
        proposal.effective_period = Some(PeriodRef {
            calendar: h.book.calendar.id.clone(),
            code: "FY2026-OPEN".into(),
        });
        proposal.origin = EntryOrigin::Migration {
            run_ref: body.vid(),
            source_system: body.source_system.clone(),
            source_id: seal(&h.book, "legacy cash opening"),
            source_recorded_at_ns: None,
            source_entered_by: None,
            source_approved_by: None,
            batch_oid: evidence.oid(),
        };
        proposal.evidence = vec![evidence.evidence_ref(1)];
        let approvals = h.approve(proposal.proposal_digest().unwrap());
        let request = PostRequest {
            proposal,
            approvals,
            plan_certificate: None,
            capability: migration_cap.clone(),
        };
        let entry = h
            .runtime
            .block_on(post(&mut h.db, &cx, &h.book, request))
            .unwrap()
            .unwrap()
            .entry_ref();
        let proposal = plan_run_transition(
            &h.db,
            &h.book,
            body.vid(),
            fa_journal::migration::kind::FINALIZE,
            OWNER,
            b"finalize-bank-migration",
            seal(&h.book, "finalize bank migration"),
        )
        .unwrap()
        .unwrap();
        let approvals = h.approve(proposal.proposal_digest().unwrap());
        h.runtime
            .block_on(transition_run(
                &mut h.db,
                &cx,
                &h.book,
                RunControlRequest {
                    proposal,
                    capability: migration_cap,
                    approvals,
                },
            ))
            .unwrap()
            .unwrap();
        let (import, lines) =
            h.imported_lines_at("WIRE", &[10_000, 20_000], b"opening-statement", opening);
        let mut first = h.request(import.clone(), lines[0].clone(), entry, 0);
        first.lines = lines.clone();
        let mut second = h.request(import, lines[1].clone(), entry, 1);
        second.lines = lines;
        let recorded = h.confirm(&cap(CONFIRMER), first.clone()).unwrap();
        let BankMatchPreparation::Ready(prepared) =
            prepare_bank_match(&mut h.db, &cx, &h.book, &cap(CONFIRMER), second)
                .unwrap()
                .unwrap()
        else {
            panic!("the distinct migrated cash leg is still available");
        };
        assert_eq!(h.read(recorded.match_vid, None).unwrap().unwrap(), recorded);
        let mut damage = WriteBatch::new(relation::IN_MIGRATION_RUN);
        if remove_run {
            damage.delete_vertex(body.vid());
        } else {
            damage.set_vertex_property(
                body.vid(),
                property::STATE,
                Some(RunState::Abandoned.scalar()),
            );
        }
        h.write(damage);
        let damaged_at = h.head();
        assert_eq!(
            h.read(recorded.match_vid, None).unwrap_err().code,
            refusal::code::BANK_MATCH_DRIFT
        );
        assert_eq!(
            h.confirm(&cap(CONFIRMER), first).unwrap_err().code,
            refusal::code::BANK_MATCH_DRIFT
        );
        assert_eq!(
            h.read(recorded.match_vid, Some(recorded.recorded_at))
                .unwrap()
                .unwrap(),
            recorded,
            "a later damaged run cannot rewrite the valid original confirmation"
        );
        assert_eq!(
            h.runtime
                .block_on(prepared.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap_err()
                .code,
            refusal::code::CONFLICT,
            "publication must retain the migration-run visibility witness"
        );
        assert_eq!(h.head(), damaged_at);
    }
}

#[test]
fn current_authority_and_privileged_source_admission_win_over_requested_history() {
    let mut h = Harness::new();
    let entry = h.entry(&[10_000], "WIRE", b"cash");
    let (import, line) = h.imported("WIRE", 10_000, b"statement");
    let valid = h.request(import, line, entry, 0);
    let before = h.head();
    let lower = Capability::embedded(CONFIRMER, &["read", "reconcile"]).unwrap();
    let refusal = h.confirm(&lower, valid.clone()).unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
    assert_eq!(refusal.exit, fa_journal::refusal::exit::SAFETY);
    let system = Capability::new(
        CONFIRMER,
        Profile::System,
        &[Op::Read, Op::Reconcile, Op::Privileged],
        OWNER,
    )
    .unwrap();
    assert!(
        h.confirm(&system, valid.clone())
            .unwrap_err()
            .message
            .contains("Human")
    );
    let expired = cap(CONFIRMER).expiring_at(before);
    let mut malformed = valid;
    malformed.line.bytes = b"invalid source".to_vec();
    malformed.source_known_at = CommitSeq(0);
    assert!(
        h.confirm(&expired, malformed)
            .unwrap_err()
            .message
            .contains("expir")
    );
    assert_eq!(h.head(), before);
}

#[test]
fn native_selection_rejects_synthetic_cards_over_ambiguous_or_incomplete_source_sets() {
    let mut h = Harness::new();
    let entry = h.entry(&[10_000, 10_000], "WIRE", b"ambiguous-cash");
    let (import, line) = h.imported("WIRE", 10_000, b"single-line");
    // The public caller supplies a perfectly replayable card mentioning just
    // candidate 0. The native historical universe still contains two legs.
    let request = h.request(import, line, entry, 0);
    let before = h.head();
    assert_eq!(
        h.confirm(&cap(CONFIRMER), request).unwrap_err().code,
        refusal::code::BANK_MATCH
    );
    assert_eq!(h.head(), before);

    let mut h = Harness::new();
    let entry = h.entry(&[10_000], "WIRE", b"cash");
    let (import, lines) = h.imported_lines("WIRE", &[10_000, 10_000], b"competing-lines");
    let mut request = h.request(import, lines[0].clone(), entry, 0);
    let before = h.head();
    assert_eq!(
        h.confirm(&cap(CONFIRMER), request.clone())
            .unwrap_err()
            .code,
        refusal::code::BANK_MATCH,
        "omitting the second retained line cannot manufacture uniqueness"
    );
    request.lines = lines;
    assert_eq!(
        h.confirm(&cap(CONFIRMER), request).unwrap_err().code,
        refusal::code::BANK_MATCH,
        "including both lines exposes the competing claim on one cash leg"
    );
    assert_eq!(h.head(), before);

    let mut h = Harness::new();
    let entry = h.entry(&[10_000, 20_000], "WIRE", b"distinct-cash");
    let (import, line) = h.imported("WIRE", 10_000, b"statement");
    let mut request = h.request(import, line, entry, 0);
    request.candidate_ordinal = 1;
    rebind(&mut request);
    let before = h.head();
    assert_eq!(
        h.confirm(&cap(CONFIRMER), request).unwrap_err().code,
        refusal::code::BANK_MATCH,
        "a syntactically valid proposal cannot relabel the actual candidate coordinate"
    );
    assert_eq!(h.head(), before);
}

#[test]
fn deleting_a_later_native_reversal_cannot_revive_an_old_cash_proposal() {
    let mut h = Harness::new();
    let entry = h.entry(&[10_000], "WIRE", b"cash");
    let (import, line) = h.imported("WIRE", 10_000, b"statement");
    let request = h.request(import, line, entry, 0);
    let reversed = h.reverse(entry);
    assert_eq!(reversed.vid, fa_journal::rows::reversal_vid(entry.vid));
    assert_eq!(
        h.confirm(&cap(CONFIRMER), request.clone())
            .unwrap_err()
            .code,
        refusal::code::BANK_MATCH
    );
    let mut damage = WriteBatch::new(relation::CITES);
    damage.delete_vertex(reversed.vid);
    h.write(damage);
    let before = h.head();
    assert_eq!(
        h.confirm(&cap(CONFIRMER), request).unwrap_err().code,
        refusal::code::BANK_MATCH_DRIFT
    );
    assert_eq!(h.head(), before);
}
