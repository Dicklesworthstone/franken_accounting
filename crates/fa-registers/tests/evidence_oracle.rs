//! The kernel's evidence law against the reference oracle (fa-lp6, fa-g21;
//! plan §9.2–§9.3, FA-INV-05 `evidence-minimum`).
//!
//! Two differentials:
//! 1. **Exhaustive, pure.** For every registered entry class and every set of
//!    up to two cited documents drawn from 90 archetypes (6 kinds × all 5
//!    provenance grades × no review / reviewed by another principal /
//!    reviewed by the uploader), with no assertion, a registered one, or an
//!    unregistered one, `fa_journal::evidence::check_minimum` and
//!    `fa_reference::evidence::verdict` return the same refusal code — the
//!    kernel from its own code, the oracle from the plan's text and the
//!    registry rows.
//! 2. **Seeded, on the real substrate.** Random histories of document
//!    intake, Reviewed and ManualAssertion recording, and posts citing held,
//!    unheld, and mis-committed documents, each step's kernel outcome equal
//!    to the oracle's over plain maps. Floors make every recording refusal,
//!    every posting refusal the history can reach, and both admitted
//!    attestation paths (a reviewed agent upload; a preparer's assertion)
//!    occur on every seed. Refusals that only a forged row can reach at post
//!    time (a stored self-review, an unregistered stored reason, drift) are
//!    fa-journal's genesis tests.
//!
//! No-claim boundary: agreement proves the registered cases are admitted and
//! the planted negatives refused; it says nothing about the legal
//! sufficiency of any evidence.

use std::collections::BTreeMap;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::attestation::{Review, record_manual_assertion, record_review};
use fa_journal::evidence::{CitedDocument, Document, add_document, check_minimum};
use fa_journal::import::{ImportRecorded, ImportRequest, RunReceipt, import_run, verify_receipt};
use fa_journal::*;
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128, LegPayload, Oid, SealKey,
    SymbolTable,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_reference::evidence::{
    Attestations, Citation, Custody, Doc, Law, manual_verdict, review_verdict, verdict,
};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;

const KINDS: [&str; 6] = [
    "Invoice",
    "Rate",
    "Memo",
    "Workpaper",
    "Spreadsheet",
    "Confirmation",
];

/// Review states of an archetype: none, by another principal, by the uploader.
const REVIEWS: [Option<u64>; 3] = [None, Some(8), Some(7)];
const UPLOADER: u64 = 7;

#[test]
fn kernel_and_oracle_agree_on_every_class_and_every_pair_of_documents() {
    let law = Law::embedded().expect("registries");
    let policy = &law.policy;
    let grades: Vec<String> = policy.grades.iter().map(|g| g.name.clone()).collect();
    assert_eq!(grades.len(), 5, "every provenance grade is exercised");
    let mut archetypes: Vec<(String, String, Option<u64>)> = Vec::new();
    for k in KINDS {
        for g in &grades {
            for r in REVIEWS {
                archetypes.push((k.to_string(), g.clone(), r));
            }
        }
    }
    let mut sets: Vec<Vec<usize>> = vec![Vec::new()];
    for a in 0..archetypes.len() {
        sets.push(vec![a]);
        for b in a + 1..archetypes.len() {
            sets.push(vec![a, b]);
        }
    }
    let mut compared = 0usize;
    let mut refusals: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut admitted_by_review = 0usize;
    let mut admitted_by_assertion = 0usize;
    let mut class_names: Vec<String> = EntryClass::ALL
        .iter()
        .map(|(_, name, _)| (*name).to_string())
        .collect();
    assert_eq!(class_names.len(), 30, "every registered class");
    class_names.push("NoSuchClass".into());
    for class in &class_names {
        for set in &sets {
            let mut docs = BTreeMap::new();
            let mut cited = Vec::new();
            let mut citations = Vec::new();
            let mut reviews = BTreeMap::new();
            for (i, a) in set.iter().enumerate() {
                let (kind, grade, review) = &archetypes[*a];
                let id = u64::try_from(i).unwrap() + 1;
                let commit = [u8::try_from(*a % 251).unwrap(); 32];
                docs.insert(
                    id,
                    Doc {
                        kind: kind.clone(),
                        grade: grade.clone(),
                        commit,
                        uploader: UPLOADER,
                        custody: Custody::uploaded(),
                    },
                );
                citations.push(Citation {
                    doc: id,
                    commit,
                    role: 1,
                });
                if let Some(r) = review {
                    reviews.insert(id, *r);
                }
                let tag = policy.kind_by_name(kind).unwrap().tag;
                let grade_tag = policy.grade_by_name(grade).unwrap().tag;
                // The kernel reads a review only for an admissible
                // self-sourced document; the oracle ignores it elsewhere.
                let reads = policy.minimum(class).is_some_and(|m| m.kinds.admits(tag))
                    && policy
                        .grade_by_tag(grade_tag)
                        .is_some_and(|g| g.self_sourced);
                cited.push(CitedDocument {
                    vid: VId(u128::from(id)),
                    oid: Oid([u8::try_from(id).unwrap(); 32]),
                    kind: tag,
                    grade: grade_tag,
                    uploader: VId(u128::from(UPLOADER)),
                    review: review.filter(|_| reads).map(|r| Review {
                        attestation: VId(1000 + u128::from(id)),
                        reviewer: VId(u128::from(r)),
                    }),
                });
            }
            for manual in [None, Some(1u16), Some(4), Some(0), Some(999)] {
                let kernel = check_minimum(policy, &law.reasons, class, &cited, manual)
                    .err()
                    .map(|r| r.code);
                let attestations = Attestations {
                    reviews: reviews.clone(),
                    manual,
                };
                let oracle = verdict(&law, class, &docs, &citations, &attestations);
                assert_eq!(
                    kernel,
                    oracle,
                    "class {class}, manual {manual:?}, documents {:?}",
                    set.iter().map(|a| &archetypes[*a]).collect::<Vec<_>>()
                );
                match oracle {
                    Some(code) => *refusals.entry(code).or_default() += 1,
                    None => {
                        let bare = Attestations::default();
                        if verdict(&law, class, &docs, &citations, &bare).is_some() {
                            let reviews_only = Attestations {
                                reviews: reviews.clone(),
                                manual: None,
                            };
                            if verdict(&law, class, &docs, &citations, &reviews_only).is_none() {
                                admitted_by_review += 1;
                            } else {
                                admitted_by_assertion += 1;
                            }
                        }
                    }
                }
                compared += 1;
            }
        }
    }
    // Coverage floors: the space is not vacuous, and every outcome the law
    // can reach is reached many times.
    assert_eq!(compared, class_names.len() * sets.len() * 5);
    assert!(compared > 300_000, "{compared}");
    for code in ["FA-REF-080", "FA-REF-086", "FA-REF-111", "FA-REF-112"] {
        assert!(
            refusals.get(code).copied().unwrap_or(0) > 100,
            "{code} reached only {:?} times",
            refusals.get(code)
        );
    }
    assert!(admitted_by_review > 1_000, "{admitted_by_review}");
    assert!(admitted_by_assertion > 100, "{admitted_by_assertion}");
    eprintln!(
        "evidence-oracle exhaustive: compared={compared} refusals={refusals:?} admitted_by_review={admitted_by_review} admitted_by_assertion={admitted_by_assertion}"
    );
}

// ---------------------------------------------------------------------------
// The seeded differential on the real substrate
// ---------------------------------------------------------------------------

/// Principals: every one may post and approve, so self-review is reachable.
const PRINCIPALS: [u64; 3] = [7, 8, 9];
const PREPARER: u64 = 7;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[usize::try_from(self.below(u64::try_from(items.len()).unwrap())).unwrap()]
    }
}

struct Book {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    cash: VId,
    revenue: VId,
}

impl Book {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn capability(principal: u64) -> Capability {
        Capability::embedded(VId(u128::from(principal)), &["post", "approve"]).expect("ops")
    }

    fn add(&mut self, doc: &Document) -> Result<DocumentAdded, Refusal> {
        let ctx = self.ctx();
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(async move { add_document(db, &ctx, book, doc).await })
            .expect("kernel")
    }

    fn review(
        &mut self,
        reviewer: u64,
        document: Oid,
        against: Vec<Oid>,
    ) -> Result<Attested, Refusal> {
        let ctx = self.ctx();
        let cap = Self::capability(reviewer);
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(async move {
                record_review(
                    db,
                    &ctx,
                    book,
                    &cap,
                    VId(u128::from(reviewer)),
                    document,
                    against,
                )
                .await
            })
            .expect("kernel")
    }

    fn assert_manually(
        &mut self,
        proposal: &EntryPayload,
        reason: u16,
        nonce: u8,
    ) -> Result<Attested, Refusal> {
        let ctx = self.ctx();
        let cap = Self::capability(PREPARER);
        let statement = Erasable::seal(
            &"the landlord issues no invoice; rent is set by the lease".to_string(),
            None,
            &self.book.seal_key,
            [nonce; 32],
            [nonce; 24],
        );
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(async move {
                record_manual_assertion(db, &ctx, book, &cap, proposal, reason, statement).await
            })
            .expect("kernel")
    }

    fn post(&mut self, proposal: EntryPayload) -> Result<Posted, Refusal> {
        let req = PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Self::capability(PREPARER),
        };
        let ctx = self.ctx();
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel")
    }

    fn proposal(&self, class: EntryClass, key: &[u8], evidence: Vec<EvidenceRef>) -> EntryPayload {
        let legs = vec![
            LegPayload::simple(Side::Debit, self.cash, Amount::new(self.usd, 1_500)),
            LegPayload::simple(Side::Credit, self.revenue, Amount::new(self.usd, 1_500)),
        ];
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class,
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            document_date: None,
            description: Erasable::seal(
                &"evidence differential".to_string(),
                None,
                &self.book.seal_key,
                [9; 32],
                [9; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: VId(u128::from(PREPARER)),
            session_ref: None,
            evidence,
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }
}

fn book() -> Book {
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let keys = DatabaseKeys::new(
        [0x5a; 32],
        DatabaseSecurityNamespaceId([0x5b; 32]),
        [0x5c; 32],
    );
    let mut db = runtime
        .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
        .expect("open");
    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
    let book_id = Id128([0x5e; 16]);
    let spec = BookSpec {
        book_id,
        name: "Attestation Co".into(),
        base_unit: usd,
        calendar: calendar.clone(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    };
    let symbols = SymbolTable::compiled();
    runtime
        .block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await })
        .expect("create_book");
    let book = BookContext {
        book_id,
        calendar,
        units,
        seal_key: SealKey([0x11; 32]),
        symbols,
    };
    let leaf = |code: &str, account_type: u8, normal_balance: u8| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type,
        normal_balance,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: None,
    };
    let chart = vec![leaf("1000", 1, 0), leaf("4000", 4, 1)];
    let day = DateDay::from_ymd(2026, 1, 1).unwrap();
    let principal = VId(u128::from(PREPARER));
    runtime
        .block_on(async {
            install_chart(
                &mut db,
                &ctx,
                &book,
                &chart,
                principal,
                day,
                b"chart",
                Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]),
                &Capability::embedded(principal, &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("kernel")
        .expect("installs");
    let (_, periods) = runtime
        .block_on(async {
            create_periods(
                &mut db,
                &ctx,
                &book,
                2026,
                fgdb_types::VId(1),
                fa_model::Erasable::seal(
                    &"periods".to_string(),
                    None,
                    &book.seal_key,
                    [1; 32],
                    [2; 24],
                ),
                &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("periods")
        .expect("admitted");
    let march = periods
        .iter()
        .find(|p| {
            p.contains(DateDay::from_ymd(2026, 3, 15).unwrap()) && p.kind == PeriodKind::Normal
        })
        .unwrap()
        .code
        .clone();
    runtime
        .block_on(async {
            transition_period(
                &mut db,
                &ctx,
                &book,
                &march,
                PeriodTransition::Open,
                principal,
                1,
                b"open",
                Erasable::seal(
                    &"period".to_string(),
                    None,
                    &book.seal_key,
                    [3; 32],
                    [4; 24],
                ),
                &Capability::embedded(principal, &["close"]).expect("close"),
                &[],
            )
            .await
        })
        .expect("kernel")
        .expect("opens");
    Book {
        runtime,
        root,
        db,
        cash: fa_model::account_vid(book_id, "1000"),
        revenue: fa_model::account_vid(book_id, "4000"),
        book,
        usd,
    }
}

/// What the oracle holds besides the documents: one review per document
/// (this build's identity), with the reviewer and the `against` surrogates.
type Reviews = BTreeMap<u64, (u64, Vec<u64>)>;

fn outcome<T>(r: &Result<T, Refusal>) -> Option<&'static str> {
    r.as_ref().err().map(|r| r.code)
}

#[test]
fn attestations_on_the_real_kernel_agree_with_the_oracle() {
    let law = Law::embedded().expect("registries");
    let mut totals: BTreeMap<&'static str, usize> = BTreeMap::new();
    for seed in [
        0x9e37_79b9_7f4a_7c15_u64,
        0xd1b5_4a32_d192_ed03,
        0x8cb9_2ba7_2f3d_8dd7,
    ] {
        let mut rng = Rng(seed);
        let mut b = book();
        // The oracle's book: surrogate → document, and the kernel's handle.
        let mut docs: BTreeMap<u64, Doc> = BTreeMap::new();
        let mut handles: BTreeMap<u64, EvidenceRef> = BTreeMap::new();
        let mut reviews: Reviews = BTreeMap::new();
        // Proposals the preparer asserted over, with the reason, to post later.
        let mut asserted: Vec<(EntryPayload, Vec<Citation>, u16)> = Vec::new();
        let mut seen: BTreeMap<&'static str, usize> = BTreeMap::new();
        let book_id = b.book.book_id;
        let ghost = |n: u64| Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: VId(7),
            bytes: format!("never recorded {n}").into_bytes(),
        };
        let kinds: Vec<(u8, String)> = ["Invoice", "Memo", "Rate"]
            .iter()
            .map(|k| (law.policy.kind_by_name(k).unwrap().tag, (*k).to_string()))
            .collect();
        let grades: Vec<(u8, String)> = ["HumanUpload", "AgentUpload"]
            .iter()
            .map(|g| (law.policy.grade_by_name(g).unwrap().tag, (*g).to_string()))
            .collect();

        for step in 0..240u64 {
            let roll = rng.below(100);
            if roll < 22 || docs.len() < 2 {
                // Intake.
                let (kind, kind_name) = rng.pick(&kinds).clone();
                let (grade, grade_name) = rng.pick(&grades).clone();
                let uploader = *rng.pick(&PRINCIPALS);
                let doc = Document {
                    book_id: b.book.book_id,
                    kind,
                    mime: "text/plain".into(),
                    grade,
                    retrieved_by: VId(u128::from(uploader)),
                    bytes: format!("{kind_name} {seed:x}/{step}").into_bytes(),
                };
                b.add(&doc).expect("intake of a registered kind and grade");
                let id = step + 1;
                docs.insert(
                    id,
                    Doc {
                        kind: kind_name,
                        grade: grade_name,
                        commit: doc.doc_commit(),
                        uploader,
                        custody: Custody::uploaded(),
                    },
                );
                handles.insert(id, doc.evidence_ref(1));
                *seen.entry("intake").or_default() += 1;
            } else if roll < 50 {
                // A review: of a held document (sometimes one already
                // reviewed), or of one never recorded; compared against
                // nothing, a held document, or one never recorded.
                let held: Vec<u64> = docs.keys().copied().collect();
                let (subject, subject_oid) = if rng.below(8) == 0 {
                    (u64::MAX - step, ghost(step).oid())
                } else {
                    let id = *rng.pick(&held);
                    (id, handles[&id].document_oid)
                };
                let mut against: Vec<(Oid, u64)> = match rng.below(4) {
                    0 => {
                        let id = *rng.pick(&held);
                        vec![(handles[&id].document_oid, id)]
                    }
                    1 if rng.below(2) == 0 => {
                        vec![(ghost(step + 10_000).oid(), u64::MAX - step - 10_000)]
                    }
                    _ => Vec::new(),
                };
                against.retain(|(oid, _)| *oid != subject_oid);
                let reviewer = *rng.pick(&PRINCIPALS);
                let against_ids: Vec<u64> = against.iter().map(|(_, id)| *id).collect();
                let law_says = review_verdict(&docs, subject, &against_ids, reviewer);
                let expected = match (law_says, reviews.get(&subject)) {
                    (Some(code), _) => Some(code),
                    (None, Some((r, a))) if *r == reviewer && *a == against_ids => None,
                    (None, Some(_)) => Some("FA-REF-032"),
                    (None, None) => None,
                };
                let got = b.review(
                    reviewer,
                    subject_oid,
                    against.iter().map(|(oid, _)| *oid).collect(),
                );
                assert_eq!(
                    outcome(&got),
                    expected,
                    "seed {seed:x} step {step}: review of {subject} by {reviewer} against {against_ids:?}: {got:?}"
                );
                match expected {
                    None => {
                        reviews.entry(subject).or_insert((reviewer, against_ids));
                        *seen.entry("review recorded").or_default() += 1;
                    }
                    Some(code) => *seen.entry(code).or_default() += 1,
                }
            } else if roll < 64 {
                // An assertion over a fresh proposal, of a class that may or
                // may not admit one, with a reason that may not be registered.
                let class = *rng.pick(&[
                    EntryClass::ORIGINAL,
                    EntryClass::ADJUSTING,
                    EntryClass::PENDING,
                    EntryClass::REVALUATION,
                ]);
                let reason = *rng.pick(&[1u16, 2, 3, 4, 5, 0, 6, 999]);
                // An assertion says no document exists: most such proposals
                // cite nothing; some cite what they have anyway.
                let (evidence, citations) = if rng.below(10) < 7 {
                    (Vec::new(), Vec::new())
                } else {
                    cite(&mut rng, &docs, &handles, step)
                };
                let key = format!("m-{seed:x}-{step}");
                let proposal = b.proposal(class, key.as_bytes(), evidence);
                let class_name = class.name().unwrap();
                let expected = manual_verdict(&law, class_name, reason);
                let got = b.assert_manually(&proposal, reason, u8::try_from(step % 251).unwrap());
                assert_eq!(
                    outcome(&got),
                    expected,
                    "seed {seed:x} step {step}: assertion over {class_name} with reason {reason}: {got:?}"
                );
                match expected {
                    None => {
                        asserted.push((proposal, citations, reason));
                        *seen.entry("assertion recorded").or_default() += 1;
                    }
                    Some(code) => *seen.entry(code).or_default() += 1,
                }
            } else {
                // A post: an asserted proposal (half the time, when there is
                // one) or a fresh one citing a random selection.
                let (proposal, citations, manual) = if !asserted.is_empty() && rng.below(3) != 0 {
                    let i =
                        usize::try_from(rng.below(u64::try_from(asserted.len()).unwrap())).unwrap();
                    let (p, c, reason) = asserted.swap_remove(i);
                    (p, c, Some(reason))
                } else {
                    let class = *rng.pick(&[EntryClass::ORIGINAL, EntryClass::ADJUSTING]);
                    // Steer a share of posts at an agent upload another
                    // principal reviewed, so the review path is reached.
                    let promoted: Vec<u64> = reviews
                        .keys()
                        .copied()
                        .filter(|d| docs[d].grade == "AgentUpload")
                        .collect();
                    let (evidence, citations) = if !promoted.is_empty() && rng.below(4) == 0 {
                        let id = *rng.pick(&promoted);
                        let e = handles[&id];
                        let c = Citation {
                            doc: id,
                            commit: e.doc_commit,
                            role: e.role,
                        };
                        (vec![e], vec![c])
                    } else {
                        cite(&mut rng, &docs, &handles, step)
                    };
                    let key = format!("p-{seed:x}-{step}");
                    (b.proposal(class, key.as_bytes(), evidence), citations, None)
                };
                let class_name = proposal.class.name().unwrap();
                let attestations = Attestations {
                    reviews: reviews.iter().map(|(d, (r, _))| (*d, *r)).collect(),
                    manual,
                };
                let expected = verdict(&law, class_name, &docs, &citations, &attestations);
                let got = b.post(proposal);
                assert_eq!(
                    outcome(&got),
                    expected,
                    "seed {seed:x} step {step}: post of {class_name} citing {citations:?} with {attestations:?}: {got:?}"
                );
                match expected {
                    None => {
                        assert!(matches!(got, Ok(Posted::Committed { .. })), "{got:?}");
                        let bare = verdict(
                            &law,
                            class_name,
                            &docs,
                            &citations,
                            &Attestations::default(),
                        );
                        let reviews_only = Attestations {
                            manual: None,
                            ..attestations.clone()
                        };
                        let path = if bare.is_none() {
                            "posted on documents"
                        } else if verdict(&law, class_name, &docs, &citations, &reviews_only)
                            .is_none()
                        {
                            "posted on a review"
                        } else {
                            "posted on an assertion"
                        };
                        *seen.entry(path).or_default() += 1;
                    }
                    Some(code) => *seen.entry(code).or_default() += 1,
                }
            }
        }
        eprintln!("evidence-oracle seed {seed:x}: {seen:?}");
        // Floors on every seed: each recording refusal, each posting outcome
        // the history can reach, both attestation paths.
        for key in [
            "FA-REF-080",
            "FA-REF-081",
            "FA-REF-082",
            "FA-REF-086",
            "FA-REF-110",
            "FA-REF-111",
            "FA-REF-112",
            "FA-REF-032",
            "posted on documents",
            "posted on a review",
            "posted on an assertion",
        ] {
            assert!(
                seen.get(key).copied().unwrap_or(0) >= 2,
                "seed {seed:x}: {key} reached {:?} times: {seen:?}",
                seen.get(key)
            );
            *totals.entry(key).or_default() += seen[key];
        }
    }
    eprintln!("evidence-oracle totals: {totals:?}");
}

/// A random citation list (sorted, as the payload requires) and the
/// oracle's view of it in the same order: nothing, held documents, a
/// document never recorded, or a held one under a wrong commitment.
fn cite(
    rng: &mut Rng,
    docs: &BTreeMap<u64, Doc>,
    handles: &BTreeMap<u64, EvidenceRef>,
    step: u64,
) -> (Vec<EvidenceRef>, Vec<Citation>) {
    let held: Vec<u64> = docs.keys().copied().collect();
    let mut chosen: Vec<(EvidenceRef, u64)> = Vec::new();
    match rng.below(10) {
        0 | 1 => {}
        2 => {
            let ghost = Document {
                book_id: Id128([0x5e; 16]),
                kind: 1,
                mime: "text/plain".into(),
                grade: 3,
                retrieved_by: VId(7),
                bytes: format!("never recorded, cited {step}").into_bytes(),
            };
            chosen.push((ghost.evidence_ref(1), u64::MAX - step));
        }
        3 => {
            let id = *rng.pick(&held);
            let mut wrong = handles[&id];
            wrong.doc_commit = [0xee; 32];
            chosen.push((wrong, id));
        }
        n => {
            for _ in 0..1 + n % 2 {
                let id = *rng.pick(&held);
                chosen.push((handles[&id], id));
            }
        }
    }
    chosen.sort_by_key(|a| a.0);
    chosen.dedup_by(|a, b| a.0 == b.0);
    let citations = chosen
        .iter()
        .map(|(e, id)| Citation {
            doc: *id,
            commit: e.doc_commit,
            role: e.role,
        })
        .collect();
    (chosen.into_iter().map(|(e, _)| e).collect(), citations)
}

// ---------------------------------------------------------------------------
// Custody and import receipts on the real substrate (fa-txf)
// ---------------------------------------------------------------------------

impl Book {
    fn import(
        &mut self,
        principal: u64,
        source: fa_model::IntakeSource,
        key: &[u8],
        documents: Vec<Document>,
    ) -> Result<ImportRecorded, Refusal> {
        let ctx = self.ctx();
        let cap = Self::capability(principal);
        let req = ImportRequest {
            principal: VId(u128::from(principal)),
            source,
            idempotency_key: key.to_vec(),
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            description: Erasable::seal(
                &"import".to_string(),
                None,
                &self.book.seal_key,
                [4; 32],
                [4; 24],
            ),
            documents,
        };
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(async move { import_run(db, &ctx, book, &cap, req).await })
            .expect("kernel")
    }

    fn transfer(
        &mut self,
        document: Oid,
        from: u64,
        to: u64,
    ) -> Result<fa_journal::CustodyMoved, Refusal> {
        let ctx = self.ctx();
        let cap = Self::capability(from);
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(async move {
                transfer_custody(
                    db,
                    &ctx,
                    book,
                    &cap,
                    document,
                    VId(u128::from(from)),
                    VId(u128::from(to)),
                )
                .await
            })
            .expect("kernel")
    }

    fn write_raw(&mut self, batch: fgdb::WriteBatch) {
        let ctx = self.ctx();
        let db = &mut self.db;
        self.runtime
            .block_on(async move { db.write(&ctx.commit(), batch).await })
            .expect("raw write");
    }

    /// A planted custody break, written outside every law.
    fn plant(&mut self, plant: &Plant, doc: &Document) {
        use fa_model::symbols::{label, property, relation};
        let scalar = |b: Vec<u8>| fgdb_types::CanonicalScalar::bytes(b).unwrap();
        let mut batch = fgdb::WriteBatch::new(relation::CUSTODY_OF);
        let event = |batch: &mut fgdb::WriteBatch, e: &fa_journal::CustodyEvent| {
            let vid = fa_journal::custody::custody_vid(e.book_id, &e.document_oid, e.index);
            let mut props = vec![
                (property::FA_PAYLOAD, scalar(e.canonical_bytes().unwrap())),
                (property::FA_DIGEST, scalar(e.digest().unwrap().to_vec())),
                (property::BOOK_ID, scalar(e.book_id.0.to_vec())),
            ];
            props.sort_by_key(|(k, _)| k.0);
            let l = if e.index == 0 {
                label::IMPORT_RECEIPT
            } else {
                label::CUSTODY_TRANSFER
            };
            batch.create_vertex(vid, vec![l], props);
        };
        let receipt = fa_journal::CustodyEvent {
            book_id: doc.book_id,
            document_oid: doc.oid(),
            index: 0,
            prev_digest: [0; 32],
            body: fa_journal::CustodyBody::Receipt {
                source: fa_model::IntakeSource::Upload {
                    principal: doc.retrieved_by,
                },
                received_by: doc.retrieved_by,
                digest_at_receipt: doc.doc_commit(),
                run_ref: None,
            },
        };
        let set_len = |batch: &mut fgdb::WriteBatch, n: i64| {
            batch.set_vertex_property(
                fa_journal::evidence::document_vid(&doc.oid()),
                property::CUSTODY_LEN,
                Some(fgdb_types::CanonicalScalar::Int(n)),
            );
        };
        match plant {
            // The document exists already (an upload); its chain is broken.
            Plant::Gap => set_len(&mut batch, 2),
            Plant::Unchained => {
                event(
                    &mut batch,
                    &fa_journal::CustodyEvent {
                        index: 1,
                        prev_digest: [0xab; 32],
                        body: fa_journal::CustodyBody::Transfer {
                            from: doc.retrieved_by,
                            to: VId(9),
                        },
                        ..receipt.clone()
                    },
                );
                set_len(&mut batch, 2);
            }
            Plant::NotHolder => {
                event(
                    &mut batch,
                    &fa_journal::CustodyEvent {
                        index: 1,
                        prev_digest: receipt.digest().unwrap(),
                        body: fa_journal::CustodyBody::Transfer {
                            from: VId(99),
                            to: VId(9),
                        },
                        ..receipt.clone()
                    },
                );
                set_len(&mut batch, 2);
            }
        }
        self.write_raw(batch);
    }
}

/// The custody breaks the differential plants on an uploaded document.
#[derive(Clone, Copy, Debug)]
enum Plant {
    /// `custody_len` says 2; link 1 was never written.
    Gap,
    /// Link 1 does not chain to the receipt.
    Unchained,
    /// Link 1 is a transfer by a principal that did not hold the document.
    NotHolder,
}

fn oracle_source(s: &fa_model::IntakeSource) -> fa_reference::evidence::Source {
    use fa_model::IntakeSource as K;
    use fa_reference::evidence::Source as O;
    match s {
        K::Upload { .. } => O::Upload,
        K::Connector { name, version } => O::Connector {
            name: name.clone(),
            version: version.clone(),
        },
        K::Email { message_id } => O::Email {
            message_id: message_id.clone(),
        },
        K::Scan { device } => O::Scan {
            device: device.clone(),
        },
    }
}

#[test]
fn custody_and_import_receipts_on_the_real_kernel_agree_with_the_oracle() {
    use fa_model::IntakeSource;
    use fa_reference::evidence::{Event, intake_verdict, receipt_verdict, transfer_verdict};
    let law = Law::embedded().expect("registries");
    let sources = [
        IntakeSource::Connector {
            name: "fa-import".into(),
            version: "1".into(),
        },
        IntakeSource::Connector {
            name: "bank-feed".into(),
            version: "1".into(),
        },
        IntakeSource::Email {
            message_id: "<run@example>".into(),
        },
        IntakeSource::Scan {
            device: "office-scanner".into(),
        },
    ];
    let mut totals: BTreeMap<&'static str, usize> = BTreeMap::new();
    for seed in [
        0x51ed_2701_8b3c_4d19_u64,
        0x2545_f491_4f6c_dd1d,
        0x9e37_79b9_7f4a_7c15,
    ] {
        let mut rng = Rng(seed);
        let mut b = book();
        let mut docs: BTreeMap<u64, Doc> = BTreeMap::new();
        let mut handles: BTreeMap<u64, (Document, EvidenceRef)> = BTreeMap::new();
        let mut holders: BTreeMap<u64, u64> = BTreeMap::new();
        let mut runs: Vec<(RunReceipt, std::collections::BTreeSet<[u8; 32]>)> = Vec::new();
        let mut seen: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut next_id = 1u64;
        let mut new_doc = |rng: &mut Rng, book_id, step: u64| -> Document {
            next_id += 1;
            Document {
                book_id,
                kind: 1,
                mime: "text/plain".into(),
                grade: 3,
                retrieved_by: VId(u128::from(*rng.pick(&PRINCIPALS))),
                bytes: format!("INVOICE {seed:x}/{step}/{next_id}").into_bytes(),
            }
        };
        let book_id = b.book.book_id;
        for step in 0..220u64 {
            let roll = rng.below(100);
            if roll < 20 || docs.is_empty() {
                // An upload.
                let doc = new_doc(&mut rng, book_id, step);
                b.add(&doc)
                    .expect("an upload of a registered kind and grade");
                let id = step + 1_000;
                docs.insert(
                    id,
                    Doc {
                        kind: "Invoice".into(),
                        grade: "HumanUpload".into(),
                        commit: doc.doc_commit(),
                        uploader: u64::try_from(doc.retrieved_by.0).unwrap(),
                        custody: Custody::uploaded(),
                    },
                );
                holders.insert(id, u64::try_from(doc.retrieved_by.0).unwrap());
                let e = doc.evidence_ref(1);
                handles.insert(id, (doc, e));
                *seen.entry("upload").or_default() += 1;
            } else if roll < 35 {
                // An import run from a registered or unregistered source.
                let source = rng.pick(&sources).clone();
                let n = 1 + rng.below(3);
                let principal = *rng.pick(&PRINCIPALS);
                // An import run's documents are retrieved by the principal
                // that runs it: the kernel binds retrieved_by to the acting
                // capability's holder (FA-REF-011 otherwise; planted below).
                let batch: Vec<Document> = (0..n)
                    .map(|_| {
                        let mut doc = new_doc(&mut rng, book_id, step);
                        doc.retrieved_by = VId(u128::from(principal));
                        doc
                    })
                    .collect();
                let expected = intake_verdict(&law, &oracle_source(&source));
                if expected.is_none() && step % 7 == 0 {
                    let mut foreign = batch.clone();
                    let other = PRINCIPALS
                        .into_iter()
                        .find(|p| *p != principal)
                        .expect("three principals");
                    foreign[0].retrieved_by = VId(u128::from(other));
                    let refused = b.import(
                        principal,
                        source.clone(),
                        format!("foreign-{seed:x}-{step}").as_bytes(),
                        foreign,
                    );
                    assert_eq!(
                        outcome(&refused),
                        Some("FA-REF-011"),
                        "seed {seed:x} step {step}: a document retrieved by another principal: {refused:?}"
                    );
                    *seen.entry("import-foreign-refused").or_default() += 1;
                }
                let key = format!("run-{seed:x}-{step}");
                let got = b.import(principal, source.clone(), key.as_bytes(), batch.clone());
                assert_eq!(
                    outcome(&got),
                    expected,
                    "seed {seed:x} step {step}: import from {source:?}: {got:?}"
                );
                match got {
                    Ok(run) => {
                        for (i, doc) in batch.iter().enumerate() {
                            let id = step * 10 + u64::try_from(i).unwrap() + 100_000;
                            let mut custody = Custody::uploaded();
                            custody.events.insert(
                                0,
                                Event::Receipt {
                                    source: oracle_source(&source),
                                    digest_matches: true,
                                },
                            );
                            docs.insert(
                                id,
                                Doc {
                                    kind: "Invoice".into(),
                                    grade: "HumanUpload".into(),
                                    commit: doc.doc_commit(),
                                    uploader: u64::try_from(doc.retrieved_by.0).unwrap(),
                                    custody,
                                },
                            );
                            holders.insert(id, principal);
                            let e = doc.evidence_ref(1);
                            handles.insert(id, (doc.clone(), e));
                        }
                        let set = batch.iter().map(|d| d.oid().0).collect();
                        runs.push((run.receipt, set));
                        *seen.entry("import recorded").or_default() += 1;
                    }
                    Err(r) => *seen.entry(r.code).or_default() += 1,
                }
            } else if roll < 50 {
                // A transfer, by the holder or by someone else.
                let ids: Vec<u64> = docs.keys().copied().collect();
                let id = *rng.pick(&ids);
                let holder = holders[&id];
                let from = if rng.below(3) == 0 {
                    *rng.pick(&PRINCIPALS)
                } else {
                    holder
                };
                let to = *rng.pick(&[7u64, 8, 9, 10]);
                if from == to {
                    continue;
                }
                // A broken chain refuses every transfer before the holder
                // check; the oracle says so first.
                let expected = if law.custody_complete(&docs[&id].custody) {
                    transfer_verdict(holder, from)
                } else {
                    Some(fa_reference::evidence::CUSTODY_INCOMPLETE)
                };
                let oid = handles[&id].1.document_oid;
                let got = b.transfer(oid, from, to);
                assert_eq!(
                    outcome(&got),
                    expected,
                    "seed {seed:x} step {step}: transfer of {id} {from}->{to} (holder {holder}): {got:?}"
                );
                if got.is_ok() {
                    let custody = &mut docs.get_mut(&id).unwrap().custody;
                    let index = custody.len;
                    custody.events.insert(
                        index,
                        Event::Transfer {
                            chained: true,
                            from_holder: true,
                        },
                    );
                    custody.len += 1;
                    holders.insert(id, to);
                    *seen.entry("transfer recorded").or_default() += 1;
                } else if let Some(code) = expected {
                    *seen.entry(code).or_default() += 1;
                }
            } else if roll < 58 {
                // A planted break on an intact, single-receipt document.
                let ids: Vec<u64> = docs
                    .iter()
                    .filter(|(_, d)| d.custody == Custody::uploaded())
                    .map(|(id, _)| *id)
                    .collect();
                if ids.is_empty() {
                    continue;
                }
                let id = *rng.pick(&ids);
                let plant = *rng.pick(&[Plant::Gap, Plant::Unchained, Plant::NotHolder]);
                b.plant(&plant, &handles[&id].0.clone());
                let custody = &mut docs.get_mut(&id).unwrap().custody;
                custody.len = 2;
                match plant {
                    Plant::Gap => {}
                    Plant::Unchained => {
                        custody.events.insert(
                            1,
                            Event::Transfer {
                                chained: false,
                                from_holder: true,
                            },
                        );
                    }
                    Plant::NotHolder => {
                        custody.events.insert(
                            1,
                            Event::Transfer {
                                chained: true,
                                from_holder: false,
                            },
                        );
                    }
                }
                *seen.entry("planted").or_default() += 1;
            } else if roll < 68 && !runs.is_empty() {
                // A receipt checked against the run's list or a tampered one.
                let i = usize::try_from(rng.below(u64::try_from(runs.len()).unwrap())).unwrap();
                let (receipt, set) = &runs[i];
                let mut presented: Vec<[u8; 32]> = set.iter().copied().collect();
                match rng.below(4) {
                    0 => {}
                    1 => presented[0][0] ^= 1,
                    2 => {
                        presented.pop();
                    }
                    _ => presented.push([0xee; 32]),
                }
                let expected = receipt_verdict(set, &presented);
                let oids: Vec<Oid> = presented.iter().map(|o| Oid(*o)).collect();
                let got = verify_receipt(receipt, book_id, &oids);
                assert_eq!(
                    got.as_ref().err().map(|r| r.code),
                    expected,
                    "seed {seed:x} step {step}: receipt check"
                );
                *seen
                    .entry(expected.unwrap_or("receipt verified"))
                    .or_default() += 1;
            } else {
                // A post citing one document.
                let ids: Vec<u64> = docs.keys().copied().collect();
                let id = *rng.pick(&ids);
                let e = handles[&id].1;
                let citations = vec![Citation {
                    doc: id,
                    commit: e.doc_commit,
                    role: e.role,
                }];
                let expected = verdict(
                    &law,
                    "Original",
                    &docs,
                    &citations,
                    &Attestations::default(),
                );
                let key = format!("p-{seed:x}-{step}");
                let got = b.post(b.proposal(EntryClass::ORIGINAL, key.as_bytes(), vec![e]));
                assert_eq!(
                    outcome(&got),
                    expected,
                    "seed {seed:x} step {step}: post citing {id}: {got:?}"
                );
                *seen.entry(expected.unwrap_or("posted")).or_default() += 1;
            }
        }
        eprintln!("custody-oracle seed {seed:x}: {seen:?}");
        for key in [
            "FA-REF-083",
            "FA-REF-114",
            "FA-REF-115",
            "FA-REF-119",
            "import recorded",
            "transfer recorded",
            "receipt verified",
            "posted",
            "planted",
        ] {
            assert!(
                seen.get(key).copied().unwrap_or(0) >= 2,
                "seed {seed:x}: {key} reached {:?} times: {seen:?}",
                seen.get(key)
            );
            *totals.entry(key).or_default() += seen[key];
        }
    }
    eprintln!("custody-oracle totals: {totals:?}");
}

// ---------------------------------------------------------------------------
// External storage on the real substrate (fa-txf part B)
// ---------------------------------------------------------------------------

#[test]
fn every_read_of_an_external_document_agrees_with_a_literal_model() {
    use fa_journal::BlobStore;
    use fa_journal::evidence::{add_document_external, fetch_document};
    let mut totals: BTreeMap<&'static str, usize> = BTreeMap::new();
    for seed in [0x1234_5678_9abc_def1_u64, 0x0fed_cba9_8765_4321] {
        let mut rng = Rng(seed);
        let mut b = book();
        let open_store = |path: &str| {
            let directory = b
                .runtime
                .block_on(fa_journal::blob::DurableDirectory::create(
                    &b.ctx().commit(),
                    fgdb::MemVfs::new().unwrap(),
                    std::path::Path::new(path),
                ))
                .unwrap();
            BlobStore::open(1, directory).unwrap()
        };
        let store = open_store("blobs");
        let decoy = open_store("decoy");
        // The model: per document, its bytes, whether they are external, and
        // whether its blob currently holds other bytes.
        let mut model: Vec<(Document, bool, bool)> = Vec::new();
        let mut seen: BTreeMap<&'static str, usize> = BTreeMap::new();
        for step in 0..120u64 {
            let roll = rng.below(100);
            if roll < 30 || model.is_empty() {
                let external = rng.below(2) == 0;
                let doc = Document {
                    book_id: b.book.book_id,
                    kind: 1,
                    mime: "text/plain".into(),
                    grade: 3,
                    retrieved_by: VId(7),
                    bytes: format!("INVOICE {seed:x}/{step} ")
                        .repeat(1 + usize::try_from(rng.below(40)).unwrap())
                        .into_bytes(),
                };
                let ctx = b.ctx();
                let (db, book) = (&mut b.db, &b.book);
                let added = if external {
                    b.runtime.block_on(async {
                        add_document_external(db, &ctx, book, &store, &doc).await
                    })
                } else {
                    b.runtime
                        .block_on(async { add_document(db, &ctx, book, &doc).await })
                };
                added.expect("kernel").expect("intake");
                model.push((doc, external, false));
                *seen
                    .entry(if external { "external" } else { "inline" })
                    .or_default() += 1;
            } else if roll < 45 {
                // Change, or restore, an external document's blob.
                let externals: Vec<usize> = (0..model.len()).filter(|i| model[*i].1).collect();
                if externals.is_empty() {
                    continue;
                }
                let i = externals
                    [usize::try_from(rng.below(u64::try_from(externals.len()).unwrap())).unwrap()];
                let (doc, _, changed) = &mut model[i];
                let locator = fa_journal::blob::locator_of(&doc.doc_commit());
                let bytes = if *changed {
                    doc.bytes.clone()
                } else {
                    let mut x = doc.bytes.clone();
                    x[0] ^= 0x01;
                    x
                };
                b.runtime
                    .block_on(async { store.put(&b.ctx().commit(), &locator, &bytes).await })
                    .expect("blob write");
                *changed = !*changed;
            } else {
                // A read, from the book's store or from a decoy that holds nothing.
                let i = usize::try_from(rng.below(u64::try_from(model.len()).unwrap())).unwrap();
                let (doc, external, changed) = &model[i];
                let use_decoy = rng.below(3) == 0;
                let expected: Option<&'static str> = match (external, use_decoy, changed) {
                    (false, _, _) => None,
                    (true, true, _) => Some("FA-REF-116"),
                    (true, false, true) => Some("FA-REF-085"),
                    (true, false, false) => None,
                };
                let ctx = b.ctx();
                let db = &b.db;
                let from = if use_decoy { &decoy } else { &store };
                let oid = doc.oid();
                let got = b
                    .runtime
                    .block_on(async { fetch_document(db, &ctx, from, &oid).await })
                    .expect("kernel");
                assert_eq!(
                    got.as_ref().err().map(|r| r.code),
                    expected,
                    "seed {seed:x} step {step}: read of {i} (external {external}, decoy {use_decoy}, changed {changed}): {got:?}"
                );
                if expected.is_none() {
                    assert_eq!(got.unwrap(), Some(doc.clone()), "seed {seed:x} step {step}");
                }
                *seen
                    .entry(expected.unwrap_or(if *external {
                        "external read"
                    } else {
                        "inline read"
                    }))
                    .or_default() += 1;
            }
        }
        eprintln!("txf external seed {seed:x}: {seen:?}");
        for key in ["external read", "inline read", "FA-REF-085", "FA-REF-116"] {
            assert!(
                seen.get(key).copied().unwrap_or(0) >= 3,
                "seed {seed:x}: {key} reached {:?}: {seen:?}",
                seen.get(key)
            );
            *totals.entry(key).or_default() += seen[key];
        }
    }
    eprintln!("txf external totals: {totals:?}");
}

impl Book {
    fn place_hold(
        &mut self,
        subjects: Vec<VId>,
        authority: Oid,
        key: &[u8],
    ) -> Result<LegalHoldPlaced, Refusal> {
        let ctx = self.ctx();
        let cap = Capability::embedded(VId(u128::from(PREPARER)), &["hold"]).expect("hold");
        let req = LegalHoldRequest {
            principal: VId(u128::from(PREPARER)),
            reach: HoldReach::Subjects(subjects),
            authority,
            effective_date: DateDay::from_ymd(2026, 3, 20).unwrap(),
            idempotency_key: key.to_vec(),
            description: Erasable::seal(
                &"legal hold".to_string(),
                None,
                &self.book.seal_key,
                [31; 32],
                [31; 24],
            ),
        };
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(async move { place_legal_hold(db, &ctx, book, &cap, req).await })
            .expect("kernel")
    }

    /// Plan, optionally approve (by principal 8, a Human other than the
    /// preparer), and commit a release of `hold`.
    fn release_hold(&mut self, hold: VId, key: &[u8], approve: bool) -> Result<VId, Refusal> {
        let description = Erasable::seal(
            &"hold release".to_string(),
            None,
            &self.book.seal_key,
            [32; 32],
            [32; 24],
        );
        let plan = plan_release(
            &self.db,
            &self.book,
            hold,
            VId(u128::from(PREPARER)),
            DateDay::from_ymd(2026, 3, 25).unwrap(),
            key,
            description,
        )
        .expect("kernel")?;
        let mut approvals = Vec::new();
        if approve {
            let ctx = self.ctx();
            let req = ApprovalRequest {
                capability: Self::capability(8),
                approved_proposal_digest: plan.proposal_digest(&self.book).unwrap(),
                role: 0,
            };
            let (db, book) = (&mut self.db, &self.book);
            let approved = self
                .runtime
                .block_on(async move { record_approval(db, &ctx, book, req).await })
                .expect("kernel")
                .expect("an approval");
            approvals.push(approved.approval());
        }
        let ctx = self.ctx();
        let cap = Capability::embedded(VId(u128::from(PREPARER)), &["hold"]).expect("hold");
        let (db, book) = (&mut self.db, &self.book);
        self.runtime
            .block_on(
                async move { release_legal_hold(db, &ctx, book, &cap, &plan, &approvals).await },
            )
            .expect("kernel")
            .map(|r| r.release)
    }

    fn erase(&self, subject: VId) -> Refusal {
        let cap = Capability::embedded(VId(u128::from(PREPARER)), &["erase"]).expect("erase");
        fa_journal::evidence::erasure_cut(&self.db, &self.book, &cap, subject).expect("kernel")
    }
}

/// Legal holds (fa-txf, plan §8.5) against a literal model: per hold its
/// subject set and whether it is released; a subject is pinned exactly while
/// some unreleased hold names it. Every placement, release and erasure on
/// the real kernel agrees with the model, step by step, and at the end every
/// subject's active holds and every hold's release state agree too.
#[test]
fn legal_holds_on_the_real_kernel_agree_with_a_literal_model() {
    use std::collections::BTreeSet;
    let mut totals: BTreeMap<&'static str, usize> = BTreeMap::new();
    for seed in [0x51de_cafe_0bad_f00d_u64, 0x2468_ace0_1357_9bdf] {
        let mut rng = Rng(seed);
        let mut b = book();
        let authority = Document {
            book_id: b.book.book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: VId(7),
            bytes: format!("PRESERVATION ORDER {seed:x}").into_bytes(),
        };
        b.add(&authority).expect("admitted");
        // Holdable subjects: documents and posted entries.
        let mut pool: Vec<VId> = Vec::new();
        for i in 0..6u64 {
            let doc = Document {
                bytes: format!("INVOICE {seed:x}/{i}").into_bytes(),
                ..authority.clone()
            };
            let added = b.add(&doc).expect("admitted");
            pool.push(added.vid);
            if i < 3 {
                let proposal = b.proposal(
                    EntryClass::ORIGINAL,
                    format!("entry-{i}").as_bytes(),
                    vec![doc.evidence_ref(1)],
                );
                pool.push(b.post(proposal).expect("posted").entry_ref().vid);
            }
        }
        // Not holdable: a vid the book never wrote, and the book's root.
        let bogus = [VId(0xdead_beef), fa_journal::rows::book_root()];
        // The model: hold -> (subjects, released).
        let mut model: BTreeMap<u128, (BTreeSet<u128>, bool)> = BTreeMap::new();
        let active = |model: &BTreeMap<u128, (BTreeSet<u128>, bool)>, s: VId| -> Vec<VId> {
            model
                .iter()
                .filter(|(_, (subjects, released))| !released && subjects.contains(&s.0))
                .map(|(h, _)| VId(*h))
                .collect()
        };
        let mut seen: BTreeMap<&'static str, usize> = BTreeMap::new();
        for step in 0..150u64 {
            let roll = rng.below(100);
            if roll < 40 {
                let n = 1 + rng.below(4);
                let mut subjects: Vec<VId> = (0..n).map(|_| *rng.pick(&pool)).collect();
                let twist = rng.below(10);
                if twist == 0 {
                    subjects.push(*rng.pick(&bogus));
                }
                if twist == 1 {
                    subjects.clear();
                }
                let mut set: BTreeSet<u128> = BTreeSet::new();
                let repeated = !subjects.iter().all(|s| set.insert(s.0));
                let expected: Option<&'static str> = if subjects.is_empty() || repeated {
                    Some("FA-REF-100")
                } else if subjects.iter().any(|s| bogus.contains(s)) {
                    Some("FA-REF-141")
                } else {
                    None
                };
                let key = format!("hold-{step}");
                let got = b.place_hold(subjects.clone(), authority.oid(), key.as_bytes());
                assert_eq!(
                    outcome(&got),
                    expected,
                    "seed {seed:x} step {step}: place {subjects:?}: {got:?}"
                );
                if let Ok(placed) = got {
                    assert_eq!(
                        placed.subjects,
                        set.iter().map(|s| VId(*s)).collect::<Vec<_>>(),
                        "seed {seed:x} step {step}: the scope is the set, ascending"
                    );
                    assert!(model.insert(placed.hold.0, (set, false)).is_none());
                }
                *seen.entry(expected.unwrap_or("placed")).or_default() += 1;
            } else if roll < 65 {
                // Release a hold (active or not), or something that is none.
                let target = if model.is_empty() || rng.below(6) == 0 {
                    *rng.pick(&pool)
                } else {
                    let holds: Vec<u128> = model.keys().copied().collect();
                    VId(*rng.pick(&holds))
                };
                let approve = rng.below(5) != 0;
                let expected = match model.get(&target.0) {
                    None | Some((_, true)) => Some("FA-REF-118"),
                    Some((_, false)) if !approve => Some("FA-REF-012"),
                    Some((_, false)) => None,
                };
                let key = format!("release-{step}");
                let got = b.release_hold(target, key.as_bytes(), approve);
                assert_eq!(
                    outcome(&got),
                    expected,
                    "seed {seed:x} step {step}: release {target:?} (approved {approve}): {got:?}"
                );
                if got.is_ok() {
                    model.get_mut(&target.0).expect("a modelled hold").1 = true;
                }
                *seen.entry(expected.unwrap_or("released")).or_default() += 1;
            } else if roll < 90 {
                let subject = if rng.below(4) == 0 {
                    *rng.pick(&bogus)
                } else {
                    *rng.pick(&pool)
                };
                let holds = active(&model, subject);
                let expected = if holds.is_empty() {
                    "FA-REF-088"
                } else {
                    "FA-REF-117"
                };
                let r = b.erase(subject);
                assert_eq!(
                    r.code, expected,
                    "seed {seed:x} step {step}: erasure of {subject:?} under {holds:?}: {r}"
                );
                for h in &holds {
                    assert!(r.message.contains(&format!("{:032x}", h.0)), "{r}");
                }
                *seen.entry(expected).or_default() += 1;
            } else {
                let subject = *rng.pick(&pool);
                assert_eq!(
                    active_legal_holds(&b.db, b.book.book_id, subject).unwrap(),
                    active(&model, subject),
                    "seed {seed:x} step {step}: active holds on {subject:?}"
                );
                *seen.entry("cell read").or_default() += 1;
            }
        }
        for subject in pool.iter().chain(&bogus) {
            assert_eq!(
                active_legal_holds(&b.db, b.book.book_id, *subject).unwrap(),
                active(&model, *subject),
                "seed {seed:x}: final holds on {subject:?}"
            );
        }
        for (hold, (subjects, released)) in &model {
            let read = read_legal_hold(&b.db, b.book.book_id, VId(*hold))
                .unwrap()
                .expect("a placed hold");
            assert_eq!(
                read.subjects,
                subjects.iter().map(|s| VId(*s)).collect::<Vec<_>>()
            );
            assert_eq!(read.released.is_some(), *released, "seed {seed:x}");
        }
        eprintln!("txf hold seed {seed:x}: {seen:?}");
        for key in [
            "placed",
            "released",
            "FA-REF-117",
            "FA-REF-088",
            "FA-REF-118",
        ] {
            assert!(
                seen.get(key).copied().unwrap_or(0) >= 3,
                "seed {seed:x}: {key} reached {:?}: {seen:?}",
                seen.get(key)
            );
        }
        for (key, n) in seen {
            *totals.entry(key).or_default() += n;
        }
    }
    eprintln!("txf hold totals: {totals:?}");
    for key in ["FA-REF-100", "FA-REF-141", "FA-REF-012", "cell read"] {
        assert!(
            totals.get(key).copied().unwrap_or(0) >= 1,
            "{key} never reached: {totals:?}"
        );
    }
}

/// Every control record in `db`, its kind checked against the oracle's
/// literal copy of the registry (fa-g23): the class the kind mints is the
/// record's class. Returns the count per kind; logs each origin.
fn control_kinds_in(db: &Database<MemVfs>) -> BTreeMap<u16, usize> {
    let mut seen: BTreeMap<u16, usize> = BTreeMap::new();
    for row in db.vertices().expect("scan") {
        if !row.labels.contains(&fa_model::symbols::label::ENTRY) {
            continue;
        }
        let (entry, _) = fa_journal::post::read_entry(db, row.vid)
            .expect("kernel")
            .expect("an entry");
        if let EntryOrigin::Control {
            control_kind,
            spec_body_digest,
        } = &entry.proposal.origin
        {
            let class = entry.proposal.class.name().expect("a registered class");
            eprintln!(
                "g23 control record {:032x}: control_kind {} ({}) on {class}, spec_body_digest {}",
                row.vid.0,
                control_kind.id(),
                control_kind.name(),
                fa_journal::evidence::hex(spec_body_digest)
            );
            assert_eq!(
                fa_reference::control_kind_class(control_kind.id()),
                Some(class),
                "control record {:032x}",
                row.vid.0
            );
            *seen.entry(control_kind.id()).or_default() += 1;
        }
    }
    seen
}

/// fa-g23, the positive half: on a fresh book, every control record the
/// kernel mints (chart install, period transitions, a tick, a capability
/// revocation, an import run, a legal hold and its release) carries the
/// registry's number for its kind.
#[test]
fn every_control_record_carries_its_registered_kind() {
    let mut b = book();
    let seal = |b: &Book, text: &str, n: u8| {
        Erasable::seal(&text.to_string(), None, &b.book.seal_key, [n; 32], [n; 24])
    };
    let tick = TickRequest {
        observed_utc_ns: 1_000,
        source: fa_journal::sweep::SOURCE_DAEMON_CLOCK,
        monotonic_ok: true,
        principal_ref: VId(7),
        capability: Capability::embedded(VId(7), &["witness"]).expect("witness"),
        idempotency_key: b"g23-tick".to_vec(),
        description: seal(&b, "tick", 41),
    };
    let revoked = Capability::embedded(VId(9), &["post"]).expect("post");
    let revocation = RevocationRequest {
        capability: Capability::embedded(VId(7), &["issue_capability"]).expect("issue"),
        revoked: revoked.commitment().expect("commitment"),
        effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
        idempotency_key: b"g23-revoke".to_vec(),
        description: seal(&b, "revocation", 42),
    };
    let ctx = b.ctx();
    let (db, book) = (&mut b.db, &b.book);
    b.runtime.block_on(async {
        record_tick(db, &ctx, book, tick)
            .await
            .expect("kernel")
            .expect("tick");
        revoke_capability(db, &ctx, book, revocation)
            .await
            .expect("kernel")
            .expect("revoked");
    });
    let imported = Document {
        book_id: b.book.book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: VId(7),
        bytes: b"INVOICE (g23 import fixture)".to_vec(),
    };
    let imported_oid = imported.oid();
    b.import(
        7,
        fa_model::IntakeSource::Connector {
            name: "fa-import".into(),
            version: "1".into(),
        },
        b"g23-import",
        vec![imported],
    )
    .expect("an import run");
    let held = b
        .place_hold(
            vec![fa_journal::evidence::document_vid(&imported_oid)],
            imported_oid,
            b"g23-hold",
        )
        .expect("placed");
    b.release_hold(held.hold, b"g23-release", true)
        .expect("released");
    let seen = control_kinds_in(&b.db);
    eprintln!("g23 control kinds on a fresh book: {seen:?}");
    for kind in [1, 2, 4, 6, 7, 8] {
        assert!(seen.contains_key(&kind), "kind {kind} minted: {seen:?}");
    }
}

/// fa-vwf: capability-bound `upload_document` derives provenance grade from
/// `(intake source = Upload, capability.profile())`, refuses any mismatched
/// `--grade` assertion (`FA-REF-084`), preserves an earlier `AgentUpload`
/// grade and uploader on a later Human re-upload of the same bytes, and agrees
/// with `fa_reference::evidence` across reviews and postings on 4 seeds.
#[test]
fn capability_bound_uploads_derive_grade_from_profile_and_agree_with_the_oracle() {
    use fa_journal::upload::{UploadRequest, upload_document};
    use fa_policy::{Op, Profile};
    use fa_reference::evidence::upload_verdict;

    let law = Law::embedded().expect("registries");
    let invoice_tag = law.policy.kind_by_name("Invoice").unwrap().tag;
    let all_grades: Vec<(u8, String)> = law
        .policy
        .grades
        .iter()
        .map(|g| (g.tag, g.name.clone()))
        .collect();

    for seed in [
        0x51a7_c0d3_1122_3344_u64,
        0x89ab_cdef_0123_4567,
        0xfeed_face_cafe_babe,
        0x3141_5926_5358_9793,
    ] {
        let mut rng = Rng(seed);
        let mut b = book();
        let mut docs: BTreeMap<u64, Doc> = BTreeMap::new();
        let mut handles: BTreeMap<u64, EvidenceRef> = BTreeMap::new();
        let mut raw_bytes: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut reviews: BTreeMap<u64, u64> = BTreeMap::new();
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();

        for step in 0..80_u64 {
            let uploader = *rng.pick(&PRINCIPALS);
            let is_human = rng.below(2) == 0;
            let profile = if is_human {
                Profile::Human
            } else {
                Profile::Agent
            };
            let cap = Capability::new(
                VId(u128::from(uploader)),
                profile,
                &[Op::Post],
                VId(u128::from(uploader)),
            )
            .expect("upload capability");

            // 1. Exercise asserted_grade (None, matching, or forged/mismatched).
            let asserted: Option<(u8, String)> = if rng.below(3) == 0 {
                None
            } else {
                Some(rng.pick(&all_grades).clone())
            };
            let bytes = format!("vwf-invoice-{seed:x}-{step}").into_bytes();
            let req = UploadRequest {
                kind: invoice_tag,
                mime: "text/plain".into(),
                bytes: bytes.clone(),
                asserted_grade: asserted.as_ref().map(|(tag, _)| *tag),
            };
            let ctx = b.ctx();
            let head_before = b.db.frontier().unwrap();
            let kernel_res = b
                .runtime
                .block_on(upload_document(&mut b.db, &ctx, &b.book, &cap, req))
                .expect("kernel");
            let oracle_res =
                upload_verdict(&law, is_human, asserted.as_ref().map(|(_, n)| n.as_str()));

            match (kernel_res, oracle_res) {
                (Ok(added), Ok(expected_grade)) => {
                    let expected_tag = law.policy.grade_by_name(expected_grade).unwrap().tag;
                    assert_eq!(added.grade, expected_tag, "seed {seed:x} step {step}");
                    assert!(!added.already_recorded);
                    let id = step + 1;
                    docs.insert(
                        id,
                        Doc {
                            kind: "Invoice".into(),
                            grade: expected_grade.into(),
                            commit: added.doc_commit,
                            uploader,
                            custody: Custody::uploaded(),
                        },
                    );
                    handles.insert(
                        id,
                        EvidenceRef {
                            document_oid: added.oid,
                            doc_commit: added.doc_commit,
                            role: 1,
                        },
                    );
                    raw_bytes.insert(id, bytes.clone());
                    if is_human {
                        *counts.entry("human_upload").or_default() += 1;
                    } else {
                        *counts.entry("agent_upload").or_default() += 1;
                        // Re-uploading the same bytes from a Human session must not
                        // upgrade the recorded AgentUpload grade or change uploader.
                        let human_reuploader =
                            Capability::new(VId(99), Profile::Human, &[Op::Post], VId(99)).unwrap();
                        let repeat_req = UploadRequest {
                            kind: invoice_tag,
                            mime: "text/plain".into(),
                            bytes,
                            asserted_grade: Some(
                                law.policy.grade_by_name("HumanUpload").unwrap().tag,
                            ),
                        };
                        let ctx = b.ctx();
                        let repeated = b
                            .runtime
                            .block_on(upload_document(
                                &mut b.db,
                                &ctx,
                                &b.book,
                                &human_reuploader,
                                repeat_req,
                            ))
                            .expect("kernel")
                            .expect("repeat upload succeeds");
                        assert!(repeated.already_recorded);
                        assert_eq!(repeated.grade, added.grade);
                        assert_eq!(repeated.oid, added.oid);
                        *counts.entry("human_reupload_kept_agent_grade").or_default() += 1;
                    }

                    // 2. Post citing the newly uploaded document before review.
                    let key = format!("vwf-post-pre-{step}").into_bytes();
                    let prop = b.proposal(EntryClass::ORIGINAL, &key, vec![handles[&id]]);
                    let post_pre = outcome(&b.post(prop));
                    let citations = vec![Citation {
                        doc: id,
                        commit: added.doc_commit,
                        role: 1,
                    }];
                    let att = Attestations {
                        reviews: reviews.clone(),
                        manual: None,
                    };
                    let oracle_pre = verdict(&law, "Original", &docs, &citations, &att);
                    assert_eq!(post_pre, oracle_pre, "seed {seed:x} step {step} pre-review");
                    if let Some(code) = post_pre {
                        *counts.entry(code).or_default() += 1;
                    }

                    // 3. For an AgentUpload document, test self-review refusal and independent review promotion.
                    if !is_human {
                        let self_rev = outcome(&b.review(uploader, added.oid, Vec::new()));
                        assert_eq!(
                            self_rev,
                            review_verdict(&docs, id, &[], uploader),
                            "seed {seed:x} step {step} self-review"
                        );
                        assert_eq!(self_rev, Some("FA-REF-111"));
                        *counts.entry("FA-REF-111").or_default() += 1;

                        let reviewer = PRINCIPALS.iter().copied().find(|p| *p != uploader).unwrap();
                        let rev_ok = outcome(&b.review(reviewer, added.oid, Vec::new()));
                        assert_eq!(
                            rev_ok,
                            review_verdict(&docs, id, &[], reviewer),
                            "seed {seed:x} step {step} independent review"
                        );
                        assert_eq!(rev_ok, None);
                        reviews.insert(id, reviewer);

                        let key_post = format!("vwf-post-after-{step}").into_bytes();
                        let prop_after =
                            b.proposal(EntryClass::ORIGINAL, &key_post, vec![handles[&id]]);
                        let post_after = outcome(&b.post(prop_after));
                        let att_after = Attestations {
                            reviews: reviews.clone(),
                            manual: None,
                        };
                        let oracle_after = verdict(&law, "Original", &docs, &citations, &att_after);
                        assert_eq!(
                            post_after, oracle_after,
                            "seed {seed:x} step {step} post-review"
                        );
                        assert_eq!(post_after, None);
                        *counts.entry("reviewed_post_admitted").or_default() += 1;
                    }
                }
                (Err(refusal), Err(expected_code)) => {
                    assert_eq!(
                        refusal.code, expected_code,
                        "seed {seed:x} step {step}: {refusal}"
                    );
                    assert_eq!(
                        b.db.frontier().unwrap(),
                        head_before,
                        "refused upload must not advance frontier"
                    );
                    *counts.entry(expected_code).or_default() += 1;
                }
                other => panic!("seed {seed:x} step {step} kernel/oracle mismatch: {other:?}"),
            }
        }

        eprintln!("vwf upload seed {seed:x}: {counts:?}");
        for (key, min) in [
            ("agent_upload", 3usize),
            ("human_upload", 3),
            ("FA-REF-084", 5),
            ("FA-REF-086", 3),
            ("FA-REF-111", 3),
            ("reviewed_post_admitted", 3),
            ("human_reupload_kept_agent_grade", 3),
        ] {
            assert!(
                counts.get(key).copied().unwrap_or(0) >= min,
                "seed {seed:x}: expected {key} >= {min}, got {:?}",
                counts.get(key)
            );
        }
    }
}
