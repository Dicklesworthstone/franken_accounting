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
use fa_journal::*;
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128, LegPayload, Oid, SealKey,
    SymbolTable,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_reference::evidence::{
    Attestations, Citation, Doc, Law, manual_verdict, review_verdict, verdict,
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
    assert_eq!(class_names.len(), 21, "every registered class");
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
            )
            .await
        })
        .expect("kernel")
        .expect("installs");
    let (_, periods) = runtime
        .block_on(async { create_periods(&mut db, &ctx, &book, 2026).await })
        .expect("periods");
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
                day,
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
    chosen.sort_by(|a, b| a.0.cmp(&b.0));
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
