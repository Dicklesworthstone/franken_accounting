# COMPREHENSIVE PLAN FOR THE DESIGN OF FRANKENACCOUNTING

*A universal, evidence-native, double-entry accounting system of record in memory-safe Rust, built on FrankenGraphDB and the Franken/asupersync ecosystem, designed so that the books of any entity can be posted, closed, restated, audited, litigated, and investigated from one immutable journal — by accountants, regulators, forensic examiners, courts, and AI agents — without ever trusting a mutable balance.*

---

## 0. The Thesis: What "Solving the Field" Actually Means Here

Double-entry bookkeeping is 530 years old and has not had a single structural upgrade in that time. Every system that holds books today is a compromise fossilized around a decision made long ago, and the fossils are the same across the whole market:

- **The ERP general ledger** (SAP S/4HANA's Universal Journal, Oracle Fusion GL, NetSuite, Workday, Dynamics) fossilized around *balances as mutable rows*. The journal is a table you `UPDATE`; the "audit trail" is a second table that logs some of those updates and can disagree with the first; "closing" a period is a flag column; a restatement is a human re-keying prior-period entries with a memo. SAP's `ACDOCA` is the apex of this lineage — one 400-column denormalized table that is, in a precise sense, a very large spreadsheet — and it still cannot answer "what did the books say on March 3rd about February" without restoring a backup.
- **Small-business accounting** (QuickBooks, Xero, Odoo, GnuCash) fossilized around *edit-in-place*. Entries are rows with an edit button. The "audit log" (where one exists) records that a field changed, not why, not under whose authority, and not what the statements said before. Evidence is an attachment icon.
- **Payments-grade ledger kernels** got the *primitive* right and stopped there. TigerBeetle is the most rigorous shipping ledger in the world: immutable transfers, 128-bit integer amounts, two-phase holds, linked atomic batches, deterministic simulation testing of every line. It is also, by design, a narrow OLTP balance engine: two-leg transfers only, three opaque `user_data` integers for everything else, no journal entry as an object, no periods, no close, no restatement semantics, no documents, no "the books as of", no relationships, no analytics, no multi-book, no branches. It is the engine block of a ledger, not a ledger.
- **Fintech ledger APIs** (Formance, Modern Treasury Ledgers, Fragment, Blnk, the Postgres-function ledgers) fossilized around *money movement inside one product*. They are double-entry, often immutable, often idempotent, and uniformly stop at "balances and transactions": no fiscal calendar, no close, no consolidation, no restatement, no audit evidence model, no forensic surface, and nearly all are SaaS whose system of record you do not hold.
- **Plain-text accounting** (Ledger, hledger, Beancount) got *immutability and reproducibility* right — the journal is text in git, every balance is recomputed from source, a balance assertion is a first-class statement — and is single-user, in-memory, unauthenticated, has no evidence model beyond a filename, no concurrency, no proofs, and no way to let an auditor in without giving them everything.
- **Audit and forensic tooling** (IDEA, ACL/Diligent, Excel, the AI-anomaly vendors; i2 and Palantir for tracing) fossilized around *the extract*. The books are dumped to CSV, loaded into a separate tool, and analyzed there; nothing proves the extract equals the system; nothing links a finding back to an immutable entry; the tracing graph is built by hand from the extract and dies with the engagement.
- **"Triple-entry" and blockchain ledgers** got *tamper evidence* and paid for it with the wrong trust model (public consensus for a private entity's books), the wrong cost model, and no accounting semantics above the token transfer.
- The **academic and standards frontier** has solved, *in isolation*, every hard subproblem: the REA ontology makes accounting a graph of resources, events, and agents (McCarthy 1982; ISO/IEC 15944-4); bitemporal databases make "as known at" and "effective at" orthogonal axes (Snodgrass; SQL:2011); immutability and event sourcing make the journal the only truth (Helland's "accountants don't use erasers"); Fowler's accounting patterns make reversal and replacement adjustments a lineage rather than an edit; the AICPA Audit Data Standards and SAF-T fix the vocabulary of an audit extract; AS 2401 fixes the journal-entry tests every auditor runs; Certificate Transparency and Merkle Mountain Ranges make an append-only log verifiable by an outsider; TigerBeetle made deterministic simulation of a ledger table stakes. **No shipping system has ever composed them.**

FrankenAccounting's leapfrog is not one trick. It is the *composition* of six bets, each at or beyond the current frontier, made feasible only because FrankenGraphDB and asupersync already exist and already absorbed the hard systems problems (immutable content-addressed commit stream, bitemporal property graph, git-style branches, incremental views, capability security, deterministic replay, lab-runtime simulation):

| # | Bet | One-line statement | Why nobody else can do it |
|---|-----|--------------------|---------------------------|
| **A1** | **One Posting Universe** | There are no balance rows. The journal is the database; every balance, register, trial balance, statement, and aging is a deterministic fold over the immutable entry stream at a `(book, branch, known-at, effective)` coordinate, materialized incrementally and verifiable by recomputation. Every change to accounting state — including the chart, the calendar, the policies, and the posting rules — is an appended, content-addressed journal object. | Requires an append-only, content-addressed, time-travelable commit stream (FrankenGraphDB Chronicle) plus an incremental view engine (Ripple) designed in from byte zero, so that "balance = fold" is cheap rather than a nightly batch. |
| **A2** | **Bitemporal by Construction, Period Law Mechanized** | Every entry has an *effective* date (which period it belongs to) and a *recorded* instant (when the books learned of it, assigned by the commit stream and never user-supplied). "The books for FY2024 as they stood on 2025-03-03" and "FY2024 as currently restated" are selectors, not backups. Period close is a valid-time lock enforced at the posting kernel; reopening and restating are journaled, authorized events with lineage, never flag flips. | Requires a substrate whose system time is immutable by construction and whose valid-time axis is a typed interval algebra with constraints (FrankenGraphDB §4.6), so ASC 250 / IAS 8 restatement mechanics become constraints rather than procedures. |
| **A3** | **Evidence-Native and Outsider-Verifiable** | Nothing posts without a *why*: every entry carries a content-addressed provenance closure — source documents, the business event, the posting rule version that generated it, the principal or agent and session, approvals, and every computation input (FX rate documents, allocation bases). The audit trail is not a log beside the data; it is part of the entry's identity. Any balance can be verified from documents through rules to the trial balance with inclusion proofs an outsider checks offline with a dependency-free verifier. | Requires content addressing, a transparency accumulator, and capability-scoped redaction in the storage engine (Chronicle §5.8, Warden §12.6), so proofs are a product feature rather than a bolt-on hash column. |
| **A4** | **The Ledger Is a Graph (REA, not rows)** | Accounts, legal entities, counterparties, instruments, documents, people, periods, policies, and findings are vertices; legs, approvals, ownership, control, settlement, intercompany pairing, and supersession are edges. "Follow the money", related-party exposure, circular flows, kiting, Ponzi motifs, structuring, and constructive-trust tracing are graph queries and `fnx` algorithms over the time-travelable graph, executed in the database under capabilities — not an extract rebuilt by hand in i2. | Requires a property-graph engine with in-database analytics, snapshot isolation for analytics, and determinism witnesses (FrankenGraphDB Prism + franken_networkx CGSE). |
| **A5** | **Exact and Deterministic as a Product Feature** | Amounts are exact fixed-scale integers in a registered unit; every rounding, allocation, and FX conversion is a *named law* with a residual leg, so no penny leaks and no two reports disagree. Every report is a certified, replayable computation: same closure ⇒ byte-identical output, with a certificate an expert witness can replay years later. | Requires the determinism doctrine (plan certificates, CGSE tie-breaks, replay manifests) and exact integer foundations (`fgdb-bigint`, `CanonicalDecimal`) already present in the substrate. |
| **A6** | **Agent-Native with Counterfactual Branches** | AI agents are the primary users. Every write is a typed intent with a dry-run plan; every error teaches the exact next command; every agent works on a draft that cannot touch trunk without authorized promotion; what-if, but-for, pro-forma, and pre-restatement scenarios are branches of the whole book with ledger-level diffs. One contract drives the CLI (robot mode) and the MCP server. | Requires git-style branches with semantic merge (Chronicle §5.6, the merge ladder §7.4), macaroon capabilities with graph caveats (Warden), a deterministic intent language, and the asupersync-native MCP framework (fastmcp_rust). |

The 2026 context makes the timing exact. Agents now prepare, review, and reconcile books in production; every regulator and audit firm is asking how to trust work an agent did; the SEC's 2023 amendments to Rule 17a-4 made a complete time-stamped audit trail an accepted alternative to WORM media; FRE 902(13) and 902(14) let hash-certified electronic records self-authenticate; FDIC Part 370 requires large banks to reconstruct insured-deposit positions at a point in time within 24 hours of failure; and the forensic profession's tools still begin with "export the GL to CSV". What the market lacks is a system of record whose every statement is reproducible, whose every number is evidenced, whose history cannot be rewritten, and which an agent can operate safely at machine speed. FrankenAccounting is that system.

### 0.1 The five readers

The plan is written for five audiences who will use the same artifact in very different ways. Each gets a worked workflow in §15.6.

1. **The CPA auditor** (financial-statement audit, SOX 404 attestation): wants to pull a complete GL extract whose completeness is *proven*, run journal-entry tests, sample with reproducible seeds, tie subledgers to control accounts, and export workpapers with stable references — without the client being able to alter history between fieldwork visits.
2. **The regulator and examiner** (FDIC, Federal Reserve, OCC, SEC, CFTC, state): wants point-in-time positions (the balance sheet "as of the close of business on the day before failure"), schedule lines derived deterministically from the ledger (call reports, FR Y-9C), proof that reported figures were produced from the books and not typed into a form, and a read-only, scoped, logged way in.
3. **The litigation consultant and expert witness** (damages, solvency, preference and fraudulent-transfer analysis, tracing): wants but-for scenarios that are reproducible, a chain of custody for every exhibit, hash-certified productions that satisfy FRE 902(14), and a methodology a court can examine under Daubert — including replaying the exact computation three years later.
4. **The forensic accountant and investigator** (FBI, Treasury/IRS-CI, FinCEN, FDIC OIG, internal investigations, receivers and trustees): wants to follow funds across accounts, entities, and banks; find related parties, layering, kiting, structuring, Ponzi flows, and top-side entries; apply the legal tracing rules (lowest intermediate balance, FIFO, pro rata) as code; and produce findings that cite immutable evidence.
5. **The AI agent** (the day-to-day operator of the books): wants one command that says what needs attention, typed intents with dry-run plans, errors that name the fix, stable IDs it can cite, explanations of any balance down to the entries and documents, a draft that cannot hurt trunk, and a query language it already knows.

### 0.2 The boundary with judgment

FrankenAccounting is the *mechanical* layer: exact arithmetic, immutable posting, time, evidence, proofs, analytics, and the surfaces that expose them. Questions that require professional judgment — materiality, which GAAP treatment applies, the five-step revenue-recognition analysis, whether a reserve is adequate, going-concern doubt, the tax position of a transaction — are the province of agent skills and human professionals that *act on* this system. The boundary is a design rule: FrankenAccounting never silently applies a judgment (it never auto-balances, never picks an account, never rounds without a law, never decides a period is "probably open"); it makes every mechanical fact exact, every policy explicit and versioned, and every judgment someone else made attributable and reversible with lineage. Skills such as tax preparation, audit planning, or revenue-recognition analysis plug in through Canon posting rules (§10), typed intents, and the MCP surface (§15), and the system records *which* rule version and *which* principal made each call.

### 0.3 Anti-goals

There is no "MVP", no "v1 simplification", no "phase where balances are a mutable table temporarily." §19 sequences *integration*, not ambition. FrankenAccounting is also deliberately **not**: an ERP (no procurement, inventory, payroll, or HR workflow — though their subledgers can be modeled as books that post into it); a payments processor or bank core (it records money movement, it does not move money); a user-interface product (surfaces are a CLI, an MCP server, and a Rust API; web UIs are downstream); a tax engine or a GAAP interpreter (see §0.2); a blockchain (tamper evidence comes from content addressing and transparency checkpoints, not consensus among strangers); a SaaS (the system of record is a directory you hold). It never uses floating-point for an amount, never stores a balance as authoritative, never edits an entry in place, never deletes, and never closes a period by setting a flag.

---

## 1. Constraints and Non-Negotiables

1. **The dependency universe is closed.** Allowed: `core`/`alloc`/`std`, the pinned Rust nightly (`nightly-2026-08-31`, the same date FrankenGraphDB and asupersync pin), and four foundation projects — `asupersync` (consumed as-is, with whatever it vendors; its choices are its own), **`frankengraphdb`** (the `fgdb` embedded API and the specific `fgdb-*` foundation crates named in §2.1, consumed at an exact git revision because they are unpublished), the `fnx-*` crates of `franken_networkx` (through FrankenGraphDB's Prism bridge and, for forensic projections, directly), and `fastmcp-rust` (in the `fa-mcp` surface posture only; its transitive serde/ring set is confined to that posture closure by `deny.toml` exactly as FrankenGraphDB confines its foundations' transitives). Everything else — calendar arithmetic, exact decimal multiply/divide, the posting-rule language, every file-format reader and writer (AICPA ADS, SAF-T, XBRL, ISO 20022 camt/pain, BAI2, OFX, Beancount/Ledger text, CSV), the evidence-bundle format and its verifier, the forensic procedures — is built in-house (§18 is the complete inventory). **No serde, no tokio, no chrono, no rust_decimal, no bigdecimal, no arrow, no sqlite bindings, no frankenpandas in an engine crate** (it links arrow, which the substrate bans). `frankensqlite` is not linked (§2.5 records why). A dataframe or search export adapter, if ever wanted, is a separately named packaging-boundary crate outside every posture closure, exactly as FrankenGraphDB isolates its Python binding.
2. **Memory safety is structural, with zero unsafe islands.** Every crate root carries `#![forbid(unsafe_code)]` and the workspace sets `unsafe_code = "forbid"`. FrankenAccounting adds **no** `fa-unsafe-*` crates: every raw-pointer need (SIMD, arenas, mmap, I/O) is already satisfied by the foundation's ledgered boundary crates, and accounting logic has no legitimate claim to one. A proposed unsafe island is a design defect to be routed upstream, not a ledger row to be added here.
3. **`Cx` everywhere.** Every function that performs I/O, takes a lock, allocates from a shared arena, or can block accepts `&Cx` (asupersync's capability context), or one of FrankenGraphDB's purpose-typed wrappers (`TxnCx`, `CommitCx`, `MaintCx`). This is what makes A5 possible: swap the `Cx`, and the entire accounting system — posting, close, restatement, forensic procedures, the MCP server — runs under the lab runtime with virtual time, deterministic scheduling, and fault injection. **The sharpest instance:** Canon posting rules and every Lantern procedure execute under a `Cx` with **no clock, entropy, network, or filesystem capability**; a rule that wants "today's date" must receive it as a declared input, so the effective date of an entry can never depend on when an agent happened to run.
4. **Exactness is constitutional.** An amount is `Amount { unit: UnitId, mantissa: i128 }` at the unit's registered scale; intermediate products and quotients use exact wide integers (`fgdb-bigint`); every rounding is an explicit, registered `RoundingLaw`; every allocation and FX conversion conserves totals under a registered law with a residual posted to a named account. A floating-point value may appear only in analytics outputs clearly typed as approximate (a Benford statistic), never in a leg, register, or statement line. There is no "tolerance" that silently absorbs an imbalance.
5. **The journal is the source of truth, and it is append-only.** A committed entry, document, attestation, rule version, chart object, period, or policy is immutable. Correction is a new object that supersedes with lineage (§8). There is no update, no delete, no "void" bit; a void is an entry. Registers, trial balances, statements, indexes, aging, and findings are derived and **never more authoritative than the journal** (FG-INV-18 inherited as FA-INV-04); recovery discards and rebuilds them, and every one of them is verifiable by recomputation.
6. **Recorded time is never user-supplied.** An entry's `recorded_at` is the commit stream's assignment (the FrankenGraphDB `MarkerRef` and its HLC), full stop. Migrations from legacy systems carry the legacy system's timestamps as *provenance properties* (`migrated_from { source_system, source_recorded_at, source_id }`), not as recorded time. This single rule is what makes "the books as known at *t*" defensible as evidence: no actor, including an administrator, can backdate what the system knew.
7. **Period law is enforced at commit, not reported after.** The posting kernel resolves every entry's effective date to exactly one period per fiscal calendar and checks the Appendix C admissibility matrix (period state × entry class × capability) inside the same serializable transaction that reads the period's state, so a post racing a close is resolved by SSI, not by a cron job. Reopen, close, lock, and restate are journaled control entries with approvals and lineage.
8. **Authorization precedes observation, and duties are segregated structurally.** Capabilities (macaroons with accounting caveats, §14) scope books, entities, account subtrees, periods, dimensions, operations, amount ceilings, and known-at horizons; they compile to planner predicates in the substrate (FG-INV-20), so an auditor's token cannot observe a privileged document's bytes even by accident, and an agent's token cannot express a trunk post. Segregation-of-duties policies (preparer ≠ approver; dual control for restatement, close, reopen, rule change) are commit-time constraints.
9. **Single artifact, three postures.** One codebase produces (a) an embedded library (`fa`) usable from Rust; (b) a CLI (`fa`) with a robot mode that is the agent contract; (c) an MCP server (`fa-mcp`, hosted by the long-running `fad` daemon that also owns the book's single writer lease and serves the CLI over a local socket). A networked multi-tenant posture over `fgdbd` is a registered post-1.0 workstream (§19), not a 1.0 claim.
10. **Deterministic by default, with an explicit domain.** Same evidence closure (book root and branch head, normalized query or report definition and parameters, calendar/unit/law registries at their epochs, rule versions, capability, numeric profile, and recorded external inputs) ⇒ byte-identical canonical result encoding, including order. Every report, finding, dry-run plan, and bundle carries a certificate naming that closure. Nondeterminism (a sampled procedure, a learned score) is opt-in, seeded, and declared in the certificate.
11. **Claims have types.** Every load-bearing statement is registered as exactly one of `invariant`, `proof`, `bounded_model`, `statistical`, `slo`, or `benchmark`, under FrankenGraphDB's claim-class lattice (§1 constraint 11 there; `registries/constitution.toml` here). A weaker class may inform policy but may not enforce or justify a stronger one. `invariants.toml` contains only exact safety/liveness obligations (FA-INV-01…); `evidence.toml` carries `FA-EVID-*`/`FA-CAL-*` (every forensic detector's score is one of these, never an invariant); `slo.toml` carries `FA-CFG-*`, performance, and benchmark rows.
12. **Costs are registered claims.** Every posting and reporting operation class has a row in the operation-cost registry (Appendix G) mapping it onto FrankenGraphDB's Appendix G rows: how many substrate transactions, which barrier chain, which external authorities, which derived objects. Every §17 gate must be derivable from that mapping; a latency gate below the substrate's barrier floor is a registry error that fails CI, never an ambitious target. A change that adds a substrate transaction, a synchronous external lookup (a rate service, a KMS), or a per-entry derived object updates the registry in the same change.
13. **Prohibited shortcuts (constitutional).** No mutable balance column presented as a register; no float in any amount path; no "soft delete" flag; no edit-in-place of any journaled object; no period flag flip; no separate audit-log table that could diverge from the journal; no silent auto-balancing or "rounding tolerance"; no posting rule that reads the wall clock; no user-supplied recorded time; no detached background thread; no serde-derived enum as a durable format; no "interim" single-writer global lock. Early code may implement a *subset* of each final abstraction — never a substitute for it. A slice that stubs the period law or writes a register directly is a prototype, and prototypes are prohibited.
14. **FrankenGraphDB is consumed, never forked.** When a substrate capability FrankenAccounting needs is not yet live (branches, materialized views, valid-time contracts, the MMR accumulator — the exact ledger is Appendix H), the interim posture is one of: a deterministic FrankenAccounting-level mechanism that remains correct and useful after the capability lands (an intent-log draft that *is* the semantic merge, a journal-level accumulator the outsider verifier needs anyway), or a feature-flagged absence. Never a copy of substrate code into this repository, never a second storage engine.

---

## 2. Foundation Audit: Exactly What We Stand On

This section is the result of a full review of the foundation repositories as they exist on 2026-10-09. It maps *specific existing assets* to *specific FrankenAccounting subsystems*, because the leapfrog claim is only credible if the reuse plan is concrete and the gaps are named.

### 2.1 frankengraphdb (31 crates, ~8,800 tests, unreleased): the substrate

FrankenAccounting is, in a precise sense, *an application written in the FrankenGraphDB programming model*: its data is a property graph in a book directory, its transactions are the substrate's serializable transactions, its history is the commit stream, its proofs are the commit stream's proofs, its security is the substrate's capability model. The table lists what is consumed, what it gives, and which FrankenAccounting subsystem uses it. Appendix H is the normative status ledger (live today / interim posture / tracking bead) for each row; the status column here is a summary checked on 2026-10-09 against `crates/fgdb/src/lib.rs`, `README.md`, and `IMPLEMENTATION_STATUS.md`.

| Asset | What it gives us | Used by | Status 2026-10-09 |
|---|---|---|---|
| `fgdb::Database` embedded API: `create/open/open_memory/open_read_view`, `write(cx, WriteBatch)`, `begin(&TxnCx) -> WriteTxn`, `prepare_write/commit_prepared`, `execute_gql[_at]`, `execute_gql_certified`, `pinned_read_view`, `delta_since`, `replay`; `WriteBatch::{create_vertex, add_edge, set_*_property, compare_and_set_*}`; `DatabaseKeys` | The only way bytes reach disk. Serializable (strict in Local posture) transactions over a bitemporal property graph; GQL reads; certified results; the change feed Folio's register maintainer consumes | Folio (§5), every reader | **Live.** `delta_since` is the interim feed for registers (§5.3) |
| Chronicle: content-addressed, RaptorQ-coded commit stream; `MarkerRef`/`CommitSeq`; two-fsync commit; `manifest.root` as the only mutable file; checkpoints and retention tiers; `FOR SYSTEM_TIME AS OF SEQ` | Immutable system time (constraint 6), durability without double-write journaling, time travel as a corollary of MVCC | Almanac's known-at axis (§7.1), Notary (§13), recovery | **Live** for the retained sequence range; retention policy is per book |
| Block-MVCC + Graph-SSI + witness types (§7 of the substrate plan); escrow and conserved-rights algebra (§4.7 there) | Correct post-versus-close races by construction; balance limits (overdraft, budget caps) without hot-register locks | Folio §5.4–5.5, Almanac §7.3 | SSI **live**; escrow domains **planned** — interim in §5.5 |
| Valid-time contracts (`ValidTimeContract`, slice sets, `FOR VALID_TIME` selectors, temporal non-overlap constraints) | The effective-date axis as a typed interval algebra: period membership, account effectivity, ownership intervals, policy versions | Almanac §7, Palimpsest §8, Steward §14 | **Planned** — interim in §7.8 |
| Branches (`BranchForkSpec`, squash merge, `DIFF` operator family, merge ladder) | Draft-per-agent isolation, what-if/but-for scenarios, pre-restatement rehearsal, consolidation on a branch, ledger diffs | A6 (§15), Concordat §12.3 | Read selectors **live** (`AT BRANCH` over a pinned snapshot); fork/merge **planned** — interim in §15.2 (drafts are intent logs) |
| Ripple: DBSP-style Z-set circuits, `CREATE MATERIALIZED VIEW … REFRESH INCREMENTAL`, `SUBSCRIBE TO`, watermarks | Registers, trial balances, agings, and findings maintained incrementally at a published watermark, with "watermark + tail fold" exactness | Folio §5.3, Statements §12.1, Lantern §11 | Subscriptions **live**; materialized views **planned** — interim maintainer actor in §5.3 |
| Beacon: property B-tree/hash, FTS/BM25, HNSW, path indexes with shadow-build/transactional activation | Account/date/party indexes; full-text over documents and memos; similarity over descriptions for duplicate detection | Docket §9, Lantern §11 | Property indexes **live** per `IMPLEMENTATION_STATUS.md`; FTS/HNSW partially (per-call build) — treated as accelerators, never semantics |
| Prism + `fnx-*` (550+ algorithms behind `GraphView`; CGSE tie-break policies and complexity witnesses) | Cycle detection, SCC, shortest/widest paths, max-flow/min-cut, community detection, centrality, exact-integer `network_simplex_int`, all with determinism witnesses | Lantern §11.4–11.6 | **Live** for the registered subset; FrankenAccounting also links `fnx-classes`/`fnx-algorithms` directly for projection-local forensic graphs |
| Warden: macaroon capability tokens with graph caveats compiled to planner predicates; redaction contracts; differential-privacy budgets; the audit pipeline and `AuditDomainId` | Books/entities/accounts/periods/dimensions/ops caveats; auditor and regulator profiles; privileged-document redaction with proof; who-read-what | Steward §14, Docket §9.6–9.7 | Policy/permit types **live** in `fgdb-warden`/`fgdb-policy`; full caveat compilation **in progress** |
| Determinism doctrine: plan certificates, `ReplayManifest`, `ReplayCompleteness` grades, decision cards, `Redacted` replay arm | Certified reports and findings; expert-witness replay; attributable degradation under erasure | A5, Notary §13.6, Lantern §11.8 | `execute_gql_certified` and `Database::replay` **live** for the native read subset |
| §5.8 accumulator and transparency layer: MMR over markers, inclusion/consistency proofs, `TransparencyCheckpoint`, `WitnessPolicy`, the post-1.0 dependency-free verifier SDK | Storage-level proof that an entry's commit is in the retained history and that history is append-only | Notary §13.1, §13.5 | **Planned** — FrankenAccounting's journal-level accumulator (§13.2) is a permanent design, not a stopgap, and cross-anchors when this lands |
| Foundation value crates: `fgdb-types` (`CanonicalPropertyValue` incl. `Decimal128`, `Date`, `ZonedDateTime`, `Duration`, `Struct`, `List`, `Map`; `CanonicalDecimal` — i128 coefficient, scale 18, checked add/sub/neg, half-even rescale, 16-byte canonical encoding; purpose contexts), `fgdb-bigint` (`BigInt` with limb-limited checked add/sub/mul/div_rem, canonical bytes), `fgdb-claim` (the claim-class lattice as types), `fgdb-evidence`, `fgdb-crypto` (BLAKE3 profiles, AEAD) | The exact arithmetic floor; canonical scalar encodings; claim typing as a compile-time guarantee | Abacus §6, every registry | **Live**, `publish = false` — consumed at git rev |
| `fgdb-sim`, `fgdb-reference`, `fgdb-oracles` patterns | The verification house style; the lab VFS and crash matrices FrankenAccounting's own sim extends | §16 | **Live** for bounded scenarios |
| `fgdb-udf-vm` (deterministic UDF bytecode VM, §13.8 of the substrate plan) | The compile target for Canon rules | Canon §10.3 | **Planned** — interim in-house typed-IR evaluator under a stripped `Cx` |
| `fgdb-cli` robot mode conventions (NDJSON, `robot schema`, exit-code dictionary 0/2/3/4/5), `fgdb doctor` | The in-family precedent the `fa` CLI matches so an agent that knows one knows both | Teller §15.3 | **Live** |

**The deep synergy.** An accounting system is a temporal, evidence-bearing, multi-party graph with a few exact algebraic laws on top. FrankenGraphDB is a temporal, evidence-bearing, capability-governed graph engine with determinism and proofs; its merge ladder is exactly "replay the intents and revalidate"; its escrow algebra is exactly "an account may not go negative"; its valid-time contracts are exactly "this entry belongs to February"; its branch model is exactly "rehearse the restatement before committing it"; its commit stream is exactly "the books as known at *t*". FrankenAccounting does not add a storage engine, a transaction model, a time model, a proof system, or a security model. It adds the accounting *laws*, the accounting *vocabulary*, the accounting *surfaces*, and the accounting *verification corpus* — and that is the entire codebase.

### 2.2 asupersync (~580 KLOC, 0.5.0 at rev `78b64636`): the operating system

| Asset | What it gives us | Used by |
|---|---|---|
| Region tree, obligations, `Outcome` lattice, three-lane scheduler, structured cancellation | Every background service (register maintainer, index feeder, bundle builder, forensic batch) is a supervised region; a cancelled close drains deterministically | §5.3, §16.4 |
| `Cx` capability contexts + narrowing | Constraint 3; the stripped `Cx` for Canon rules and Lantern procedures | §10, §11 |
| Lab runtime: virtual time, seeded scheduling, DPOR, chaos, crashpacks, lab VFS | `fa-sim`: the whole system — including the MCP server — under seed-replayable fault injection | §16.4 |
| RaptorQ (RFC 6330), per-symbol authentication | Consumed indirectly through Chronicle; bundles may optionally carry FEC for lossy courier transfer | §13.2 |
| Networking (TCP/HTTP/1.1/2/WebSocket/TLS), channels, combinators | `fad`'s local socket and HTTP transports; MCP transports via fastmcp_rust | §15 |
| Spork/OTP supervision | `fad` process tree | §16 |
| Macaroons, authenticated types | Capability tokens (through Warden) | §14 |
| Metrics/OTel | Telemetry | §16 |
| Statistical governance (e-processes, conformal, sequential tests) | Lantern's detectors carry calibrated evidence rather than magic thresholds; FA-CAL rows | §11.9 |

### 2.3 franken_networkx (`fnx-*` 0.3.0): the forensic algorithm brain

Consumed primarily through Prism over the book graph, and directly (`fnx-classes::DiGraph`, `fnx-algorithms`) over *projection graphs* Lantern builds from legs — the money-flow graph `(Party)-[:PAID]->(Party)` — where the projection is small enough to materialize and the algorithm family (max-flow, min-cost flow, SCC, simple cycles, community detection, betweenness) is what tracing and layering detection need. CGSE's tie-break policies and complexity witnesses are folded into every Lantern finding certificate so a ranking of suspicious parties is reproducible by an opposing expert.

### 2.4 fastmcp_rust (0.12.0): the MCP framework

`#[tool]`/`#[resource]`/`#[prompt]` handlers over `McpContext` (cancellation and budget via `Cx`), `ServerBuilder`, stdio and HTTP/SSE/WebSocket transports, the 2026-07-28 protocol facade with the official conformance suite at 110/115 SUCCESS and 0 FAILURE at `99a3b4e8`. `fa-mcp` is a thin adapter from the Teller verb registry (§15.1) to fastmcp tools; it defines no accounting semantics of its own. Risk rows: fastmcp pins `nightly-2026-08-25` (one week older than ours) and carries serde and ring transitively; both are confined to the `fa-mcp` posture closure by `deny.toml` (§18.4).

### 2.5 frankensqlite: why it is not the substrate (decision record)

The question was asked directly and deserves a direct answer. frankensqlite (0.4.10, ~26,500 tests, released) is more mature today than FrankenGraphDB, SQL is the lingua franca of accountants, and its page-level MVCC with `BEGIN CONCURRENT` is real. It was evaluated as the substrate and rejected, for recorded reasons:

| Dimension | frankensqlite as substrate | FrankenGraphDB as substrate |
|---|---|---|
| Data model | Relational; REA relationships become foreign keys; tracing is recursive CTE joins; the "ledger is a graph" bet (A4) becomes an ETL to a graph library | Property graph; REA is native; tracing and related-party closure are pattern queries and `fnx` calls over the live snapshot |
| System time | Snapshot ring today; the time-travel `VersionStore` is design-only; "as known at" would be built by FrankenAccounting | Immutable commit stream with retained history and `FOR SYSTEM_TIME AS OF` live |
| Valid time | None; FrankenAccounting would implement interval algebra and constraints in application code | Typed `ValidTimeContract` with non-overlap constraints and temporal path semantics (planned, normative) |
| Branches / scenarios | None; a scenario is a copy of the database file | Fork/merge with semantic difference engine (planned); read selectors live |
| Proofs | None; FrankenAccounting would build the accumulator | Content-addressed objects live; MMR/transparency planned; FrankenAccounting's journal-level accumulator cross-anchors |
| Capabilities | Connection-level; row security would be application code | Macaroon caveats compiled to planner predicates before expansion (FG-INV-20) |
| Determinism | SQL results are deterministic but uncertified | Plan certificates, replay manifests, CGSE witnesses |
| Incremental views | None | Ripple (planned) |
| Maturity today | Released, data-integrity advisory open on 0.4.10 | Unreleased, ~8,800 tests, several load-bearing surfaces planned |

The decision: **FrankenGraphDB is the substrate**, because five of the six bets are properties the substrate must have at byte zero and frankensqlite has none of them; choosing it would mean rebuilding Chronicle, valid time, branches, Ripple, Warden, and the proof layer inside FrankenAccounting — the "application grows a database" fossil. The maturity gap is managed, not ignored: Appendix H names every substrate capability relied on, its status, and the interim posture; FrankenAccounting's semantic core (`fa-journal`, `fa-money`, `fa-time`, `fa-reference`) is written against the substrate's *normative* contracts and is tested first against the reference oracle, so it does not block on the substrate's schedule. frankensqlite is not linked at all (its `fsqlite-*` crates are forbidden in FrankenGraphDB's closure, and two storage engines in one book is a smell with no upside). Its *designs* are already inside FrankenGraphDB. If the substrate's schedule slips catastrophically, the registered response is to pin a known-good revision and contribute upstream — never to swap engines.

### 2.6 Other suite assets considered

- **frankenpandas / franken_numpy / frankenscipy:** no decimal types; frankenpandas links arrow (banned). None enters an engine or posture closure. A post-1.0 `fa-frames` packaging-boundary crate may expose certified report rows as `frankenpandas::DataFrame` for downstream analysis; frankenscipy's `fsci_stats` is a candidate differential oracle for Lantern's statistical procedures in tests only.
- **frankensearch:** links tantivy and fsqlite (banned in the substrate's closure). Not used; Beacon's FTS/BM25 serves document and memo search.
- **frankentui (`ftui` 0.9.0):** inline mode and the `console` feature are usable for the human posture; the CLI's human output is plain text tables by default and `ftui` is an optional feature of `fa-cli`, never required, never on bare invocation (§15.7).
- **frankengit:** its `constellation.lock` (per-crate checksum and unsafe digest) and `registries/dependency_policy.tsv` are the house pattern for pinning foundations; FrankenAccounting adopts a `franken-stack.lock` recording each foundation's git commit and checksum (as `eidetic_engine_cli` does).
- **frankenfs:** confirms that RaptorQ is consumed from asupersync, never reimplemented.
- **eidetic_engine_cli:** the reference consumer of the stack — exact `=` pins, no path deps, a `deny.toml` that bans tokio/rusqlite/petgraph/hyper/reqwest/axum, and `scripts/check-forbidden-deps.sh` in CI. FrankenAccounting follows the same convention, with FrankenGraphDB (unpublished) as the one git-rev dependency.

### 2.7 What the foundations do *not* provide (and we therefore build)

The accounting vocabulary and object schemas; the posting kernel and its laws; exact decimal multiply/divide, rounding, allocation, and FX laws (`CanonicalDecimal` has add/sub/neg only); civil-date and fiscal-calendar arithmetic; the period state machine and admissibility matrix; supersession and restatement cases; the evidence model, chain of custody, attestations, and the journal-level accumulator; the posting-rule language and its evaluator; statement definitions and the report engine; multi-book, FX translation, intercompany and consolidation; the forensic procedure catalog and tracing laws; the evidence-bundle format and the dependency-free verifier; the capability caveat vocabulary and SoD policy engine; the Teller verb registry, CLI, daemon, and MCP adapter; every format reader/writer; the reference oracle, simulator scenarios, synthetic-book and fraud-scenario generators, benchmark harness, and conformance corpora. Estimated 120–200 KLOC of new Rust — small, because the substrate absorbed the hard systems problems — on a foundation that already proved them. The complete build-it-ourselves inventory is §18.

---

## 3. SOTA Distillation: The Field, and Where It Falls Short

A condensed map of the review (systems, standards, law, and literature), organized as *adopt / adapt / reject* decisions. Full bibliography in Appendix E.

### 3.1 Ledger kernels

| Source | Core idea | Verdict for FrankenAccounting |
|---|---|---|
| **TigerBeetle** (Zig, Apache-2.0; `Account {debits_pending, debits_posted, credits_pending, credits_posted, ledger, code, flags}`, `Transfer {debit_account_id, credit_account_id, amount: u128, pending_id, timeout, ledger, code, flags}`; flags `linked`, `pending`, `post_pending_transfer`, `void_pending_transfer`, `balancing_debit/credit`, `closing_debit/credit`, `imported`, `history`, `debits_must_not_exceed_credits`; cluster-assigned nanosecond timestamps; VOPR deterministic simulation; Viewstamped Replication; static allocation; "Tiger Style") | The debit/credit transfer as the only mutation; immutable transfers; 128-bit integer amounts; two-phase holds whose resolution is a new transfer pointing back through `pending_id`; linked chains as atomic batches; accounts never deleted, only closed; `imported` events carrying historical timestamps that must be past and strictly increasing; account-level balance limits checked at reservation time; four balance fields separating pending from posted | **Adopt the discipline, generalize the object.** FrankenAccounting's primitive is the *N-leg journal entry* (an atomic, immutable, content-addressed object whose legs balance per unit), of which a TigerBeetle transfer is the two-leg case; linked chains become multi-entry atomic batches; two-phase holds, closing flags, balance limits (via FrankenGraphDB escrow), pending/posted register separation, and the "resolution is a new object" rule are adopted verbatim (§5.4–5.5); `imported` is **adapted** — effective dates are always user-supplied, recorded time never is, and legacy timestamps are provenance (constraint 6); `user_data_{128,64,32}` is **rejected** in favor of typed provenance edges (§9); the single-core batched execution model is **not** adopted (FrankenAccounting is a system of record, not a payments core; its throughput gate is derived from the substrate's barrier chain, §17); VOPR's "every line of the system runs under deterministic simulation" is **adopted** by inheritance from the asupersync lab; a post-1.0 TigerBeetle-compatible transfer API profile is **registered** so TigerBeetle clients can target a FrankenAccounting book (§19) |
| **Stripe Ledger** (five billion events/day; money movement modeled as balance transfers between discrete states; a transaction-level system of record that proves multistage pipelines reconcile) | The ledger as an observable state machine over money states; reconciliation as a first-class, continuous property; "99.99% of dollar volume verified within four days" | **Adopt** "every movement is a state transition between named balances" (holds, clearing, settlement are states, not memos) and continuous reconciliation as registered constraints with lag SLOs (§5.7); **reject** the proprietary ingestion layer |
| **Uber LedgerStore** (immutable records in sealed, signed batches; indexes rebuildable from the ledger) | Sealing and signing time-bounded batches makes tampering detectable; indexes are never authoritative | **Adopt**; FrankenAccounting's journal accumulator (§13.2) is the generalization, and FG-INV-18 is the index rule |
| **Formance Ledger** (open source; Numscript, a declarative money-movement language with `send`/`source`/`destination` and overdraft bounds), **Modern Treasury Ledgers**, **Fragment** (GraphQL ledger), **Blnk**, Postgres-function ledgers (e.g., pgledger), Medici, the Rails `double_entry` gem | Double-entry as an API; idempotent postings; a small DSL for routing amounts across accounts; balance constraints at posting time | **Adapt** the idea of a typed money-movement language into Canon (§10), with totality, determinism, content-addressed versions, and no I/O; **adopt** idempotency keys as first-class; **reject** their scope ceiling (no periods, close, restatement, evidence, forensics, multi-book) and SaaS custody |
| **Plain-text accounting** — Ledger-cli, hledger, Beancount (v3) | The journal is the only truth; every balance is recomputed; `balance` assertions are first-class statements that fail the build; `pad` as an explicit plug; directives for prices and commodities; `bean-check` as a validator; git as history | **Adopt** balance = fold (A1), balance assertions as `Attestation`s of a register value at a date with evidence (§9.4), explicit prices/rates as documents, and the whole category as an **external differential oracle** (§16.3: export the journal to Beancount/hledger text and compare computed balances); **reject** single-user, in-memory, unauthenticated operation and filename-grade evidence |

### 3.2 General ledgers and ERP

| Source | Core idea | Verdict |
|---|---|---|
| **SAP S/4HANA Universal Journal (`ACDOCA`)** | One line-item table for FI, CO, asset, material, and profitability with a wide dimension set ("one truth"); ledgers (0L, 2L…) for parallel GAAP; extension ledgers for adjustments | **Adopt** the *goal* (one journal for every view; parallel books; adjustment layers) via books (§12.2) and supersession classes (§8); **reject** the mutable wide table and the separate change-document audit trail |
| **Oracle Fusion GL / Workday "worktags" / NetSuite / Dynamics** | Chart-of-accounts segments and tag dimensions; period status by ledger; subledger accounting rules that generate GL entries from events | **Adopt** dimension sets on legs (§4.3) and *subledger accounting rules* as the ancestor of Canon (§10); **reject** period-status flags and journal "approval" as workflow state outside the ledger |
| **QuickBooks / Xero / Odoo / GnuCash** | Audit log of field edits; "void" and "delete"; reconciliation status bits; attachment links | **Reject** edit-in-place, void bits, and attachment-as-link; **adopt** the usability lesson that reconciliation and matching must be first-class (§5.7) |
| **Martin Fowler, *Analysis Patterns* ch. 6 and the online "Accounting Patterns"** (Account, Entry, Transaction, Posting Rules, Accounting Event, Reversal Adjustment, Replacement Adjustment, Difference Adjustment, Summary Account, Memo Account) and **"Temporal Patterns"** (Audit Log, Effectivity, Temporal Property, Temporal Object, Bitemporal) | Corrections are reversal + replacement entries that preserve the original; posting rules turn events into entries; bitemporal models separate actual time from record time | **Adopt** nearly verbatim as the vocabulary of §8 and §10, upgraded with content addressing, lineage edges, and commit-time enforcement |

### 3.3 Accounting theory and time

| Source | Core idea | Verdict |
|---|---|---|
| **Pacioli, *Particularis de computis et scripturis* (1494)** | Memoriale → journal → ledger; every debit has a credit; the trial balance proves arithmetic consistency | **Adopt**; the balance law is FA-INV-01, the trial balance is a certified fold, and the three books are the event log, the journal, and the registers |
| **McCarthy's REA model (1982); ISO/IEC 15944-4** | Accounting as a graph of economic Resources, Events, and Agents with duality (give/take) and stock-flow relationships; accounts and debits/credits are *derived views* over the event graph | **Adopt** as the data model's spine (§4): business events and parties are vertices; journal entries are the derived, immutable projection of events through posting rules; the graph retains *both* the event and the entry with `DERIVED_FROM` lineage, so an auditor can test the derivation |
| **Ijiri's momentum/triple-entry (1986, 1989); Grigg's "Triple Entry Accounting" (2005)** | A third entry recording the rate of change (Ijiri) or a signed receipt shared by both parties (Grigg) makes the ledger self-evidencing | **Adapt** Grigg's signed receipt as `Attestation` and counterparty-shared evidence (§9.4); **reject** momentum accounting as a product feature (it is a registered analytic, not a posting law) |
| **Helland, "Immutability Changes Everything" (CIDR 2015)** | Accountants do not use erasers; append-only logs with derived views are the natural model for systems that must be audited | **Adopt** as A1's philosophical statement |
| **Snodgrass; SQL:2011 system/application time; Jensen & Snodgrass bitemporal semantics** | Transaction time and valid time are orthogonal; queries select on both; "now" is a query input | **Adopt** through the substrate's bitemporal axes (§7.1); omitted valid-time syntax means *all*, never wall-clock now (the substrate's rule, inherited) |
| **Event sourcing (Fowler 2005; Young)** | State is a fold over events; projections are rebuildable | **Adopt** (A1) with the substrate's determinism so projections are *certified* folds |

### 3.4 Audit, forensic, and regulatory practice

| Source | Core idea | Verdict |
|---|---|---|
| **AICPA Audit Data Standards — General Ledger Standard** (`GL_Detail_YYYYMMDD_YYYYMMDD`, `Chart_Of_Accounts`, `Source_Listing`, `Business_Unit_Listing`, journal fields such as `Journal_ID`, `Journal_ID_Line_Number`, `Effective_Date`, `Entered_Date`, `Entered_By`, `Approved_By`, `GL_Account_Number`, `Amount`, `Amount_Currency`, `Debit_Credit_Indicator`, `Source`, `Fiscal_Year`, `Period`, `Reversal_Indicator`, `JE_Header_Description`) | A uniform extract vocabulary auditors' tools already consume | **Adopt** as a native export whose completeness is *proven* (the export carries the journal accumulator root and inclusion proofs for the range, §13), and as a field-name vocabulary checked against the data model (§4) so every ADS column has a defined source |
| **OECD SAF-T**, **XBRL GL** and the **US-GAAP/IFRS XBRL taxonomies**, **ISO 20022** (`camt.053` statements, `pain.001` payments), **BAI2**, **OFX** | Standard audit files for tax authorities; machine-readable statements; bank data formats | **Adopt** as readers/writers in `fa-formats` (§18); taxonomies and mappings are versioned *data* in the book, not code |
| **PCAOB AS 2401 (fraud) ¶.58–.62 journal-entry testing; AU-C/ISA 240; AS 1215/ISA 230 (documentation); AS 2201 (ICFR); AS 2315/ISA 530 (sampling); AS 2310/ISA 505 (confirmations); COSO** | The characteristics of suspect entries (unrelated/unusual/seldom-used accounts; unusual preparers; end-of-period or post-closing timing; little or no description; round numbers; top-side consolidation entries); the sufficiency of documentation; monetary-unit and attribute sampling; external confirmation as evidence | **Adopt** JET as registered Lantern procedures (§11.2), seeded reproducible sampling (§11.7), confirmations as external attestations (§9.4), and the "audit assertion → mechanism" mapping (§13.4) so each assertion names the FrankenAccounting feature that supports it |
| **Nigrini's Benford analyses; Relative Size Factor; duplicate and round-number tests** | Digit-distribution conformity (MAD ranges), largest-to-second-largest ratios, same-same-same/same-same-different duplicate tests | **Adopt** as procedures with calibrated evidence (FA-EVID rows), never as invariants (§11.3, §11.9) |
| **SOX §302/§404/§802; 18 U.S.C. §1519; SEC Rule 17a-4(f) (2022 amendments: the time-stamped audit-trail alternative to WORM); FINRA 4511; CFTC 1.31** | Management certifies controls; altering records in an investigation is a crime; broker-dealer records must be non-rewritable or carry a complete audit trail | **Adopt** as design targets, not legal claims: append-only journal + immutable recorded time + supersession lineage *is* a complete time-stamped audit trail; the plan states which technical properties exist and leaves regulatory sufficiency to counsel (§13.4) |
| **FRE 902(13)/902(14) (2017), FRE 1006, FRE 702/Daubert (2023 amendment); chain of custody** | Hash-certified electronic records self-authenticate; summaries of voluminous records are admissible; expert methodology must be reliable and reproducible | **Adopt**: evidence bundles carry canonical hashes and a certifier statement template (§13.2); certified reports are the summary with replayable methodology (§13.6); custody edges (§9.3) |
| **FDIC Part 370; FFIEC Call Reports; FR Y-9C; BSA/AML (CTR/SAR, 31 U.S.C. §5324 structuring); OFAC** | Point-in-time deposit positions within 24 hours of failure; regulatory schedules derived from the GL; structuring under reporting thresholds | **Adopt**: as-of positions are selectors (§7.4); schedules are statement definitions (§12.6); structuring is a registered procedure (§11.3) |
| **Bankruptcy and fraud litigation: 11 U.S.C. §547 preferences (90-day/1-year lookback), §548 and UVTA fraudulent transfers, solvency tests (balance-sheet, cash-flow, capital adequacy), tracing rules (lowest intermediate balance rule, FIFO, LIFO, pro rata; *Cunningham v. Brown* pro-rata distribution in Ponzi cases)** | Point-in-time solvency; lookback windows; constructive-trust tracing through commingled accounts | **Adopt** as registered Lantern procedures and but-for branches (§11.5–11.6) |
| **i2 Analyst's Notebook / Palantir / Linkurious-style link analysis; MindBridge-style GL anomaly scoring; IDEA/ACL** | Graph visualization of flows; ML risk scores; scripted analytics over extracts | **Adapt** the graph *questions* (not the extract); treat ML scores as advisory features on decision cards with a deterministic fallback (§11.9); **reject** the extract as the unit of work |

### 3.5 Verifiability and cryptography

| Source | Core idea | Verdict |
|---|---|---|
| **Certificate Transparency (RFC 6962), Merkle Mountain Ranges, authenticated data structures** | Append-only logs with inclusion and consistency proofs; gossip/witnesses against split views | **Adopt** through the substrate's §5.8 and the journal-level accumulator (§13); proof scopes labeled exactly (`membership_only`, detection vs prevention) |
| **WORM media; content-addressed storage; signed sealed batches** | Non-rewritable history | **Adopt** by construction (Chronicle) |
| **Blockchains and "triple-entry on chain"** | Tamper evidence by public consensus | **Reject**; a company's books need a transparency log with named witnesses (the auditor, the regulator), not anonymous consensus |

### 3.6 What we deliberately reject

Floats in any amount path; mutable balance rows; soft deletes and void bits; edit-in-place; period flags; an audit-log table beside the journal; implicit rounding tolerances and auto-balancing; posting rules with I/O or clock access; user-supplied recorded time; OLAP cubes as the reporting substrate (Ripple views are the cube); stored procedures as the rules language; blockchain consensus; SaaS custody of the system of record; ERP workflow scope; a second storage engine; a web UI in the core.

Four seductive alternatives were evaluated in depth and rejected with recorded reasons: (a) **legs as independently mutable rows** (rejected: an entry's identity must cover all its legs so partial visibility is impossible by construction and the entry digest is tamper-evident; §4.2); (b) **registers updated synchronously in the posting transaction** (rejected as the *primary* design: it turns every hot account into a serialization point exactly as TigerBeetle's authors warn; registers are watermark-maintained derived views with tail folds, and balance *limits* use escrow rights, §5.3–5.5); (c) **a single "posting date" column** (rejected: effective, recorded, document, and approval times are distinct facts with distinct legal meaning; §4.7); (d) **storing proofs only at the storage layer** (rejected: an outsider's verifier must verify *accounting* objects without understanding the engine's formats; the journal-level accumulator is permanent, §13.2).

---

## 4. Data Model: REA on a Bitemporal Property Graph

### 4.1 The FrankenAccounting model

A book is a FrankenGraphDB database (one directory, one `manifest.root`, one security namespace) holding one or more **graphs**: `ledger` (the journal and everything derived from it), `evidence` (documents, attestations, custody), and `system` (the book's own runtime: sessions, capabilities, access audit, findings). Until the substrate ships a graph catalog, the three are label-partitioned regions of one graph with the partition recorded in the `_graph` system property; nothing in this plan depends on the distinction being physical.

All element kinds are declared in **Strict** schema posture (the substrate's §4.2) with existence, key, cardinality, and check constraints active; free-form annotations live in a declared overflow map (`Shaped` posture) on `Party`, `Document`, and `Finding` only.

**Vertices (ledger graph).**

| Label | Identity / key | Load-bearing properties | Notes |
|---|---|---|---|
| `Book` | `book_id` (ULID-shaped, allocated once) | `name`, `base_unit: UnitId`, `calendar_ref`, `gaap: {USGAAP, IFRS, Tax, Statutory, Management, Custom(id)}`, `numeric_profile_oid`, `registry_epochs: Map` | Exactly one trunk `Book` per database; parallel books (§12.2) are additional `Book` vertices sharing entities and parties |
| `LegalEntity` | `entity_id` | `name`, `jurisdiction`, `tax_ids: Map`, `functional_unit: UnitId`, valid-time `[formed, dissolved)` | Consolidation scope via `OWNS`/`CONTROLS` edges |
| `Account` | `(book_id, code)` key constraint | `name`, `type: {Asset, Liability, Equity, Revenue, Expense, Contra(of: type), OffBalance, Memo, Statistical}`, `normal_balance: {Debit, Credit}`, `posting: {Leaf, Summary}`, `unit_policy: {Single(UnitId), AnyCurrency, AnyUnit}`, `control_of: Option<SubledgerId>`, `dimension_requirements: List<DimensionId>`, `balance_limit: Option<EscrowDomainRef>`, valid-time `[opened, closed)` | Hierarchy via `CHILD_OF`; only `Leaf` accounts receive legs (FA-INV-01 clause `leaf-only`) |
| `Dimension` / `DimensionValue` | `(book_id, dimension_code)` / `(dimension_id, value_code)` | `name`, `kind: {CostCenter, Department, Project, Product, Region, Fund, Grant, Segment, Custom}`, hierarchy via `CHILD_OF`, valid-time effectivity | A leg's `DimensionSet` references values by id; required dimensions are enforced per account |
| `Unit` | `unit_code` | `kind: {Currency(iso4217), Commodity, Share(class), Time, Count, Custom}`, `scale: u8` (minor-unit digits; `USD` 2, `JPY` 0, `BTC` 8, `ETH` 18, shares 6 by default), `rounding_default: RoundingLawId`, `symbol`, `display_scale` | The registry row is also a vertex so unit changes are journaled |
| `FiscalCalendar` / `Period` | `calendar_id` / `(calendar_id, period_code)` | Calendar: `kind: {Monthly12, Weeks445, Weeks454, Weeks544, Week5253(end_rule), Custom}`, `year_start`, `adjustment_periods: u8`; Period: `fiscal_year`, `ordinal`, valid-time `[start, end)` on the `DateDay` domain, `kind: {Normal, Adjustment, Opening, Closing}`, `state: {Future, Open, SoftClosed, Closed, Locked}` as a versioned property whose every change is a control entry | §7 |
| `Entry` | `entry_ref` = substrate VId; `entry_digest` (BLAKE3 over canonical bytes) | See §4.2 | The atom of the journal |
| `Leg` (derived projection) | `(entry_ref, ordinal)` | `side: {Debit, Credit}`, `amount: Amount`, `base_amount: Option<Amount>`, `dimension_set_ref`, `memo` | Derived from the entry's inline legs in the same transaction; never authoritative (§4.2) |
| `Register` (derived view) | `(book, branch, account, unit, period, dimension_subset_key)` | `debits_posted`, `credits_posted`, `debits_pending`, `credits_pending`, `entry_count`, `watermark: CommitSeq`, `fold_digest` | §5.3; TigerBeetle's four balance fields, per key |
| `Party` | `party_id`; external ids via `ExternalId` vertices | `kind: {Customer, Vendor, Employee, Bank, Investor, RelatedParty, Government, Other}`, `name`, `identifiers: Map` (overflow), KYC/beneficial-ownership links via edges | Counterparties for tracing and related-party analysis |
| `Instrument` | `instrument_id` | `kind: {BankAccount, Loan, Security, FixedAsset, Lease, Derivative, Wallet, Custom}`, `unit`, `held_at: Party`, `account_ref` (the GL account that mirrors it) | Bank accounts are instruments; their statements are documents; their lines are `BankLine`s |
| `Event` (REA economic event) | `event_id`; idempotency key | `kind` (registered: `Sale`, `Purchase`, `Receipt`, `Payment`, `Shipment`, `Return`, `Accrual`, `Depreciation`, `Custom(id)`), `occurred_on`, `resources: List<{unit, quantity, instrument?}>`, agents via edges | The thing that happened; entries are derived from it by Canon rules |
| `Subledger` | `subledger_id` | `kind: {AR, AP, FixedAssets, Inventory, Payroll, Cash, Investments, Custom}`, `control_account_ref` | A subledger's detail balances must equal its control account (FA-INV-12) |
| `RestatementCase`, `DraftSet`, `CloseRun`, `Scenario` | ids | §8.3, §15.2, §7.5, §15.2 | Control objects, journaled like everything else |
| `StatementDefinition`, `RegisterDefinition`, `RuleVersion`, `Policy` | content-addressed `oid` | §12.1, §5.3, §10.3, §14 | Versioned data, never code paths |

**Vertices (evidence graph).** `Document` (§9.1), `Attestation` (§9.4), `BankLine` (§9.5), `ImportReceipt` (§9.3), `Principal` (a human, a service, or an agent: `kind`, `program`, `model`, `session` lineage), `Approval`.

**Vertices (system graph).** `Capability` (issued token metadata, never the secret), `AccessEvent` (who read what, under which capability, at which snapshot), `Finding` (§11.8), `Certificate` (§13.6), `Bundle` (§13.2), `DecisionCard`.

**Edges.**

| Edge | Endpoints | Properties | Meaning |
|---|---|---|---|
| `HAS_LEG {ordinal}` | `Entry → Leg` | — | Derived projection of inline legs |
| `POSTS_TO` | `Leg → Account` | — | The GL posting |
| `FOR` | `Leg → DimensionValue` | `dimension_id` | Dimension tagging |
| `IN_UNIT` | `Leg → Unit` | — | |
| `CHILD_OF` | `Account → Account`, `DimensionValue → DimensionValue`, `Period → FiscalCalendar` | valid-time | Hierarchies |
| `SUPERSEDES {kind, reason_code, case_ref?}` | `Entry → Entry` | `kind: {Reverses, Replaces, Reclassifies, Restates, Revises, Corrects, Resolves(Pending)}` | §8.2 lineage |
| `RESOLVES {disposition}` | `Entry → Entry` | `{Posts(amount), Voids, Expires}` | Two-phase resolution (§5.4) |
| `DERIVED_FROM` | `Entry → Event` | `rule_version_oid` | REA duality: the entry is the rule's projection of the event |
| `GENERATED_BY` | `Entry → RuleVersion` | `inputs_digest` | Canon provenance |
| `EVIDENCED_BY {role}` | `Entry|Event|Attestation → Document` | `role: {Source, Support, Rate, Contract, Statement, Approval, Other}` | §9.2 |
| `PREPARED_BY`, `APPROVED_BY {at, approval_ref}`, `REVIEWED_BY` | `Entry|CloseRun|RestatementCase → Principal` | — | SoD evidence |
| `ATTESTS {claim}` | `Attestation → Register|Entry|Document|Period` | — | A signed statement about an object |
| `SETTLES {amount}` / `MATCHES {method, confidence}` | `Leg → Leg`, `BankLine → Leg` | — | Application and reconciliation (§5.7) |
| `OWNS {pct}` / `CONTROLS {basis}` / `RELATED_TO {basis}` | `LegalEntity|Party → LegalEntity|Party` | valid-time | Consolidation scope and related-party closure |
| `HELD_AT` | `Instrument → Party` | — | Bank/custodian |
| `MIRRORS` | `Instrument → Account` | — | The GL account for the instrument |
| `INTERCOMPANY_WITH {pair_key}` | `Entry → Entry` | — | Matched intercompany pair (§12.3) |
| `PAID {amount, unit, effective, entry_ref}` (derived view) | `Party → Party` | — | The money-flow projection Lantern traces (§11.4) |
| `CITES` | `Finding → Entry|Leg|Party|Document|Register` | `role` | Evidence links on findings |
| `IN_CASE` | `Entry → RestatementCase`, `Entry → DraftSet`, `Entry → CloseRun` | — | Grouping |
| `READ {snapshot_seq, fields}` | `AccessEvent → any` | — | Who-read-what |

**System time** is universal and automatic (every version carries its creating `MarkerRef`). **Valid time** is enabled on `Account`, `DimensionValue`, `Period`, `Party` relationships (`OWNS`/`CONTROLS`/`RELATED_TO`), `Policy`, and `Unit` (for scale changes), on the `DateDay` domain. **Provenance** is first-class on every element (the substrate's `_provenance` system property records agent/session/rule for every write).

### 4.2 Entries and legs: the canonical immutable entry

An `Entry` is one vertex whose canonical payload contains its ordered legs inline:

```text
Entry {
  schema_major: u16, schema_minor: u16,
  book_id, branch_id,
  class: EntryClass,                       // registry entry_classes.toml (§8.1)
  effective_date: DateDay,                 // valid-time anchor → exactly one Period per calendar
  document_date: Option<DateDay>,
  description: String (bounded),
  legs: List<LegPayload>,                  // ≥ 2; ordinal = position
  unit_totals: Map<UnitId, {debits, credits}>,   // redundant, verified, for O(1) balance-law checks
  base_totals: Option<{unit, debits, credits, fx_law_oid, rate_doc_oids[]}>,
  idempotency_key: Bytes(≤64),
  origin: EntryOrigin,                     // Intent{intent_oid} | Rule{rule_version_oid, event_ref} | Migration{..} | System{control_kind}
  principal_ref, session_ref, approvals: List<ApprovalRef>,
  evidence: List<{document_oid, role}>,    // the provenance closure heads
  supersession: List<{target_entry_ref, kind, reason_code}>,
  pending: Option<{timeout: Option<Duration>, resolution_of: Option<EntryRef>}>,
  external_ids: List<{system, id}>,
  tags: Map<String, CanonicalPropertyValue> (bounded),
  entry_digest: BodyDigest<Entry>          // BLAKE3("fa:entry:v1" ‖ canonical(all fields except this one))
}
LegPayload {
  side: Debit | Credit,
  account_ref: VId,                        // must be a posting Leaf at effective_date
  amount: Amount,                          // exact; unit-scaled mantissa
  base_amount: Option<Amount>,             // under the entry's FX law
  dimension_set: List<(DimensionId, DimensionValueRef)>,  // sorted canonical
  memo: Option<String>,
  settles: List<{leg_ref, amount}>,        // application targets, validated against open items
}
```

**Why one vertex with inline legs.** The entry's identity covers every leg, so (a) partial visibility is impossible by construction — there is no interleaving in which a reader sees three of four legs; (b) `entry_digest` is a tamper-evident identity for the whole accounting fact, which is what a bundle proves and what an external ID should bind to; (c) the balance law is checkable from the vertex alone; (d) immutability is a property of one object rather than of a cluster. The `Leg` vertices and `HAS_LEG`/`POSTS_TO`/`FOR` edges are **derived projections written in the same substrate transaction** by Folio (the only writer, through the secure view), so GQL pattern queries and indexes work over legs without the projection ever becoming authoritative; a reference oracle (§16.2) asserts projection-equals-payload after every commit, and recovery rebuilds projections from payloads. `recorded_at` is **not** a payload field: it is the commit stream's assignment, read as `_commit_time` / the creating `MarkerRef`, which is precisely why it cannot be forged (constraint 6).

An entry has at least two legs. Multi-currency entries balance per unit (FA-INV-01 clause `per-unit`) and, when `base_totals` is present, in the book's base unit under the named FX law with the residual carried by an explicit leg on the registered rounding account (clause `base`). A `Memo`/`Statistical` account's legs balance among themselves and never against monetary legs.

### 4.3 Accounts and the chart

The chart is a forest of `Account` vertices under `CHILD_OF`, versioned in valid time: an account is `Leaf` or `Summary`, and only leaves accept legs; promoting a leaf to summary (because children were added) is a journaled schema effect that is legal only when the leaf has no legs effective after the promotion date, else the kernel refuses with the exact entries that block it. `type` and `normal_balance` are fixed at creation (a change is a new account plus a reclassification plan). `unit_policy` fixes whether an account holds one unit (most GL accounts), any currency (an FX clearing account), or any unit (an inventory or securities account). `dimension_requirements` lists the dimensions every leg must carry (cost center on every expense leg, for example); the kernel rejects a leg missing a required dimension with the list of allowed values. `control_of` ties the account to a `Subledger` whose detail must reconcile (FA-INV-12). `balance_limit` names an escrow domain (§5.5) such as "may not go negative" or "may not exceed budget". Chart templates (a US GAAP small-business chart, a bank chart aligned to call-report lines, an IFRS chart) are data under `templates/` and are imported as ordinary journaled schema effects.

### 4.4 Units and amounts

`Amount { unit: UnitId, mantissa: i128 }`, interpreted as `mantissa × 10^-scale(unit)`. The unit registry fixes the scale; the mantissa is always at that scale (no per-amount exponent), so equality, ordering, hashing, and summation are integer operations and `Amount` values of one unit form an ordered abelian group under checked addition. Overflow is an error, never a wrap. A unit's scale may increase by a journaled registry change (a currency redenomination, a token's precision change) with a lossless rescale of every stored mantissa recorded as a `Migration`-class control effect; it may never decrease. The full algebra is §6.

### 4.5 Parties, instruments, entities, and ownership

`LegalEntity`, `Party`, and `Instrument` form the "who and what" of REA. Ownership (`OWNS {pct}`), control (`CONTROLS {basis}`), and relatedness (`RELATED_TO {basis}`) are valid-time edges, so "related parties as of the transaction date" is a temporal closure query, not a spreadsheet. Beneficial ownership, officers, and family relationships use the same edge kinds with a `basis` vocabulary registered in `relationship_bases.toml`. Every bank account is an `Instrument` `HELD_AT` a `Party` of kind `Bank` and `MIRRORS` a GL account; statements for it are documents whose parsed `BankLine`s match legs (§9.5).

### 4.6 Documents, events, rules, principals, approvals, attestations

The evidence graph records *why*. A `Document` is a content-addressed object (§9.1). An `Event` is the REA economic event (an invoice was issued, a payment was received) that a Canon rule turns into one or more entries; the event and the entry are both retained with `DERIVED_FROM`/`GENERATED_BY` lineage so the derivation itself is testable (re-run rule version *v* over event *e* and compare digests). A `Principal` is a human, a service, or an agent (`program`, `model`, `session_id`, parent session lineage) — agent attribution is as first-class as human attribution. An `Approval` is a journaled object binding a principal, a capability, a timestamp (recorded by the commit stream), and the digest of what was approved; approvals that do not match the digest of the committed object are rejected (FA-INV-10 clause `approval-binds-digest`). An `Attestation` is a signed statement about an object (§9.4).

### 4.7 Time attributes on an entry

| Attribute | Who sets it | Axis | Meaning |
|---|---|---|---|
| `effective_date` | The intent or rule (user-supplied, validated) | Valid time | Which period the entry belongs to; drives registers and statements |
| `recorded_at` (= creating `MarkerRef`, `_commit_time`) | The commit stream — **never user-supplied** | System time | When the books learned of the entry; drives "as known at" and all evidentiary claims |
| `document_date` | The source document | Attribute | The date on the invoice/statement; drives cutoff tests |
| `approved_at` (per approval) | The commit stream, at approval commit | System time | SoD evidence |
| `migrated_from.source_recorded_at` | Migration provenance | Attribute | What the legacy system claimed; never promoted to `recorded_at` |

Effective dates are civil dates (`DateDay`) in the book's calendar; the posting kernel does not accept instants for `effective_date` (a time zone is a policy of the book, not a property of a leg). Recorded times are UTC instants from the substrate's HLC-bearing markers.

### 4.8 Books, branches, and coordinates

Every read and write names a **coordinate**: `BookCoordinate { book, branch, known_at: SystemSelector, effective: EffectiveSelector }` where `SystemSelector = Head | AsOfSeq(CommitSeq) | AsOfTime(Instant)` and `EffectiveSelector = All | Period(period_ref) | Range[start,end) | AsOf(DateDay)`. The default is `trunk@head, All`. Branches (drafts, scenarios, consolidation runs, restatement rehearsals) are substrate branches when available and intent-log drafts otherwise (§15.2); in both cases the coordinate vocabulary is identical, which is what makes the interim posture honest rather than a fork in the API.

### 4.9 Identity and stable handles

Every object an agent might cite has a stable handle: `EntryRef { vid, entry_digest }` (the digest makes the handle self-verifying), `AccountRef { book, code }`, `PeriodRef { calendar, code }`, `DocumentRef { oid }`, `FindingRef { vid, digest }`, `CertificateRef { oid }`, `BundleRef { oid }`. Handles are deterministic across machines where the underlying identity is content-addressed and otherwise carry the digest beside the allocated id. `ExternalId { system, id }` vertices carry a key constraint so a legacy journal number maps to at most one entry, and an idempotency key maps to at most one outcome (FA-INV-09).

### 4.10 Schema posture

`Entry`, `Leg`, `Account`, `Period`, `Unit`, `Register`, `Attestation`, `Approval`, and every control object are **Strict**; `Party`, `Document`, `Finding` are **Shaped** with a bounded overflow map; nothing is **Open**. Schema objects are versioned in the commit stream like data, so a chart change is time-travelable and branchable and a prepared report invalidates precisely when its schema epoch moves.

### 4.11 Reserved system surface

The substrate's reserved fields (`_id`, `_labels`, `_created_seq`, `_retired_seq`, `_commit_time`, `_valid_from`, `_valid_to`, `_provenance`) plus FrankenAccounting's: `_graph`, `_entry_digest`, `_fold_digest` (on registers), `_certificate` (on report rows), `_redaction` (on documents under a redaction contract). System edge types `DERIVED_FROM` and `SAME_AS` are the substrate's; FrankenAccounting reserves `SUPERSEDES`, `RESOLVES`, `GENERATED_BY`, `EVIDENCED_BY`, `ATTESTS`, `CITES`, and `READ`.

---

## 5. Folio: The Posting Kernel (Bet A1)

Folio is the only writer of the ledger graph. Every path that creates accounting state — an agent's typed intent, a Canon rule firing on an event, a bulk migration, a close run, a restatement case, a two-phase resolution, an expiry sweep — enters Folio as a **posting proposal** and leaves as either a committed entry (with its derived projections) or a typed refusal naming exactly what to change. There is no second door.

### 5.1 The posting pipeline

```text
Intent | Event+Rule | Batch | Control            (§10, §5.8, §7.5, §8.3)
        │
        ▼
 1. ADMIT     capability check (books/entities/accounts/periods/ops/amount ceiling) — before any observation (FA-INV-10)
 2. RESOLVE   accounts by code→VId at effective_date; dimensions; units; period(s) via Almanac; open items for `settles`
 3. CANON     if rule-driven: evaluate rule_version over event under stripped Cx → candidate legs (§10)
 4. ABACUS    exact totals per unit; base conversion under FX law; rounding residual leg; allocation conservation (§6)
 5. LAWS      balance law (per unit, base); leaf-only; unit policy; required dimensions; entry-class admissibility
              for the resolved period state (Appendix C); supersession target validity; pending/resolution rules;
              SoD (preparer ≠ approver; dual control where the matrix demands); idempotency key lookup
 6. PLAN      build the dry-run plan: resulting legs, register deltas at head, period decision, SoD decision,
              escrow rights required, evidence closure heads, certificate of the plan (this is what `--dry-run` returns)
 7. COMMIT    one substrate transaction: create Entry vertex (payload) + derived Leg vertices/edges + supersession/
              resolution/evidence/approval edges + ExternalId vertices + escrow rights consumption + DraftSet/Case
              membership; SSI witnesses on Period state, Account effectivity, open items, and idempotency keys
 8. ACK       return EntryRef{vid, entry_digest}, MarkerRef, the plan certificate, and next_actions
 9. DERIVE    (asynchronous, supervised) register maintainer advances watermark; indexes; findings; subscriptions
```

Steps 1–6 are pure given a pinned snapshot; the dry run *is* steps 1–6 with no step 7, and its certificate names the snapshot, so a plan an agent reviewed is exactly the plan that commits if the snapshot's witnesses still hold (the substrate's SSI makes "the period closed between my dry run and my commit" an abort with a typed conflict, not a silent post into a closed period).

### 5.2 The balance law

For every committed entry and every unit `u` appearing in its legs: `Σ amount(leg) over debit legs in u = Σ amount(leg) over credit legs in u`, exactly, in `u`'s scale (FA-INV-01 `per-unit`). When the book requires base-unit equivalents (every book does for monetary units other than its base), each monetary leg carries `base_amount` computed under the entry's `fx_law_oid` from rate documents named in `base_totals.rate_doc_oids`, and `Σ base debits = Σ base credits` in the base unit (`base` clause); the arithmetic residual that rounding produces is carried by an explicit leg on the account the FX law names (`fx-residual` clause), so the base-unit balance law is also exact. Memo and statistical units balance among themselves (`memo` clause). There is no tolerance. A proposal that is unbalanced is refused with the per-unit imbalance and, when a registered rounding account exists and the imbalance is within the unit's minor unit, the *suggested* residual leg — suggested in the error, never applied silently.

### 5.3 Registers are folds

A `Register` is the derived cell `(book, branch, account, unit, period, dimension_subset_key) → {debits_posted, credits_posted, debits_pending, credits_pending, entry_count, watermark, fold_digest}`. `RegisterDefinition`s (versioned data) declare which dimension subsets are materialized per account family — "cash by legal entity", "expenses by cost center and project" — exactly as a data warehouse declares aggregates, except the definition is journaled and the cells are *certified folds*.

**Materialization doctrine.** The posting transaction writes the entry and its projections only; it never touches a register (rejected alternative (b) in §3.6). Registers are maintained by the **register maintainer**, a supervised asupersync region that consumes the book's committed delta stream in commit order and advances a published `watermark: CommitSeq` per register definition. A balance read at the head is `register(cell) ⊕ fold(legs of cell in (watermark, head])` — the substrate's "watermark + tail" exactness pattern — so reads are O(1) at the watermark plus a bounded tail scan, and the register is never stale in the answer, only in the cache. A balance read `AS KNOWN AT s` with `s ≤ watermark` folds forward from the nearest retained register checkpoint; registers keep periodic `RegisterCheckpoint`s (a journaled, content-addressed snapshot of all cells at a `CommitSeq`) so historical folds are bounded. `fold_digest` is the BLAKE3 of the canonical sorted leg contributions, so two registers that claim the same value from different histories cannot collide and a recomputation can be compared by digest.

**Verification by recomputation** is a first-class operation (`fa verify registers`): fold every cell from the journal at the register's watermark and compare digests; a mismatch is a correctness defect (FA-INV-04), and the register is discarded and rebuilt from the journal. Registers are never authoritative; statements are computed from registers but *certified* against the fold.

**Interim posture (Appendix H row R-REG).** Until Ripple's `CREATE MATERIALIZED VIEW … REFRESH INCREMENTAL` is live, the register maintainer is FrankenAccounting's own actor over `Database::delta_since` (live today). Its contract — commit-order consumption, idempotent application keyed by `(entry_ref, cell)`, published watermark, checkpoint cadence, exactness by tail fold — is the same contract a Ripple circuit will satisfy, so the switch is a replacement of the maintainer's body, not of any reader. The maintainer's correctness is proved against the reference oracle (§16.2) under the lab runtime with crash points between delta consumption and watermark publication.

### 5.4 Two-phase entries

TigerBeetle's two-phase transfer is adopted as the two-phase **entry**: an entry of class `Pending` reserves its amounts in the `*_pending` register fields without posting; it is later resolved by exactly one entry carrying `pending.resolution_of = EntryRef` and a `RESOLVES {disposition}` edge: `Posts(amount ≤ pending amount)` posts that amount and releases the remainder, `Voids` releases everything, `Expires` is the system's void at timeout. A pending entry may carry `timeout: Duration` measured from its *recorded* instant; expiry is a visibility predicate plus a deterministic sweep (the substrate's `ExpiryEpochAdvance` pattern): the `fa` daemon orders one `ExpirySweep` control entry per configured tick carrying rollback-resistant time evidence, which emits `Expires` resolutions for every pending entry whose deadline passed at that tick — so expiry is journaled, replayable, and never "best effort". Resolution is a new object; the pending entry is immutable; resolving twice is a typed refusal citing the prior resolution (`pending_already_posted|voided|expired`). Holds, authorizations, escrow deposits, grant encumbrances, and purchase commitments are the accounting uses; the pending/posted split is visible in every register and in the trial balance as a declared column.

### 5.5 Balance limits and escrow

An account's `balance_limit` names a FrankenGraphDB **escrow domain** (substrate §4.7) whose value is the account's net balance in its unit and whose bounds encode the limit: `credits_must_not_exceed_debits` ≡ lower bound 0 on a debit-normal account; a budget cap ≡ upper bound on an expense account's period cell; a loan facility ≡ upper bound on drawn principal. Posting consumes escrow *rights* reserved at step 6 and consumed at step 7, so a limit is enforced without locking the hot register: concurrent posts to a cash account proceed in parallel until rights are depleted, at which point the kernel escalates to the ordered path exactly as the substrate specifies — depletion is `NeedsRights`, never a silent overdraft. TigerBeetle's `balancing_debit/credit` flag ("transfer up to the limit") is adopted as the `Balancing` leg option: the leg's amount is `min(requested, available rights)` and the recorded amount is what moved.

**Interim posture (Appendix H row R-ESC).** Until escrow domains land, balance limits are enforced by an SSI-protected read of the limited account's head balance (register + tail) inside the posting transaction, which is correct (serializable) but contends on hot accounts; the §17 contention gate is reported for both postures and the escrow posture is the design.

### 5.6 Subledgers and control accounts

A `Subledger` groups the detail accounts (every customer's receivable) under a control account. FA-INV-12 is a *synchronous* constraint: at every committed coordinate, the fold of subledger detail legs equals the control account's register. The kernel enforces it by construction for FrankenAccounting-native subledgers (a leg on a detail account *is* a leg on the control account's register cell by definition of the register key — the control account is the summary of its subledger subtree) and by matched-pair validation for externally fed subledgers (an external AR system posts a summary entry that must name the detail batch digest it summarizes; a batch whose detail does not fold to the summary is refused).

### 5.7 Application, matching, and reconciliation

Application (a receipt applied to an invoice; a credit memo applied to a bill) is the `settles` list on a leg, validated at step 5 against the target leg's open amount (open amount = original − Σ settlements, a derived cell), creating `SETTLES {amount}` edges; over-application is refused with the open amount. Bank reconciliation is matching `BankLine`s (parsed from statement documents, §9.5) to legs with `MATCHES {method, confidence}` edges: exact matches (amount, date window, reference) are deterministic; heuristic matches are *proposals* on a decision card that a principal with the `reconcile` capability confirms, so the confirmed match carries its approver; an unmatched line after the statement's close date is a finding. Reconciliation state is derived (`Instrument.reconciled_through: DateDay` is a fold over confirmed matches) and attested by a balance assertion (§9.4) that the statement's closing balance equals the mirrored account's register at that date.

### 5.8 Batches, bulk, and migration

A **batch** is a list of proposals committed atomically (TigerBeetle's linked chain): all commit or none, in order, each visible to the next (an invoice and its application in one batch). Batches are bounded (`max_batch_entries`, registry row) and one substrate transaction. **Bulk load** (opening a book from a legacy GL, a 50-million-line migration) uses the substrate's bulk protocol (§7.5 there): chunked, gap-free, source-row-digested manifests, staged and finalized through an ordinary transaction, with `Migration`-class entries carrying `migrated_from` provenance and the opening balances posted as an `Opening`-period entry whose evidence is the legacy trial balance document. A migration never forges `recorded_at` (constraint 6); the first fact the new book knows is "on this date we imported this history", which is exactly what an auditor wants to see.

### 5.9 Idempotency and outcomes

Every proposal carries an `idempotency_key` (client-chosen, ≤ 64 bytes, scoped to the book and principal). A retry with the same key and byte-identical canonical proposal returns the recorded outcome (`EntryRef` or the original refusal); the same key with different bytes is refused as `IdempotencyConflict` with the digest of what was recorded (FA-INV-09, inheriting FG-INV-01). Outcomes are durable before acknowledgement; a client that times out and retries is the normal case, not an edge case.

### 5.10 The write path as substrate choreography

Folio holds the book's `Database` and the single writer lease inside the `fad` daemon (or the embedding process). Each commit is one `WriteBatch` executed under a `TxnCx` narrowed to the ledger graph: it `create_vertex`es the `Entry` with its payload, the derived `Leg`s, the edges, the `ExternalId`s, consumes escrow rights, and `compare_and_set`s the `DraftSet`/`RestatementCase`/`CloseRun` membership counters. The reads at steps 2 and 5 are performed on the same snapshot the transaction validates against, so their witnesses (the `Period` vertex's `state`, the `Account`'s effectivity slice, the target leg's open-amount cell, the idempotency key's absence) enter SSI validation; the substrate's first-committer-wins and dangerous-structure rules turn every race the plan cares about (post vs close, two agents applying the same receipt, duplicate idempotency keys from a retry storm) into a typed conflict (`exit 5`) with a retry hint. Group commit is the substrate's; Folio adds no barrier. The operation-cost registry (Appendix G) maps a single-entry post to the substrate's fused autocommit-write arm (two sequenced commands, one D1 payload barrier, one D2 publication) and a batch to the explicit multi-statement commit; every §17 posting gate is derived from those rows.

---

## 6. Abacus: Exact Money Algebra (Bet A5, part 1)

### 6.1 Representation and arithmetic

`Amount { unit, mantissa: i128 }` at the unit's registered scale (§4.4). Addition, subtraction, negation, comparison, and summation are checked `i128` operations; a unit mismatch is a type error at the API boundary (`Amount` arithmetic is only defined between equal units; conversion is always explicit under a law). Multiplication by a rational factor (a tax rate, an allocation share, an FX rate) and division (a per-unit cost, a pro-rata share) are **wide**: the product `mantissa × numerator` is computed in `fgdb_bigint::BigInt` (limb-limited, checked), divided by `denominator × 10^(scale adjustments)` with an exact quotient and remainder, and then *rounded under a named law* back to the target scale — never a floating-point step, never an intermediate at the wrong scale. `CanonicalDecimal` (scale 18, add/sub/neg only) is the interchange type for rates and factors, with `Rate { numerator: BigInt, denominator: BigInt }` as the exact internal form; a rate document (§6.4) states its decimal digits and is parsed to an exact rational. Percentages, basis points, and per-mille are `Rate`s with a declared denominator. Nothing in `fa-money` imports a float.

### 6.2 Rounding laws

`rounding_laws.toml` registers every admissible rounding: `HalfUp`, `HalfDown`, `HalfEven` (banker's), `HalfAwayFromZero`, `HalfTowardZero`, `Ceiling`, `Floor`, `TowardZero`, `AwayFromZero`, and *regime* laws such as `SwissFiveRappen` (cash rounding to 0.05) and `TaxAuthority(jurisdiction, rule)` (a jurisdiction's statutory rounding for VAT lines). Each law row carries its exact definition over `(quotient, remainder, denominator)`, golden vectors at every scale, and its proof-lane row (the Lean lane proves `|rounded − exact| ≤ ½ ulp` for the half-* family and `< 1 ulp` for the directed family). Every computed amount in an entry, report, or finding records the law under which it was rounded; a report certificate lists the laws used; a change of a unit's default law is a journaled registry change that does not rewrite history.

### 6.3 Allocation laws

Allocation distributes an amount across *n* targets by weights and must conserve the total exactly. `allocation_laws.toml` registers `LargestRemainder` (Hamilton: floor each share, distribute the residual units to the largest fractional remainders in deterministic tie order), `ProRataResidualToNamed(target)` (round each share under a rounding law, post the residual to the named target leg), `Waterfall(tiers)` (fill tiers in order with caps), `Tiered(brackets)` (progressive bands, for tax and commission schedules), `EqualSplitResidualFirst`, and `ByUnitsThenValue` (two-key allocations). Each law carries the conservation theorem `Σ shares = total` (Lean lane), determinism of tie-breaking (CGSE policy id), and golden vectors; Canon rules invoke allocations by law id, and the resulting legs record the law and basis digest so an auditor can recompute a cost-center allocation from its driver table.

### 6.4 FX laws and rate documents

A rate is evidence, not configuration: an `FxRateDocument` is a `Document` of kind `Rate` with `{source, base_unit, quote_unit, rate: CanonicalDecimal, digits, as_of: DateDay|Instant, retrieved_at, retrieval_proof?}`. An `FxLaw` row fixes: which rate document class a book accepts for which purpose (`transaction`, `period_end`, `average`), the inverse convention (whether `EUR/USD` may be inverted and at what precision), the triangulation rule through the base unit when no direct rate exists, the rounding law for base-amount computation, and the residual account. Transaction conversion at step 4 records `fx_law_oid` and the rate document oids on the entry; period-end **revaluation** (monetary balances remeasured at the closing rate) and **translation** (a foreign-functional-currency entity's statements translated into the reporting currency with the cumulative translation adjustment in equity — ASC 830 / IAS 21 mechanics) are Canon rules under laws of kind `Revaluation` and `Translation` whose entries are `Revaluation`-class and carry the rate documents and the computation basis (§12.4).

### 6.5 Quantities beyond currency

Shares, units of inventory, hours, tokens, and commodities are units with their own scale; a securities account holds `AnyUnit` legs; cost basis is a separate monetary leg linked by `settles`-style lot edges (lot accounting — FIFO/LIFO/specific-identification/average — is a Canon rule family under registered laws, not a kernel feature). Unit conversion (ounces to grams, hours to days) is never implicit; a `ConversionLaw` row with exact factors exists or the conversion is refused.

### 6.6 Canonical encoding and cross-crate determinism

Amounts encode as `(unit_id: u32, mantissa: i128 LE)`; rates as canonical `BigInt` numerator/denominator bytes; laws by registry id and epoch. Every arithmetic result is bit-identical across machines because no step depends on a float, a platform integer width, or iteration order over a hash map (all aggregations iterate in canonical sorted order). The cross-crate determinism harness (the substrate's `w1_cross_crate_determinism_e2e` pattern) runs the same allocation and FX vectors through `fa-money` on every target and compares digests.

### 6.7 Formal anchors

Lean lanes: group laws for `Amount`; rounding error bounds per law; allocation conservation per law; FX round-trip bounds (`convert(convert(a, L), L⁻¹)` differs from `a` by at most the registered bound under the inverse convention); balance-law preservation under reversal and replacement (a reversal's legs are the exact negation; a replacement chain's net equals the replacement). Each theorem has a proof-lane manifest naming scope and what remains unproved (bigint limb limits are assumptions, not theorems).

---

## 7. Almanac: Time, Periods, and the Close (Bet A2, part 1)

### 7.1 Two axes and a third coordinate

**Known-at** (system time) is the commit stream's `CommitSeq`/HLC: immutable, total, assigned by the substrate. **Effective** (valid time) is the civil-date axis every entry is anchored to and every period, account, dimension value, policy, and relationship is sliced on. **Branch** is the third coordinate. They are orthogonal: `FOR PERIOD FY2024-Q4 AS KNOWN AT 2025-03-03` answers "what did the books say on March 3rd about Q4", `… AS KNOWN AT HEAD` answers "what do they say now", and the difference between the two is the set of entries recorded after March 3rd with effective dates in Q4 — a restatement, an adjustment, or a late posting, each distinguishable by class. Omitted known-at means head; omitted effective means all time; neither ever means an ambient wall clock.

### 7.2 Fiscal calendars

A `FiscalCalendar` generates `Period`s deterministically from its kind: `Monthly12(year_start_month)`, `Weeks445|454|544(year_start_rule)`, `Week5253(end_rule: {LastWeekdayOfMonth(wd, m), WeekdayNearestEnd(wd, m)})`, and `Custom(explicit period list)`. Generation is a pure function with golden vectors through 2100 (including 53-week years and leap days). A book has exactly one calendar; a legal entity may declare a different statutory calendar used by its statutory book (§12.2). Adjustment periods (a 13th period for audit adjustments; an `Opening`/`Closing` period) are ordinary `Period` vertices with `kind` set. Civil-date arithmetic (proleptic Gregorian, day-of-week, month-end, ISO weeks, business-day calendars with holiday tables as data) is built in `fa-time` with no external crate, checked against a brute-force reference and the substrate's `Date` canonical type.

### 7.3 The period state machine and the period law

`state ∈ {Future, Open, SoftClosed, Closed, Locked}`. Transitions are control entries (class `PeriodControl`) with approvals: `Open` (from `Future`), `SoftClose`, `Close`, `Lock`, `Reopen(to: Open|SoftClosed, case_ref)`. Every transition is journaled with its principal and reason, so "who reopened March and why" is a query. The **period law** (FA-INV-03): an entry's `effective_date` resolves to exactly one `Period` of the book's calendar; the entry's class must be admissible for that period's state under Appendix C's matrix *and* the principal's capability must carry the required operation; `Locked` admits only `Restatement`-class entries inside an approved `RestatementCase` under dual control; `Closed` admits `Adjusting`, `Reclassification`, `Reversal`, and `Elimination` under the `post_closed` capability; `SoftClosed` admits everything `Open` admits except `Original` from non-controller principals (the soft close is "the accountants are closing; agents stop posting ordinary entries"). The read of `Period.state` at step 2 is an SSI witness; a close that commits after a dry run and before the commit aborts the post with `PeriodStateChanged {was, now}`.

### 7.4 Selectors

Native selectors in FrankenAccounting's GQL extension and in every CLI/MCP read: `AS KNOWN AT <instant|seq|HEAD>`, `FOR PERIOD <code>[..<code>]`, `EFFECTIVE AT <date>` / `EFFECTIVE BETWEEN <date> AND <date>`, `AT BRANCH <name>`, and the two restatement views `AS ORIGINALLY REPORTED` (the earliest known-at at which the period was `Closed`) and `AS CURRENTLY STATED` (head). A fifth, `AS REPORTED IN <statement_certificate>`, pins exactly the closure a published statement used, so a regulator can reproduce a filed schedule byte-for-byte years later.

### 7.5 The close as a graph

A `CloseRun` is a control object for `(book, period)` with a checklist of `CloseTask`s (vertices) and `DEPENDS_ON` edges: reconcile every bank instrument, post accruals, run depreciation, revalue monetary balances, run allocations, match intercompany, generate eliminations, roll forward, produce statements, obtain attestations, lock. Each task names the Canon rule or procedure that performs it, its evidence requirement, its approver role, and its completion attestation; the run is itself a DAG whose readiness is computed by the substrate's cycle/topological procedures. **Every close is first rehearsed on a branch** (`fa close dry-run --period 2026-03` forks a draft, executes every automated task, produces the statements, and reports the diff against the prior period and against the live book) and then executed on trunk with the same certified plan; the rehearsal's certificate is attached to the live run. Year-end `Closing`-class entries (close revenue and expense to retained earnings) are real, immutable entries generated by the `YearEndClose` rule; the next year's `Opening` period carries nothing but the opening balances derived from them.

### 7.6 Accruals, reversals, recurring entries, cutoff

An `Adjusting` entry may declare `auto_reverse_on: DateDay`; the kernel then posts the paired `Reversal`-class entry as a *scheduled* control effect at the first `ExpirySweep` tick on or after that date, under the original entry's approval (the reversal is part of the approved plan). Recurring entries are a `RecurringSchedule` control object that mints proposals on schedule under a stripped `Cx` whose "today" is the tick's time evidence. Cutoff tests compare `document_date`, `effective_date`, and `recorded_at` per period boundary (Lantern §11.7).

### 7.7 Calendar arithmetic and time zones

`fa-time` implements civil dates, durations in days/months with explicit end-of-month policy (`PreserveDay`, `ClampToMonthEnd`, `LastDayStaysLast`), business-day calendars, and period generation; instants are UTC and come only from the substrate. The book's `time_zone_policy` governs how an instant on a document is converted to an effective civil date when a rule needs one (always explicit, always recorded on the entry as `effective_date_basis`).

### 7.8 Interim posture before valid-time contracts

Until the substrate's `ValidTimeContract` is live (Appendix H row R-VT), `effective_date` is an ordinary indexed `DateDay` property; period membership, account and dimension effectivity, and relationship intervals are enforced by `fa-time`'s interval algebra in the posting kernel (same laws, same oracle) with range witnesses supplied by the substrate's existing index-range witnesses. The selectors of §7.4 are implemented by FrankenAccounting over those properties. When the contract lands, the same elements are migrated under the substrate's shadow-build/validate/activate pattern with a differential run of every §16 temporal test on both representations before the switch; the decision is a registered row, not a silent change.

---

## 8. Palimpsest: Amendments, Restatements, and Supersession (Bet A2, part 2)

A palimpsest is a manuscript scraped and written over, with the original still legible beneath. That is the exact property an accounting system needs and almost none has: the books as currently stated *and* the books as originally posted, both first-class, with the lineage between them a queryable object.

### 8.1 Entry classes

`entry_classes.toml` is the closed registry; every entry carries exactly one class, and the class determines admissibility (Appendix C), required supersession targets, required approvals, and which registers it touches.

| Class | Meaning | Supersession | Typical origin |
|---|---|---|---|
| `Original` | An ordinary posting of a new fact | none | Intent, rule |
| `Pending` | Two-phase reservation (§5.4) | none | Intent, rule |
| `Resolution` | Posts/voids/expires a pending entry | `RESOLVES` exactly one `Pending` | Intent, sweep |
| `Reversal` | Exact negation of one target entry, same or later period | `SUPERSEDES {Reverses}` one target | Intent, auto-reverse schedule |
| `Replacement` | The corrected entry in a reversal+replacement pair | `SUPERSEDES {Replaces}` one target, must be paired with its `Reversal` in the same batch | Intent |
| `Reclassification` | Moves amounts between accounts/dimensions with no P&L effect beyond classification | `SUPERSEDES {Reclassifies}` ≥ 1 target legs | Intent, rule |
| `Adjusting` | Accruals, deferrals, estimates, period-end adjustments | optional | Rule, close |
| `Closing` | Year-end close of nominal accounts | none | `YearEndClose` rule |
| `Allocation` | Distribution under an allocation law | none; records law and basis | Rule |
| `Revaluation` | FX remeasurement/translation under an FX law | none; records law and rate documents | Rule |
| `Elimination` | Intercompany/consolidation elimination in a consolidation book | references the `INTERCOMPANY_WITH` pair | Rule |
| `Migration` | Opening balances and legacy history import | none; `migrated_from` provenance | Bulk load |
| `Revision` | Immaterial prior-period correction ("little r") | `SUPERSEDES {Revises}`; inside a `RestatementCase` of kind `Revision` | Case |
| `Restatement` | Material prior-period correction ("Big R", ASC 250 / IAS 8) | `SUPERSEDES {Restates}`; inside an approved `RestatementCase` | Case, dual control |
| `PriorPeriodAdjustment` | Adjustment to opening retained earnings for a prior-period error | inside a case | Case |
| `PeriodControl` / `SchemaControl` / `PolicyControl` | State-machine transitions, chart and registry changes | none | Controller |

### 8.2 Supersession lineage and netting

`SUPERSEDES` edges form a DAG rooted at original entries (FA-INV-08: acyclic; every target exists; a `Reversal` negates exactly; a `Replacement` is paired). Two derived views are maintained as registers: **as currently stated** (every entry, with superseded entries still present because their reversals net them out — the ledger never hides anything) and **as originally posted at known-at *t*** (the fold of entries recorded ≤ *t*). The **net effect** of a lineage chain is a computed object (`fa explain lineage <entry>`) listing original, reversals, replacements, and the net legs; a chain whose net is zero is a "fully reversed" fact and is reported as such. Reason codes are a registered vocabulary (`reason_codes.toml`: `DataEntryError`, `WrongAccount`, `WrongPeriod`, `WrongAmount`, `Duplicate`, `EstimateChange`, `PolicyChange`, `Fraud`, `AuditAdjustment`, `RegulatoryDirective`, `Other(text)`), so the reasons for corrections are themselves analyzable (Lantern §11.7 reports reversal-pattern anomalies by preparer and reason).

### 8.3 Restatement cases

A `RestatementCase {kind: Revision|Restatement|PriorPeriodAdjustment|PolicyChangeRetrospective, periods_affected[], disclosure: Document, authority: approvals[], status}` is the control object that makes a material correction legal in a `Locked` period. Its life cycle is `Proposed → Rehearsed (on a branch, with the as-reported-vs-as-restated diff certificate attached) → Approved (dual control, by principals with `restate` capability, neither of whom prepared any entry in the case) → Posted (the case's entries commit in one batch) → Disclosed (the disclosure document is attested) → Closed`. The **restatement diff certificate** is a certified computation of every affected statement line as originally reported, as restated, and the delta, with the lineage of every contributing entry — the document a company's audit committee, its auditor, and the SEC comment-letter process all need, generated rather than assembled. Retrospective application of a policy change (new revenue-recognition policy applied to comparatives) is the same machinery with `kind: PolicyChangeRetrospective` and the policy versions named.

### 8.4 Admissibility

Appendix C is the normative matrix of `Period.state × EntryClass → {Admit, AdmitWith(capability, approvals), Refuse}`. Two rules are universal: an `Original` entry is never admissible in `Closed` or `Locked`; a `Restatement` is only admissible inside an `Approved` case. The matrix is a registry (`admissibility.toml`) with a generated exhaustive test, so a new class or state cannot be added without a decision for every cell.

### 8.5 Erasure, legal holds, and retention

Amounts, accounts, dates, and lineage are never erased. Personal data lives in `Party` overflow maps and in `Document` bytes; a lawful erasure request is an `ErasureCut` control entry under the substrate's erasure-tombstone mechanism: the subject's bytes are crypto-erased, a typed tombstone remains, every certificate whose closure included the erased bytes has its `ReplayCompleteness` grade downgraded to `Redacted` *attributably* (FG-INV-19's arm), and the entry digests that covered the document bytes remain verifiable against the tombstone's recorded digest. A `LegalHold {scope, authority, issued_by}` control entry pins every object in scope against erasure, GC, and retention expiry until released by an authorized principal; holds are visible to the auditor profile and their release is journaled. Retention floors (seven years for most jurisdictions' books; longer under hold) are `Policy` objects that the substrate's retention tiers honor.

### 8.6 Migration from legacy systems

A migration is a `Migration`-class batch with: the legacy trial balance as a `Document`, opening balances posted into the `Opening` period, optional legacy journal detail imported as `Migration` entries whose `effective_date` is the legacy effective date and whose `migrated_from` carries the legacy journal id, entered-by, entered-at, and approved-by fields (the AICPA ADS columns map one-to-one), and a `MigrationAttestation` by the principal responsible that the imported detail folds to the legacy trial balance (the kernel computes and the attestation signs the digest). Legacy "as known at" is lost by definition and the book says so: `AS KNOWN AT` any instant before the migration returns `BeforeBookGenesis`, never a reconstruction.

---

## 9. Docket: Evidence, Provenance, and Custody (Bet A3, part 1)

### 9.1 Documents

A `Document` is a content-addressed object: `{oid (BLAKE3 of canonical bytes through the substrate's keyed ObjectId), kind: {Invoice, Bill, Receipt, Contract, BankStatement, Rate, Confirmation, Memo, Email, Spreadsheet, Image, Disclosure, Workpaper, Other}, mime, size, storage: Inline{object} | External{locator, fetch_proof}, parsed: Option<ParsedProjection>, redaction: Option<RedactionContractRef>, retrieved_by, retrieved_at (recorded), custody: ImportReceiptRef}`. Inline storage puts the bytes in the book's commit stream (erasure-coded, encrypted, deduplicated by digest); external storage records a locator and a `fetch_proof` (the digest observed at import plus the import receipt), and a later fetch that does not match the digest is a finding, not a silent substitution. Parsing (a `camt.053` statement into `BankLine`s; an invoice PDF's extracted fields) is a derived projection with its parser version recorded; the bytes are the evidence, the projection is a convenience. Bulk evidence (a year of statements) is bounded per document and per book by registry rows and reported in the byte-economy metrics.

### 9.2 The provenance closure of an entry

The closure is the set an outsider needs to verify "why": the entry's evidence documents (`EVIDENCED_BY`), its REA event and the rule version that derived it (`DERIVED_FROM`, `GENERATED_BY`, with the rule's inputs digest), its principal and session, its approvals, every rate or basis document its arithmetic consumed, the allocation driver tables, and — for a resolution, reversal, or restatement — the target entries. FA-INV-05: every committed entry's closure is strongly retained for the retention floor and is enumerable by `fa explain evidence <entry>`; an entry whose `origin` names an unregistered source is unencodable. The closure's digest is part of the entry's certificate, so an agent can hand a reviewer one hash that covers the entry and everything it rests on.

### 9.3 Chain of custody

An `ImportReceipt {source: {Upload(principal), Connector(name, version), Email(message_id), Scan(device)}, received_at (recorded), digest_at_receipt, transformations[]}` is created for every document the book ingests, before any parsing; the chain from receipt through every derived projection is edges with versions. Productions to third parties (a litigation production, a regulator's request) are `Bundle`s (§13.2) whose manifest records what was produced, under which capability, with which redactions, and the recipient's acknowledgment attestation if returned.

### 9.4 Attestations

An `Attestation {claim, subject_refs[], principal_ref, signature: {scheme, key_id, bytes}, signed_digest, evidence_refs[], recorded_at}` is a signed statement about objects: a preparer's "I prepared this", a reviewer's "I reviewed this against the invoice", a controller's "this reconciliation is complete", an external auditor's "we have examined these bundles", a bank's confirmation. The **balance assertion** (from plain-text accounting, upgraded) is an attestation whose claim is `RegisterEquals {cell, amount, as_of_effective, as_known_at}` with the evidence (a bank statement) attached; the kernel evaluates it on commit and continuously thereafter — a later entry that makes an attested balance false is admissible (the books are the books) but produces a finding citing the attestation, so a reconciled balance cannot silently drift. Signature schemes are the substrate's authenticated-type profiles; external signatures (an auditor's PKI certificate) are stored as documents with the verification record.

### 9.5 Bank statements and external records

`fa-formats` parses ISO 20022 `camt.053`/`camt.052`, BAI2, OFX/QFX, MT940, and declared CSV layouts into `BankLine {instrument_ref, booking_date, value_date, amount, counterparty, reference, statement_oid, line_ordinal, line_digest}` vertices under `PARSED_FROM` edges to the statement document. Statement sequence continuity (opening balance equals prior closing; statement numbers contiguous) is checked at import and gaps are findings. Lines match legs (§5.7); unmatched lines are the raw material of the bank-reconciliation procedure and of the kiting and lapping detectors.

### 9.6 Redaction contracts, retention, holds

A `RedactionContract` on a document class declares which fields or byte ranges are privileged and under which capability they are visible; the substrate's redaction (§12.6 there) hides the bytes while the document's digest, size, kind, and its evidentiary edges remain visible, and the proof that a redacted document is the one an entry cites still verifies (the digest is over the unredacted canonical bytes; the redacted projection carries a redaction proof). Amounts, dates, and accounts are never redactable. Retention and legal holds are §8.5.

### 9.7 Who read what

Every read under an `Auditor`, `Regulator`, `Investigator`, or `Production` capability (§14.4) records an `AccessEvent {capability_ref, principal_ref, snapshot_seq, query_digest, objects_touched_digest, recorded_at}` in the system graph — sampled under load for ordinary profiles, complete for the external profiles. The access log is itself an append-only, queryable graph (`MATCH (a:AccessEvent)-[:READ]->(d:Document {kind: 'Contract'}) WHERE a.recorded_at > $t RETURN a.principal`), which is what a privilege-log or a regulator's own audit of the examination needs.

---

## 10. Canon: Posting Rules and Typed Intents (Bet A6, part 1)

### 10.1 Why a rules language

Every serious ledger has one: SAP's account determination, Oracle's subledger accounting rules, Formance's Numscript, Beancount's plugins, the thousand-line stored procedures that generate entries in a bank's core. They are where the accounting policy actually lives, and they are uniformly unversioned, side-effecting, untestable in isolation, and invisible to the auditor. Canon makes the rule a first-class, content-addressed, deterministic, *total* object: a rule version is a `RuleVersion` vertex; an entry records which version derived it from which event; re-evaluating the version over the event reproduces the entry byte-for-byte; and a rule that could not be evaluated (a missing rate, an unknown account) fails closed with a typed error instead of posting a guess.

### 10.2 Typed intents

An **intent** is the agent-facing unit of work: a typed, validated request whose dry-run plan is deterministic and whose commit is idempotent. `intents.toml` registers each intent's schema, required capability, admissible entry classes, and which Canon rule family it invokes. The 1.0 catalog (normative fields in Appendix B):

| Intent | What it does | Rule family |
|---|---|---|
| `PostEntry` | Post explicit legs (the escape hatch; everything below could be expressed as it) | none |
| `PostBatch` | Atomic list of intents | none |
| `RecordEvent` | Record an REA event and let the book's rules derive entries | event → entries |
| `RecordInvoice` / `RecordBill` | AR/AP originals with tax and dimension handling | sales/purchase |
| `ApplyPayment` / `ApplyReceipt` | Settlement against open items (`settles`) | application |
| `Hold` / `PostHold` / `VoidHold` | Two-phase (§5.4) | two-phase |
| `Accrue` / `Defer` (with `auto_reverse_on`) | Adjusting entries | adjusting |
| `Reclass` | Move amounts between accounts/dimensions | reclassification |
| `Reverse` / `Replace` | Reversal; reversal+replacement pair | supersession |
| `Allocate` | Distribute under an allocation law with a driver table | allocation |
| `Revalue` / `Translate` | FX period-end (§12.4) | revaluation |
| `Depreciate` / `Amortize` | Fixed-asset and intangible schedules | schedules |
| `MatchBank` / `ConfirmMatch` / `AssertBalance` | Reconciliation (§5.7, §9.4) | reconciliation |
| `OpenAccount` / `CloseAccount` / `PromoteToSummary` / `ImportChart` | Chart control | schema control |
| `OpenPeriod` / `SoftClose` / `ClosePeriod` / `LockPeriod` / `ReopenPeriod` | Period control (§7.3) | period control |
| `RunClose` (dry-run / execute) | Close orchestration (§7.5) | close |
| `OpenRestatementCase` / `RehearseCase` / `ApproveCase` / `PostCase` / `DiscloseCase` | §8.3 | case |
| `AttachEvidence` / `Attest` / `ImportDocument` | Docket | evidence |
| `Migrate` | §8.6 | migration |
| `IssueCapability` / `Revoke` / `LegalHold` / `ReleaseHold` / `ErasureCut` | Steward (§14) | governance |
| `ForkDraft` / `PromoteDraft` / `DiscardDraft` / `ForkScenario` / `DiffBranches` | A6 (§15.2) | branches |

Every intent returns the same envelope: `{outcome, entry_refs[], plan_certificate, register_deltas[], warnings[], next_actions[]}`. Every intent accepts `dry_run: true` and returns the plan without committing; intents whose class is irreversible-in-practice (`LockPeriod`, `PostCase`, `ErasureCut`, `Migrate`) *require* a prior dry-run certificate to be presented (`confirm_plan: <certificate_id>`) so an agent cannot lock a period with one call it never previewed.

### 10.3 The rule language

Canon is a small, statically typed, total, pure language whose programs map a typed event (plus explicitly declared inputs: rates, tables, the effective date, the chart at that date) to a list of candidate legs. Its design rules: no loops without a static bound; no recursion; no I/O; no clock; no entropy; no string-to-number parsing at runtime (parsing is a declared input transformation with a parser version); every arithmetic operation names its rounding law or inherits the unit's default; every account reference is by code resolved at the entry's effective date; pattern-matching over event kinds is exhaustive. A sketch:

```text
rule sales_invoice v7 for event Sale {
  inputs { tax_table: TaxTable@oid, revenue_map: AccountMap@oid }
  let gross = event.lines.sum(l => l.quantity * l.unit_price round HalfEven)
  let tax   = tax_table.apply(event.jurisdiction, event.lines) round TaxAuthority(US-CA)
  debit  "1200-AR"                      gross + tax   dims { customer = event.party }
  credit revenue_map[event.product_class] gross        dims { product = event.product }
  credit "2300-SalesTaxPayable"          tax           dims { jurisdiction = event.jurisdiction }
  effective event.invoice_date
  evidence event.documents
}
```

The compiler produces a content-addressed typed IR (`RuleVersion.ir_oid`), type-checks units (a `USD` amount cannot be added to a `JPY` amount; a quantity times a price yields the price's unit), proves totality by construction, and records the rule's static dependency set (which accounts, tables, laws, and units it may reference) so a chart change that removes an account a live rule references is refused with the rule's name. The IR's compile target is the substrate's deterministic UDF VM (Appendix H row R-VM); the interim evaluator is a tree-walking interpreter over the same IR under a stripped `Cx`, with the IR frozen so compiled and interpreted execution are differentially tested on every rule's golden corpus. Rules are versioned by content and *activated* by a `PolicyControl` entry naming the version and its effective date range; the same event evaluated under two active books (US GAAP and tax) may bind different rule versions (§12.2).

### 10.4 Dry-run semantics

A dry run executes steps 1–6 of §5.1 on a pinned snapshot and returns the plan: candidate legs with resolved accounts and dimensions, per-unit and base totals, the period decision with the matrix cell cited, the SoD decision, escrow rights required and available, the evidence closure heads, register deltas at head, warnings (a round amount, an unusual account for this rule, an effective date in a soft-closed period), and a plan certificate pinning the snapshot, rule versions, laws, and registry epochs. Committing with `confirm_plan` re-validates the witnesses; if anything the plan depended on changed, the commit is refused with `PlanInvalidated {changed: [...]}` and a fresh plan, never silently re-planned.

### 10.5 Rule testing

Every rule version ships a golden corpus (`rules/<name>/golden/*.toml`: event → expected legs) and property tests the compiler generates for free: every output of every rule satisfies the balance law (it must, by construction — the compiler refuses a rule whose debit and credit expressions cannot be proven equal per unit, and inserts a residual leg only where the rule names a residual account and law), every output is in the rule's declared account set, and evaluation is byte-deterministic across platforms. Rule changes are reviewed as diffs of IR and of golden outputs.

### 10.6 Agents authoring rules

Rules are data an agent may propose (`fa rule propose --file`), test on a draft against historical events (`fa rule backtest --rule x@v8 --events 2025-Q1 --compare x@v7`, which reports every entry that would differ), and submit for activation under the `rule_change` capability with dual control. An activated rule's provenance names the proposing agent's program, model, and session, so "which model wrote the revenue rule that caused the restatement" is a query the system answers.

---

## 11. Lantern: Forensic and Audit Analytics (Bet A4)

### 11.1 Procedures are registered, deterministic, certified computations

`procedures.toml` registers every analytic: its id, inputs (coordinate, scope predicate, parameters with defaults), the claim class of its output (`statistical` for every score and threshold test; `invariant`-derived only for exact reconciliations), its assumptions, its CGSE tie-break policy for rankings, its complexity bound (witness-locked in CI), and its evidence row (`FA-EVID-*`). A procedure runs under a stripped `Cx` over a pinned snapshot and emits `Finding`s (§11.8) plus a certificate; the same inputs produce the same findings bit-for-bit, so an opposing expert can rerun the exact procedure. Thresholds are decision cards with pinned deterministic defaults (Nigrini's conformity ranges, the AS 2401 heuristics' parameters) and may be tuned per engagement with the tuning recorded.

### 11.2 Journal-entry testing (AS 2401 / ISA 240 mechanized)

`jet.unusual_accounts` (entries to seldom-used accounts, measured by the account's posting frequency distribution over the lookback), `jet.unusual_preparers` (principals who rarely post, or post outside their role's account set), `jet.period_end_timing` (entries recorded in the last *k* days of a period or after `SoftClose`), `jet.post_closing` (entries with effective dates in a `Closed`/`Locked` period — the top-side population by construction), `jet.thin_descriptions` (empty, short, or templated descriptions; near-duplicate descriptions by edit distance), `jet.round_amounts` (round-number and consistent-ending-digit entries), `jet.manual_vs_rule` (`origin: Intent` entries in account families normally fed by rules), `jet.weekend_holiday` (recorded on non-business days per the book's calendar), `jet.self_approved` (preparer = approver; impossible under SoD, so its presence proves a capability misconfiguration), `jet.large_round_reversals`, `jet.suspense_aging` (balances in clearing/suspense accounts by age), `jet.intercompany_unmatched`. Each emits findings with the exact entries, the statistic, and the population baseline.

### 11.3 Digit and number analytics

`benford.first_digit|second_digit|first_two_digits` (chi-square, MAD against the conformity ranges, Z per digit; population and scope stated), `numbers.round_amount_density`, `numbers.threshold_splitting` (clusters of amounts just below an approval or reporting threshold, grouped by party and window — the structuring detector; thresholds come from the book's approval policy and from a registered table including the $10,000 CTR threshold), `numbers.relative_size_factor` (largest-to-second-largest ratio per party), `duplicates.same_same_same|same_same_different` (amount/party/date and amount/party/different-date), `duplicates.near` (amount within a tolerance and description similarity), `numbers.sequence_gaps` (gaps in external invoice/check sequences — the completeness assertion's mechanical half).

### 11.4 Graph procedures

Over the ledger graph and the `PAID` money-flow projection: `graph.related_party_exposure` (temporal closure of `OWNS`/`CONTROLS`/`RELATED_TO` as of each entry's effective date, intersected with counterparties; total exposure per related party), `graph.circular_flows` (simple cycles in the money-flow graph within a window, weighted by amount — round-tripping), `graph.layering` (paths of length ≥ 3 through intermediaries with ≥ 90% pass-through within *d* days), `graph.concentration` (betweenness and flow centrality of parties and instruments), `graph.communities` (Louvain/Leiden over flows to surface clusters of apparently unrelated parties that transact only with each other), `graph.kiting` (temporal cycles across bank instruments where a deposit's funding check clears after the deposit is drawn — modeled on `BankLine` value dates and the float), `graph.ponzi_motif` (inflows from new investors in window *w* funding outflows to earlier investors, with the new-money-to-redemptions ratio by period; investor cohorts by first-inflow date), `graph.shell_signature` (parties with no documents, no employees, address or bank shared with another party, and pass-through flows), `graph.ultimate_beneficiary` (max-flow decomposition of where money finally rests). Every graph procedure names the `fnx` algorithm and its CGSE policy in its certificate.

### 11.5 Tracing laws

Constructive-trust tracing through commingled accounts is a registered algorithm family, not an analyst's spreadsheet: `trace.libr` (lowest intermediate balance rule: the claimant's traceable amount in an account never exceeds the lowest balance between deposit and claim), `trace.fifo`, `trace.lifo`, `trace.pro_rata` (the *Cunningham v. Brown* pro-rata sharing used in Ponzi distributions), `trace.restitution_order` (a parameterized law set by the court's order). Each takes a source set (tainted inflows), a window, and an instrument set, and emits a traced-amount schedule per instrument and per period with the full path evidence — every `BankLine` and leg along the way — and a certificate. Two experts applying `trace.libr` to the same book with the same parameters get the same schedule; a dispute is then about the parameters, which the certificate names.

### 11.6 Solvency and lookback analysis

`solvency.balance_sheet_test` (assets vs liabilities at fair-value adjustments supplied as documents, at a point in time, `AS KNOWN AT` optionally pinned to what management knew), `solvency.cash_flow_test` (ability to pay debts as they come due over a horizon, from the aging and commitments), `lookback.preferences` (transfers to creditors within 90 days / 1 year for insiders with the insider closure from `RELATED_TO`), `lookback.fraudulent_transfer` (transfers for less than reasonably equivalent value within the statute's window, with value documents), `damages.but_for` (a `Scenario` branch with the counterfactual intents applied; the delta of statements between the branch and trunk is the damages schedule, certified).

### 11.7 Reconciliation, cutoff, aging, matching, sampling

`recon.bank` (unmatched lines and legs, timing differences, outstanding items by age), `recon.subledger_control` (FA-INV-12 as a report, with the detail that differs when the invariant is violated by an external feed), `recon.intercompany` (unmatched pairs and FX differences), `cutoff.period_boundary` (document date vs effective date vs recorded time around each boundary), `aging.ar|ap|inventory` (buckets by effective date and open amount), `match.three_way` (PO, receipt, invoice documents and legs), `reversal.patterns` (reversal rates by preparer, reason, account, and month), `sample.mus` (monetary-unit sampling with a declared seed, interval, and expected misstatement; the sample is reproducible from the certificate), `sample.random|stratified` (seeded), `confirm.coverage` (which balances have external confirmation attestations).

### 11.8 Findings

A `Finding {procedure_id, version, parameters_digest, coordinate, severity: {Info, Low, Medium, High, Critical}, statistic, population, cites[], narrative_template, status: {Open, Reviewed, Dismissed(reason, principal), Escalated(case_ref)}, certificate_ref}` is a journaled vertex with `CITES` edges to every entry, leg, party, document, register, or attestation it rests on. Findings are immutable; review and dismissal are new control effects with lineage, so "which findings did the prior auditor dismiss and why" survives. Workpaper export (`fa workpaper export --finding F --format md|json|csv`) produces a stable-numbered document (`FA-<book>-WP-<seq>`) whose every reference is a verifiable handle.

### 11.9 Claim typing and calibration

A detector's output is `statistical` evidence. Its `FA-EVID-*` row names the population, the selection rule, the assumptions (Benford applies to naturally occurring, multi-order-of-magnitude, non-assigned numbers — invoice numbers are excluded by rule), the false-positive expectation, and the deterministic fallback. Learned scores (an anomaly model) are admissible only as advisory features on a decision card with the analytic procedure as the pinned fallback, and never as a finding's sole basis (A5; the substrate's §1 constraint 10 inherited). A finding is never an accusation; it is a reproducible observation with evidence.

### 11.10 Synthetic corpora and ground truth

`fa-gen` generates synthetic books with labeled scenarios — a clean retailer; a retailer with channel stuffing and bill-and-hold; a bank with kiting across three instruments; an investment vehicle running a Ponzi scheme with cohorts; a shell network with layering and structuring; a company with a WorldCom-style capitalization of expenses and top-side entries; a payroll with ghost employees — each with the planted facts recorded, so every Lantern procedure has precision/recall measured on known truth, reported as `FA-EVID` rows beside the published thresholds. The generator is deterministic by seed and is also the benchmark fixture generator (§17).

### 11.11 Audit assertions → mechanisms

| Assertion | Mechanism |
|---|---|
| Existence / occurrence | Every leg's entry carries evidence (FA-INV-05); confirmations as attestations; `sample.mus` with evidence pull |
| Completeness | Sequence-gap procedures; statement continuity at import; the ADS export's inclusion proofs for the full range; cutoff tests |
| Accuracy / valuation | Exact arithmetic under named laws (A5); rate documents; allocation driver tables; FX laws; certified recomputation |
| Cutoff | `cutoff.period_boundary`; effective vs document vs recorded time |
| Classification / presentation | Strict chart types; statement definitions as data; reclassification lineage |
| Rights and obligations | Instruments `HELD_AT`; contract documents; related-party closure |
| Authorization (controls) | SoD at commit; approvals bound to digests; capability log; `jet.self_approved` must be empty |

---

## 12. Statements and Concordat: Reports, Multi-Book, FX, and Consolidation

### 12.1 Statement definitions as data; reports as certified computations

A `StatementDefinition {kind: {TrialBalance, BalanceSheet, IncomeStatement, CashFlowIndirect, CashFlowDirect, EquityRollForward, Aging, GLDetail, Custom}, lines[{code, label, mapping: AccountSetExpr | Formula(lines), sign, subtotal_of}], comparatives, presentation_unit, rounding_law, version}` is a journaled, content-addressed object; a company's balance-sheet layout under US GAAP, the same under IFRS, and a bank's call-report schedule are three definitions. A report run is `(definition@oid, coordinate, parameters) → rows + certificate`; rows are computed from registers (verified against the fold at the register's watermark, with the tail folded exactly) and the certificate pins definition, coordinate, registry epochs, laws, rate documents, and the register checkpoints used. Reports are pure: the same certificate replays to the same bytes (FA-INV-11). The indirect cash-flow statement is a definition over account *movements* with declared non-cash adjustments; the direct method uses the money-flow projection; both are certified. Presentation rounding (thousands, millions) is a law and a declared residual line, so a presented statement foots exactly.

### 12.2 Multi-book

A `Book` per basis (US GAAP, IFRS, tax, statutory, management) shares entities, parties, instruments, units, and calendars (statutory may differ) and has its own chart or a mapped chart, its own rule activations, its own periods, and its own registers. An `Event` posts to every book whose rules bind it; the entries carry the book id and are independent facts with shared provenance. Cross-book reconciliation (`recon.book_to_book`) explains every difference by rule version (depreciation method, lease treatment) as a certified bridge — the GAAP-to-tax reconciliation an auditor asks for, generated.

### 12.3 Intercompany and consolidation

Intercompany entries declare `pair_key`; the kernel matches pairs across entities' books (`INTERCOMPANY_WITH`) at commit when both sides exist and reports unmatched pairs continuously (FA-INV-13 is a synchronous constraint on *declared* pairs: amounts match under the FX law or the difference is posted to the registered intercompany-difference account by the matching rule). Consolidation is a `ConsolidationRun` on a branch of the consolidation book: aggregate the entities' statements under the ownership graph as of the period end (valid-time `OWNS {pct}`), generate `Elimination`-class entries by rule (intercompany balances and transactions, investment-in-subsidiary vs equity, unrealized profit in inventory), compute non-controlling interest and the cumulative translation adjustment, produce the consolidated statements with a certificate naming every entity's statement certificate, and promote to trunk under the controller's approval. Every consolidation is reproducible from the entities' books and the ownership graph.

### 12.4 FX translation and remeasurement

Remeasurement (an entity whose functional currency differs from its books' currency) and translation (into the reporting currency) are `Revaluation`-class rules under `FxLaw`s of the matching kind: monetary items at the closing rate, non-monetary at historical rates recorded on the originating legs' `base_amount` and rate documents, income-statement items at the registered average-rate document, the difference to the registered CTA equity account (translation) or to P&L (remeasurement). The rule records every rate document it consumed, so the CTA roll-forward is explainable to the leg.

### 12.5 Comparatives and the originally-reported view

Every statement run may request comparatives (`FOR PERIOD FY2025 WITH COMPARATIVE FY2024`) and the restatement views (§7.4); a run `AS ORIGINALLY REPORTED` pins known-at to the first `Closed` transition of the period, and `AS REPORTED IN <certificate>` pins the exact closure a filed statement used. The restatement diff certificate (§8.3) is a statement run over both views with the delta per line and the contributing lineage.

### 12.6 Regulatory schedules and XBRL

Call-report and FR Y-9C schedules are `StatementDefinition`s whose lines map to the bank's chart with the regulatory instructions' version recorded; XBRL export maps definitions to taxonomy concepts (US GAAP / IFRS taxonomies by version) with contexts derived from the coordinate and units from the unit registry, validated against the taxonomy's calculation linkbase (foots by construction because the definition's subtotals are exact). The mapping is data; the export is certified; the filed instance's digest is recorded as a `Document` of kind `Disclosure` attested by the filer.

---

## 13. Notary: Proofs, Bundles, Attestations, and Outsider Verification (Bet A3, part 2)

### 13.1 What is provable, and what is not

Provable to an outsider holding only a bundle and a trusted root: that an entry with digest *d* was recorded in the book's journal at position *i* (inclusion); that the journal at root *r₂* extends the journal at root *r₁* without rewriting (consistency); that a register cell's value is the fold of exactly the listed legs (recomputation, with the legs' inclusion proofs); that a statement's rows are the certified computation of the named definition over the named registers (replay). **Not** provable by these means: that the entry reflects what actually happened (that is what evidence, attestations, and professional judgment are for), that a filtered extract is complete without a range proof over the accumulator, or that a party did not keep a second set of books elsewhere. Proof scopes are labeled verbatim in every bundle (`inclusion`, `consistency`, `recomputation`, `replay`, `membership_only`), inheriting the substrate's discipline.

### 13.2 The journal accumulator and the bundle format

The **journal accumulator** is a Merkle Mountain Range over canonical entry encodings (every `Entry` payload, control entry, attestation, and document receipt in commit order), maintained by Notary **in commit order as a derived, rebuildable structure** — never written inside the posting transaction, so there is no shared hot object on the write path — whose root at any `CommitSeq` is a pure function of the journal prefix (anyone can recompute it), with `AccumulatorState` objects journaled at a configured cadence so the root at a checkpoint is itself content-addressed and inclusion proofs for any entry are computed on demand from the maintained peaks. It is deliberately at the *accounting* layer rather than only at the storage layer: an outsider's verifier must verify accounting facts without understanding the substrate's object formats, and the FrankenAccounting accumulator cross-anchors into the substrate's MMR when §5.8 lands (each `AccumulatorState` is then itself an object in the substrate's history, giving two independent chains). `TransparencyCheckpoint {book, commit_seq, root, signers[], timestamp_evidence}` objects are signed by the book owner and optionally by **witnesses** — the external auditor, a regulator, a trustee — under a registered `WitnessPolicy`, so a company cannot later present a different history to the same witness (detection) or to anyone, if the witness quorum rule is met (prevention), with the claims labeled exactly as the substrate labels them.

An **evidence bundle** (`.fab`, canonical, versioned) contains: the bundle manifest (book identity, coordinate, capability under which it was produced, redaction markings, producer principal and recorded time, scope label); the entries in scope with their payloads; their provenance closures (documents inline or by digest with size and kind when redacted or external); inclusion proofs against a named checkpoint; the checkpoint with its signatures; register cells and their fold proofs when balances are in scope; statement rows and certificates when reports are in scope; findings and their citations when procedures are in scope; and a human-readable `MANIFEST.md` generated from the manifest. Bundles are deterministic (same scope + same checkpoint ⇒ same bytes), so two productions of the same material are byte-identical and a court can compare them.

### 13.3 `fa-verify`: the dependency-free verifier

`fa-verify` is a separate crate with a registered dependency allowlist of exactly `std`: BLAKE3 (the substrate's implementation vendored by construction through `fgdb-crypto` is *not* linked — the verifier carries its own several-hundred-line BLAKE3 with golden vectors, so it is auditable in isolation), canonical decoders for the bundle schemas, MMR inclusion/consistency verification, signature verification for the registered schemes, exact-integer fold recomputation, and the statement replay for the definition kinds. Budget: several KLOC. It ships as a static binary and as a library, it is the differential oracle for the producer (§16.3), and its output is a verification report with every check's result and scope label. A regulator, an opposing expert, or a court-appointed neutral can run it on an air-gapped machine.

### 13.4 Legal and regulatory mapping (qualified)

FrankenAccounting states technical properties and lets counsel map them to law: the append-only journal with immutable recorded time and supersession lineage *is* a complete, time-stamped audit trail of every change (the shape SEC Rule 17a-4(f)'s 2022 audit-trail alternative describes); bundles carry canonical hashes and a certification template a qualified person can sign for FRE 902(13)/(14); certified statements are summaries of voluminous records whose underlying entries are producible (FRE 1006); procedure certificates name the method, parameters, and data so an expert's methodology is reproducible and testable (FRE 702); custody receipts and access logs support chain-of-custody testimony; retention floors and legal holds support document-preservation obligations; the transparency log with witnesses supports a showing that records were not altered after a trigger event (18 U.S.C. §1519 defenses are counsel's domain, the hashes are ours). None of this is a claim of admissibility or compliance; the plan's claim is that the technical predicates those rules name are present, enumerable, and testable.

### 13.5 Transparency checkpoints and witnesses

Checkpoint cadence is a policy (every close, every *n* commits, on demand before a production). A witness is a principal with the `witness` capability who signs checkpoints under the policy; the auditor's signature on the year-end checkpoint is the modern successor of the auditor's initials on the ledger page. Witness policies, quorum rules, and the exact detection-versus-prevention claims are inherited from the substrate's §5.8 vocabulary.

### 13.6 Replay certificates

Every report, finding, plan, and bundle carries a `Certificate {closure: {book root, branch head, known-at, effective selector, definition/procedure oid and version, parameters digest, registry epochs, rule versions, laws, rate and basis documents, capability}, output_digest, replay_command, completeness_grade}`. `fa replay <certificate>` reproduces the output and compares digests; a retention policy or erasure that removed part of the closure downgrades the grade attributably (`Redacted`, `VerifiableIfArtifactsSupplied`) rather than failing silently. This is the expert-witness guarantee: a damages schedule computed in 2026 replays in 2029.

---

## 14. Steward: Governance, Capabilities, and Segregation of Duties

### 14.1 Threat model

Registered in `threat_model.toml` with mitigations per threat: an insider with administrative access who wants to alter history (immutability and transparency checkpoints with external witnesses make alteration detectable; there is no "fix the row" path); collusion between preparer and approver (dual control for the dangerous classes; access logs; JET procedures on self-approval and timing); a compromised or confused agent (branch-per-task, dry-run defaults, amount ceilings and account scopes on its capability, promotion requires a human or a separately scoped approver agent); a stolen capability token (short TTLs, caveats, revocation journaled, every use logged); a rollback attack restoring an old book directory (the substrate's incarnation continuity and the witnessed checkpoints; the book's accumulator root is published to witnesses); a regulator or litigant who must read but must not see privileged material (redaction contracts with proofs; production profiles); a subpoenaed administrator who must prove non-alteration (checkpoint chain and witness signatures); erasure obligations in tension with retention (typed tombstones, attributable downgrade, legal holds).

### 14.2 Capability caveats

`capability_caveats.toml` registers the caveat vocabulary compiled into substrate predicates: `books ⊆ {…}`, `entities ⊆ {…}`, `accounts ⊆ subtree(code)`, `periods ⊆ {…}` or `effective ≤ date`, `dimensions ⊆ {…}`, `ops ⊆ {read, post, post_closed, approve, reconcile, close, reopen, restate, rule_change, issue_capability, witness, verify, produce, hold, erase}`, `classes ⊆ EntryClass`, `amount ≤ Amount` (per entry, per unit), `daily_total ≤ Amount`, `known_at ≤ seq` (an auditor pinned to fieldwork's snapshot), `branch = <draft>` (an agent confined to its draft), `redaction = <contract>`, `expires_at`, `requires_dry_run`. Caveats are conjunctive and attenuable only (a holder can narrow, never widen); issuance and revocation are journaled control entries.

### 14.3 Segregation of duties

`sod_policy.toml` is data: for each dangerous class (`Restatement`, `PriorPeriodAdjustment`, `PeriodControl::Reopen|Lock`, `PolicyControl::ActivateRule`, `ErasureCut`, `IssueCapability(ops ∋ restate)`), the number of approvers, the roles they must hold, and the exclusions (an approver cannot have prepared any entry in the case; the two approvers of a restatement cannot share a session lineage; an agent cannot approve its own draft's promotion). The kernel evaluates the policy at commit (FA-INV-10 clause `sod`), so a violation is a refusal with the exact rule cited, never a report finding after the fact — though `jet.self_approved` runs anyway, because a capability misconfiguration should be found twice.

### 14.4 Profiles

Registered capability templates: **Agent** (branch-confined, `requires_dry_run` on every write, amount ceiling, account scope, no `approve`/`close`/`restate`); **Preparer**; **Approver**; **Controller** (close, reopen with case, rule change with dual control); **Auditor** (read, verify, produce bundles, witness; `known_at` pinned at engagement start if the firm requests it; redaction contract for privileged docs); **Regulator/Examiner** (as Auditor, with the examination's scope and expiry, full access logging); **Investigator** (as Regulator plus `hold`); **Production** (a one-shot capability that can only produce one named bundle under one redaction contract); **Witness** (sign checkpoints only). Every external profile's reads are fully logged (§9.7).

### 14.5 Access audit and non-repudiation

Every capability use is attributable to a principal and, for agents, to a program, model, and session; approvals and attestations bind the digest of what was approved; the access log is append-only and queryable; the transparency log binds the whole history to witnessed roots. A principal cannot later deny an approval it signed, and the book cannot later deny what a witness signed.

### 14.6 Erasure versus retention

§8.5's law, enforced here: erasure is a typed control entry under the `erase` capability with dual control; a legal hold blocks it; the audit log records it; amounts and lineage are never in scope.

---

## 15. Teller: The Agent and Human Surface (Bet A6, part 2)

### 15.1 Design stance

AI agents are the primary users of this system; humans are the primary *authorities*. The surface is designed under one rule: **the first thing an agent instinctively tries must work, or be redirected with a precise, copy-pasteable fix** — and nothing an agent can type by accident may damage the books. The agent-ergonomics Polish Bar is adopted verbatim as a release gate (§19, G3): first-try success on bare invocation and `--help`; `--json`/robot mode on every read; `capabilities --json` and `robot-docs guide` in-tool; at least one mega-command; a documented exit-code dictionary; errors that name what failed, where, and the exact command to run instead; Levenshtein-1 flag correction and intent inference; dangerous operations gated and paired with a safe alternative; byte-deterministic output under `SOURCE_DATE_EPOCH`; `NO_COLOR`/`CI`/non-TTY discipline; no TUI on bare invocation; a regression test pinning every one of these.

All three postures share one **verb registry** (`verbs.toml`): each verb's name, aliases, arguments with types and defaults, required capability, read/write class, output schema id, exit-code mapping, examples, common mistakes, and `next_actions` template. The CLI's subcommands, the daemon's local RPC, and the MCP tools are generated from and checked against that registry (a parity gate fails CI when a verb exists in one surface and not another without a registered reason), so an agent that learned `fa explain balance` already knows the `fa.explain_balance` tool.

### 15.2 Embedded API

```rust
let rt  = fa::runtime_builder().build()?;                   // asupersync runtime, lab-swappable
let book = fa::Book::open(&cx, "acme.fabook", keys)?;       // or Book::create / Book::open_memory
let sess = book.session(&cx, capability_token)?;            // narrowed Cx; capability caveats compiled here

// Reads always name a coordinate; the default is trunk@head, all effective time.
let tb = sess.trial_balance(&cx, Coordinate::default().for_period("2026-03"))?;   // CertifiedReport<TrialBalance>
let b  = sess.balance(&cx, AccountRef::code("1010"), Coordinate::default().known_at(AsOf::Seq(41_999)))?;
let ex = sess.explain_balance(&cx, AccountRef::code("1010"), coord)?;          // legs, entries, evidence heads, proofs

// Writes are intents with a plan first.
let plan = sess.plan(&cx, Intent::RecordInvoice(inv))?;     // Plan { legs, register_deltas, period_decision, sod, certificate }
let out  = sess.commit(&cx, plan)?;                          // Outcome { entry_refs, marker, certificate, next_actions }

// Drafts and scenarios.
let draft = sess.fork_draft(&cx, "close-2026-03-rehearsal")?;
draft.run_close(&cx, PeriodRef::code("2026-03"), CloseMode::DryRun)?;
let diff  = sess.diff(&cx, draft.coordinate(), Coordinate::default())?;      // LedgerDiff { entries, registers, statements }

// Proofs.
let bundle = sess.produce_bundle(&cx, BundleScope::entries(refs).with_evidence())?;
fa_verify::verify(&bundle_bytes, &trusted_checkpoint)?;     // no book needed
```

Every method takes `&Cx`; every read returns a certified value carrying its `Certificate`; every write goes through `plan` → `commit` (a `commit` without a plan is `plan` + `commit` in one call for low-risk intents, refused for the `confirm_plan` classes). GQL is available as `sess.query(&cx, "MATCH …", coord)` with the FrankenAccounting extensions (§15.5).

**Drafts, branches, and scenarios (A6 interim posture, Appendix H row R-BR).** A **draft** is semantically an intent log: a `DraftSet` of planned intents, each validated against the snapshot at planning time, promoted by replaying the intents in one batch at promotion time with full revalidation — which is exactly the substrate's merge-ladder rung 1 (re-evaluate intents against the current head under a stripped `Cx`). When substrate branches ship, a draft may additionally *materialize* on a branch so that registers and statements can be computed over it for review; promotion remains intent replay (the semantic merge), never a storage-level merge of balances. A **scenario** (but-for, pro-forma, policy what-if) is a branch when available and otherwise a deterministic replay of the trunk journal plus scenario intents into a scratch book (`Book::open_memory` is live), which is reproducible by certificate and therefore evidentiary. The coordinate vocabulary is identical in every posture, so no API changes when the substrate lands branches.

### 15.3 The `fa` CLI

**Invocation shape.** `fa <verb> [subverb] [args] [--book <dir>] [--as-known-at …] [--for-period …] [--branch …] [--json | --robot] [--dry-run]`. Bare `fa` prints a one-screen triage (book detected or not, daemon status, what needs attention, the five most useful next commands) and exits 0; it never opens a TUI. `fa --help` and `fa help <verb>` mention `--json`, `capabilities`, `robot-docs`, and the exit-code dictionary in their footer.

**Verb taxonomy (1.0).**

| Family | Verbs |
|---|---|
| Orientation | `fa` (triage), `fa triage --json`, `fa doctor`, `fa capabilities --json`, `fa robot-docs guide|schema|exit-codes|examples`, `fa next` (what to do next, from open findings, unmatched items, pending approvals, period state) |
| Book lifecycle | `fa book create|open|info|checkpoint|verify`, `fa migrate` |
| Chart and registries | `fa chart list|show|import|open-account|close-account|promote`, `fa unit list|add`, `fa law list|show`, `fa calendar show|periods` |
| Posting | `fa post --intent <file|json>` (any intent), `fa invoice|bill|receipt|payment|accrue|defer|reclass|reverse|replace|allocate|revalue|hold|post-hold|void-hold` (typed sugar over `post`), `fa batch` |
| Explain | `fa explain balance <acct>`, `fa explain entry <ref>`, `fa explain lineage <ref>`, `fa explain evidence <ref>`, `fa explain period <code>`, `fa explain register <cell>`, `fa explain refusal <refusal_id>` |
| Query | `fa query "<GQL>"`, `fa gl detail`, `fa tb`, `fa statement <definition>`, `fa aging ar|ap`, `fa open-items` |
| Time and close | `fa period list|open|soft-close|close|lock|reopen`, `fa close dry-run|run|status`, `fa diff --from … --to …` |
| Restatement | `fa case open|rehearse|approve|post|disclose|show|diff` |
| Evidence | `fa doc import|show|attach|list`, `fa attest`, `fa assert-balance`, `fa bank import|match|confirm|status` |
| Forensics | `fa procedure list|run <id>`, `fa finding list|show|review|dismiss|export`, `fa trace <law> …`, `fa jet`, `fa benford`, `fa sample mus|random` |
| Drafts and scenarios | `fa draft new|list|show|plan|promote|discard`, `fa scenario fork|run|diff`, `fa branch list` |
| Proofs | `fa bundle produce|show`, `fa verify bundle|registers|book|certificate`, `fa checkpoint list|sign|witness`, `fa replay <certificate>` |
| Governance | `fa cap issue|list|revoke|show`, `fa hold place|release`, `fa erase` (dual control), `fa access log` |
| Interop | `fa export ads|saft|xbrl|beancount|csv`, `fa import beancount|csv|qbo|camt|bai2|ofx` |
| Daemon | `fad serve|status|stop` (the only long-running process; `fa` auto-routes to it when present) |
| Sandbox | `fa demo init --scenario <name> --seed <n>`, `fa gen book …` |

**Robot mode.** `--robot` (or `--json`) switches every verb to line-oriented NDJSON on stdout with stderr reserved for diagnostics; every line is an envelope `{"v": 1, "kind": "<schema id>", "book": …, "coordinate": …, "data": …, "certificate": …}` with a stable, versioned schema that `fa robot-docs schema <kind>` prints and that a regression test pins from `registries/robot_schema/`. Ordering is canonical (sorted keys, sorted collections); timestamps appear only in fields; `SOURCE_DATE_EPOCH` pins any time the tool would otherwise read; `NO_COLOR`, `CI=true`, `TERM=dumb`, and a non-TTY stdout suppress all styling; no verb ever prompts in non-TTY. Human mode is the default when stdout is a TTY and is plain text tables.

**Exit-code dictionary** (`fa robot-docs exit-codes`): `0` success; `1` usage or input error (bad flag, malformed intent, unknown account code — with the exact fix); `2` safety block (period law, SoD, capability, `confirm_plan` missing, destructive without `--yes`); `3` environment (no book, daemon unreachable, key file missing or wrong permissions, toolchain); `4` foundation failure (substrate I/O, corruption detected — fail closed, never partial); `5` conflict (SSI abort after the configured retries, idempotency conflict, plan invalidated); `6` verification failure (a proof, bundle, register fold, or certificate replay did not verify); `7` accounting-law violation (unbalanced, unit mismatch, missing required dimension, inadmissible class — the law and the cell cited). `fa … --json` with no results exits `0` with `data: []`, never `1`.

**Mega-commands.** `fa triage --json` returns `{health, period_states, unbalanced_drafts, pending_approvals, unmatched_bank_lines, open_findings_by_severity, register_watermark_lag, next_actions: [exact commands]}` in one call. `fa explain balance <acct> --for-period P --as-known-at T --json` returns the register cell, the fold proof, every contributing entry with its evidence heads, and the known-at history of that cell (when the balance last changed and why). `fa next --json` ranks the next actions for the caller's capability. `fa doctor --json` checks book directory, key file, daemon, writer lease, register watermarks, accumulator continuity, witness freshness, and registry epochs.

**Errors that teach.** Every refusal carries `{code, what_failed, where: {entry|leg|field}, why: law or policy cited with registry id, fix: exact command or field change, alternatives: [safe commands], docs: robot-docs anchor}`. Examples from the catalog (Appendix D): posting to a summary account → the leaf children listed with the nearest by name; a float in an amount field → refused with the exact integer-mantissa form and the unit's scale; an effective date in a closed period → the period's state, the admissible classes, the capability needed, and the reclass-into-next-period alternative; unbalanced → the per-unit imbalance, the suggested residual leg if within one minor unit and a rounding account exists (shown, never applied); `--jsno` → `did you mean --json`; `fa post` with legs that look like a reversal of an existing entry → "this looks like a reversal of E…; use `fa reverse E… --reason …` so lineage is recorded". Refusals are themselves addressable (`refusal_id`) so `fa explain refusal` can expand one later and an agent can cite it.

**Intent inference.** Levenshtein-1 correction on flags and verbs (the known-flag list is extracted from `verbs.toml`, not hand-maintained); aliases for the spellings agents try first (`fa trial-balance` = `fa tb`, `fa gl` = `fa gl detail`, `fa balance` = `fa explain balance`, `fa journal` = `fa post`); mis-ordered coordinate flags accepted anywhere; `fa post --dry-run` implied for Agent-profile capabilities (the tool says so once per session); a date given as an instant is accepted as a civil date with a warning naming the policy applied.

### 15.4 The MCP server

`fa-mcp` (over fastmcp_rust) is hosted by `fad` and exposes the verb registry as tool clusters of at most seven tools each, with resources for discovery and macros for the workflows agents actually run:

| Cluster | Tools |
|---|---|
| `fa.orient` | `triage`, `doctor`, `next`, `capabilities`, `robot_docs` |
| `fa.post` | `plan_intent`, `commit_plan`, `post_intent` (plan+commit for low-risk classes), `post_batch`, `explain_refusal` |
| `fa.read` | `balance`, `explain_balance`, `trial_balance`, `statement`, `gl_detail`, `query_gql`, `open_items` |
| `fa.time` | `period_status`, `period_transition`, `close_dry_run`, `close_run`, `diff_coordinates` |
| `fa.evidence` | `import_document`, `attach_evidence`, `attest`, `assert_balance`, `bank_import`, `bank_match`, `confirm_match` |
| `fa.forensics` | `run_procedure`, `list_findings`, `review_finding`, `trace`, `sample`, `export_workpaper` |
| `fa.draft` | `fork_draft`, `plan_in_draft`, `promote_draft`, `discard_draft`, `fork_scenario`, `diff_branches` |
| `fa.notary` | `produce_bundle`, `verify_bundle`, `replay_certificate`, `sign_checkpoint`, `list_checkpoints` |
| `fa.case` | `open_case`, `rehearse_case`, `approve_case`, `post_case`, `disclose_case` |

Resources: `resource://fa/book`, `resource://fa/chart/{book}`, `resource://fa/periods/{book}`, `resource://fa/entry/{ref}`, `resource://fa/lineage/{ref}`, `resource://fa/evidence/{ref}`, `resource://fa/findings/{book}?status=open`, `resource://fa/drafts/{principal}`, `resource://fa/capabilities/{token}`, `resource://fa/laws`, `resource://fa/intents` (the intent schemas), `resource://fa/exit-codes`. Macros: `macro_record_with_evidence` (import document → record event → plan → commit → attach), `macro_month_end_dry_run` (fork draft → run close → statements → diff → summary), `macro_investigate_party` (related-party closure → flows → JET on the party's entries → findings → workpaper), `macro_reconcile_instrument` (import statement → auto-match → list unmatched → assert balance). Every tool returns `next_actions`, stable handles, and a certificate id; every error is `{type, message, recoverable, data: {fix_hint, suggested_tool_calls, available_options}}`; mistake detectors catch floats, instants where dates are expected, summary accounts, closed periods, agents calling `approve` on their own draft, placeholder values (`YOUR_BOOK`), and broadcast-style scopes ("all accounts" on a write). Tool documentation follows the Do/Don't/Discovery/Examples/Common-mistakes template verbatim, generated from `verbs.toml`. A fake-CLI stub is not needed because the real CLI exists and routes to the same daemon; the MCP server's `robot_docs` explains both.

### 15.5 Query language

GQL (through the substrate) plus a namespaced FrankenAccounting profile: the selectors of §7.4 as clauses (`FOR PERIOD`, `AS KNOWN AT`, `EFFECTIVE AT|BETWEEN`, `AT BRANCH`, `AS ORIGINALLY REPORTED`, `AS CURRENTLY STATED`, `AS REPORTED IN`), procedures as `CALL fa.<procedure>(…) YIELD …` (every §11 procedure, `fa.trial_balance`, `fa.statement`, `fa.explain_balance`, `fa.fold`), and `EXPLAIN (CERTIFICATE)` inherited. Examples:

```gql
-- Receivables over 90 days from related parties, as the books stood at fieldwork start
MATCH (l:Leg)-[:POSTS_TO]->(a:Account {code: '1200'})<-[:CONTROLS]-(:Subledger {kind:'AR'}),
      (l)-[:FOR]->(:DimensionValue)<-[:IS]-(p:Party)
WHERE EXISTS { MATCH (p)-[:RELATED_TO|OWNS|CONTROLS*1..3]-(:LegalEntity {code:'ACME'}) EFFECTIVE AT l.effective_date }
FOR PERIOD 'FY2025' AS KNOWN AT '2026-02-01T00:00:00Z'
CALL fa.open_amount(l) YIELD open, age_days
WHERE age_days > 90
RETURN p.name, sum(open) AS exposure ORDER BY exposure DESC;

-- Every entry whose restatement lineage touched Q4, with the net effect
MATCH (e:Entry)-[s:SUPERSEDES {kind:'Restates'}]->(t:Entry) FOR PERIOD 'FY2024-Q4'
CALL fa.lineage_net(t) YIELD net_legs RETURN t, e, s.reason_code, net_legs;

-- Follow the money six hops out from a party within a window, by LIBR
CALL fa.trace('libr', {source: $party, from: '2025-01-01', to: '2025-06-30', max_hops: 6})
YIELD instrument, period, traced_amount, path RETURN *;
```

### 15.6 Worked workflows (the five readers)

**The agent closes a month.** `fa triage --json` → unmatched bank lines on instrument B1, two accrual tasks pending, period 2026-03 `Open`. `fa draft new close-03` → `fa bank import stmt.camt053.xml --instrument B1 --draft close-03` → `fa bank match --draft close-03 --json` (18 exact, 2 proposals) → `fa bank confirm M-7 M-9 --draft close-03` (refused: Agent profile cannot confirm heuristic matches; `fix: ask an approver to run fa bank confirm …`, logged) → `fa accrue --intent accrue_rent.json --draft close-03 --dry-run` (plan: legs, period decision `Open/Adjusting → Admit`) → `fa draft plan close-03 --json` (all plans valid) → `fa close dry-run --period 2026-03 --draft close-03` (statements, diff vs February, warnings: one round-amount manual entry) → `fa draft promote close-03` (refused `2`: promotion requires Approver; `next_actions: [fa draft show close-03 --json]` for the human) → the controller runs `fa draft promote close-03 --yes` → `fa period soft-close 2026-03`. Every refusal taught the next step; nothing touched trunk until a human did.

**The CPA audits FY2025.** The firm receives an Auditor capability pinned `known_at ≤ <engagement start seq>`. `fa export ads --period FY2025 --with-proofs` yields the GL detail in the AICPA layout with the accumulator checkpoint and range proofs; `fa verify bundle` on the firm's laptop confirms completeness. `fa jet --period FY2025 --json` and `fa benford --scope expenses` produce findings; `fa sample mus --population ar-open --seed 20260115 --interval 50000` yields a reproducible sample; `fa explain evidence E…` for each sampled item pulls the invoice and receipt documents; `fa assert-balance` records the bank confirmation; at year-end the partner signs the checkpoint as a witness (`fa checkpoint witness`). The client cannot alter FY2025 history during fieldwork without the firm's pinned snapshot and the witnessed root exposing it.

**The FDIC examiner needs close-of-business positions.** `fa tb --as-known-at '2026-04-10T23:59:59Z' --for-period 2026-04 --json` and `fa statement call-report-RC --as-known-at …` give the positions the books held at that instant, derived from the ledger with certificates; `fa open-items --subledger deposits --as-known-at …` gives the deposit detail Part 370 needs; every read is logged under the examiner's capability; `fa replay` reproduces each figure later.

**The litigation consultant computes but-for damages.** `fa scenario fork but-for-breach --from 2025-07-01` → apply the counterfactual intents (the contract performed; the diverted receipts recorded) → `fa statement income --branch but-for-breach --for-period FY2025` vs trunk → `fa scenario diff` is the damages schedule with a certificate naming every assumption document; `fa bundle produce --scope scenario:but-for-breach --redaction privileged-v2` is the production, hash-certified; opposing counsel runs `fa-verify` and `fa replay` on the same bundle.

**The investigator traces funds.** `fa procedure run graph.related_party_exposure --entity ACME --json`, `fa procedure run graph.layering --window 2025 --json`, `fa trace libr --source P-412 --from 2025-01-01 --to 2025-12-31 --max-hops 8 --json` → findings with cited `BankLine`s and legs → `fa hold place --scope party:P-412 --authority 'GJ subpoena 26-114'` → `fa finding export --format md` as the workpaper; `fa access log --since …` shows the investigator's own trail for the privilege log.

### 15.7 The human surface

Human mode is plain-text tables that fit a terminal, with the same content as robot mode; `--table`, `--wide`, and `--csv` are formatting options. An optional `ftui` inline view (`fa close run --watch`) shows task progress above the scrollback; it is a feature of `fa-cli`, never required and never on bare invocation. Web dashboards are downstream consumers of the robot contract.

### 15.8 Sandbox and fixtures

`fa demo init --scenario retail|bank|ponzi|shell-network|worldcom --seed 7` creates a fully populated book from `fa-gen` with planted facts documented in `README.md` of the demo directory, so an agent can practice every verb, every procedure, and every refusal on a realistic book that cannot hurt anyone; the scenarios are the same corpora Lantern's precision/recall is measured on (§11.10).

### 15.9 What an agent wants, mapped

| Want | Feature |
|---|---|
| One call that says what needs attention | `fa triage` / `fa.orient.triage` |
| To be unable to corrupt the books by accident | Agent profile: branch-confined, dry-run required, ceilings; period law; SoD at commit |
| Errors that say exactly what to do | Refusal catalog with `fix` and `alternatives`; `fa explain refusal` |
| Stable IDs to cite | `EntryRef{vid, digest}` and every handle in §4.9 |
| "Why is this balance X" | `fa explain balance` with fold proof and evidence heads |
| Deterministic output to diff | Canonical ordering, `SOURCE_DATE_EPOCH`, certificates |
| Typed intents, with raw legs when needed | Intent catalog + `PostEntry` |
| Evidence attached in the same call | `macro_record_with_evidence`; `evidence` on every intent |
| Bulk and idempotent | `PostBatch`, idempotency keys, outcomes durable before ack |
| A query language it already knows | GQL + the small FrankenAccounting profile |
| Discoverable contract in-tool | `capabilities --json`, `robot-docs`, `resource://fa/intents` |
| A sandbox | `fa demo init` |
| What-if without consequences | Drafts and scenarios |
| Safe, time-boxed access | Caveated capabilities with expiry |
| Reasons for refusals that cite policy | Every refusal names the registry row |
| Streaming for big extracts | NDJSON rows; `fa gl detail --stream` |
| No TUI, no silent failure, no prompts in non-TTY | Polish Bar, regression-tested |
| An audit-ready artifact in one command | `fa bundle produce`, `fa workpaper export` |

---

## 16. Determinism, Evidence Classes, and Verification Doctrine (Bet A5, part 2)

This is not a QA appendix; it is a design pillar with its own budget, inherited from the substrate's §15 and specialized to accounting.

### 16.1 Claim classes and registries

The substrate's lattice (`invariant > proof > bounded_model > statistical > slo > benchmark`) applies verbatim through `fgdb-claim`'s types, so an illegal justification is a compile error. `registries/invariants.toml` holds exactly the FA-INV IDs of Appendix F, each materialized as clauses with `checker_entrypoint`, `negative_test_entrypoint`, `owner`, `first_gate`, `status`, and `waiver = "forbidden"`; `evidence.toml` holds every Lantern detector's evidence row and every calibration row; `slo.toml` holds every §17 number. `claims_lint.toml` scans this plan, the README, and AGENTS.md both ways: every `FA-XXX-NN` marker resolves to a row, and every gate-table region cites a marker. `tools/registry-check` (std-only, like the substrate's) validates all of it and is itself a G0 deliverable.

### 16.2 The reference oracle (`fa-reference`)

A deliberately simple, single-threaded, obviously correct implementation of the full accounting semantics over canonical maps and vectors: posting with the balance law, period law, admissibility matrix, SoD, idempotency; registers as literal folds; bitemporal selectors as filters over `(effective_date, recorded_seq)`; supersession netting; two-phase resolution; escrow bounds as a check after every operation; allocation and FX under the laws; statement definitions evaluated by brute force; every Lantern procedure in its naïve form; the accumulator as a literal Merkle tree. Compiled for tests, fuzzing, and model checking only; never shipped; never optimized. Its dependency allowlist is `std`, `fa-types`, `fa-money`, `fa-time`, and the generated registries — importing `fgdb`, `fa-journal`, or any engine crate is a CI-rejected boundary violation, so the differential cannot be gutted by code sharing. The normative appendices and golden vectors outrank both implementations: a mismatch is triaged against the spec and never resolved by making the reference imitate the engine. **It exists before the first engine line**, which is also what lets FrankenAccounting's semantics be developed while the substrate's planned surfaces land (§2.5).

### 16.3 External oracles

- **Plain-text accounting.** `fa export beancount` and `fa export ledger` produce journals that `bean-check`, `bean-report`, `hledger balance`, and `ledger balance` evaluate; balances are compared cell-by-cell for every fixture book, including multi-currency and lot-tracked fixtures. Divergences are triaged against both specs (Beancount's rounding and price semantics differ by design; the documented divergence table is itself a conformance artifact). These tools are widely used, open, and independently implemented — a two-hop oracle to ground truth for the fold.
- **TigerBeetle semantic corpus.** A scenario corpus of two-leg, two-phase, linked, balancing, closing, and limit cases expressed in both TigerBeetle's API vocabulary and FrankenAccounting intents, with expected balance fields; FrankenAccounting must agree with TigerBeetle's documented semantics where the compat profile claims parity and document divergence elsewhere (N-leg entries, expiry sweeps).
- **AICPA ADS and SAF-T round trips.** Export → the published validators (where available) and schema checks → re-import into a fresh book → fold equality with proofs.
- **XBRL.** Exported instances validate against the taxonomy's calculation linkbase; a failed calculation check is a defect in a statement definition and fails CI.
- **`fa-verify`** as the independent verifier of the producer's bundles (independence discipline: a different crate with its own BLAKE3 and decoders).
- **frankenscipy's `fsci_stats`** as a test-only differential oracle for Benford and sampling statistics.

### 16.4 Simulation-first (`fa-sim`)

The entire system — Folio, the register maintainer, the expiry sweep, Canon, Lantern, Notary, `fad` with its MCP and local transports — runs under the asupersync lab runtime with the substrate's lab VFS: seeded deterministic scheduling, virtual time, torn writes, bit flips, ENOSPC, fsync lies, crash points at every barrier of the posting pipeline (between plan and commit; between commit and ack; between delta consumption and watermark publication; between checkpoint computation and checkpoint publication; between case approval and case post; between bundle production and bundle hand-off), and DPOR over the declared interleavings that matter: post vs close, two agents applying the same receipt, promotion vs a trunk post to the same account, a restatement vs a reopen, an expiry sweep vs a manual void. Every failure is a seed with a crashpack and a replay command; failing runs shrink themselves (delta debugging inherited). Lab-vs-live dual runs compare traces for the Genesis slice scenarios.

### 16.5 Consistency oracles (in-sim, continuous)

After every committed transaction in a lab run: balance law on every entry; register-equals-fold on every touched cell; subledger-equals-control; admissibility of every entry for its period's state at commit; SoD on every approval; idempotency outcome stability; supersession acyclicity and exact negation of reversals; accumulator consistency (each root extends the previous); escrow conservation (rights + custody = capacity); bitemporal monotonicity (a known-at view never changes once its seq is passed); projection-equals-payload for legs; erasure leaves amounts intact and downgrades grades attributably. Oracles are implemented against the reference engine, not against the engine's own types, wherever practical.

### 16.6 Differential, metamorphic, and property suites

Model-generated intent histories run against both engines and compare every outcome, register, statement, and finding. Metamorphic laws: the fold is invariant under reordering of commutative entries within a period; reversal-then-replacement equals replacement for every register; posting on a draft and promoting equals posting on trunk; a scenario replay equals a branch when both exist; export-then-import is identity on folds; a register rebuilt from the journal equals the maintained register; a bundle produced twice is byte-identical; compaction, checkpointing, and retention cuts never change any certified result inside the retained range; redaction never changes an amount; calendar generation agrees with a brute-force day-walker. Property suites for Abacus (§6.7), for calendar arithmetic (exhaustive over 1900–2100), for the admissibility matrix (exhaustive), and for the refusal catalog (every refusal has a `fix` that, applied, succeeds on the fixture).

### 16.7 Formal anchors (scoped, honest)

Lean: `Amount` group laws; rounding bounds per law; allocation conservation per law; balance-law preservation under reversal, replacement, and reclassification; supersession-net correctness; bitemporal visibility (an entry is visible at `(known_at, effective)` iff its `recorded_seq ≤ known_at` and its `effective_date ∈ effective`); the period state machine's reachability (no path from `Locked` to `Open` without a `Reopen` control entry carrying a case); escrow bound preservation under the registered transitions. TLA+/TLC: the close run as a DAG under crashes; the restatement case life cycle with dual control; the two-phase hold with expiry sweep and concurrent manual resolution; draft promotion against a moving trunk. Every model states its bounds; trace export demonstrates captured executions are allowed by the spec; none of this is called a proof of the implementation.

### 16.8 Fuzzing

Every `fa-formats` reader (camt, BAI2, OFX, MT940, CSV layouts, Beancount/Ledger text, ADS, SAF-T, XBRL instance), the Canon parser and IR decoder, the bundle decoder, the certificate decoder, the robot-mode request parsers, and the MCP argument normalizers — each with a corpus and a crash/timeout/memory budget in CI.

### 16.9 The gauntlet

Before every release, the convergent multi-round honest-evaluation gauntlet (the suite's `running-the-gauntlet` discipline) runs: oracle and differential harnesses, metamorphic suites, surface-parity audit (CLI vs MCP vs API against `verbs.toml`), the agent-ergonomics Polish Bar scorecard with fresh-context simulated agents attempting the canonical tasks of §15.6, honest performance versus the reference machine's pinned baselines, and a release-readiness scorecard whose every row names its evidence class.

### 16.10 Publish

Target four papers or tech reports: (1) *The Palimpsest Ledger: bitemporal restatement semantics for immutable books*; (2) *Balance = Fold: certified registers over a content-addressed journal*; (3) *Tracing as code: reproducible constructive-trust tracing and Ponzi-flow detection on a temporal money graph*; (4) *Agent-operated books: typed intents, dry-run plans, and structural segregation of duties*. Ambition includes the receipts.

---

## 17. Performance Doctrine and Targets

Reference machine: 32-core/64-thread, 256 GB RAM, PCIe-4 NVMe, single node. Every number is a provisional `EmpiricalGate` (`slo.toml` row), activated only when its benchmark manifest pins CPU, kernel/filesystem/mount, NVMe model and measured fsync distribution, toolchain, substrate revision, book configuration (retention, FEC, encryption, register definitions), fixture (an `fa-gen` book by seed), concurrency, result consumption, and comparison rule. Every gate names its operation class (Appendix G) and must be derivable from the substrate's barrier chain for that class: a posting-latency gate below `barrier_count × pinned fsync p50` is a registry error that fails CI. The standing laws are the substrate's six (no benchmark-only semantics; distributions not averages; never hide compaction or register maintenance; memory is a metric; adaptive numbers disclose their policy; no unpriced protocol weight) plus one of our own: **no "balance read" number is published without stating whether it was served at the watermark or with a tail fold, and the tail length.**

| Domain | Provisional gate |
|---|---|
| Single-entry post (fused autocommit, durable, with projections, 2–6 legs) | p50 ≤ 2× the substrate's fused-write floor; p99 < 15 ms warm; sustained ≥ 20k entries/s across cores with group commit, full durability, encryption and FEC on |
| Batched post (linked batch of 100 entries) | ≥ 200k entries/s sustained; batch p99 < 60 ms |
| Bulk migration (50M legacy lines) | ≥ 500k legs/s into sealed storage via the substrate bulk protocol; opening-balance attestation computed in the same run |
| Balance read at watermark (`SnapshotQuery` class) | p99 < 50 µs warm; tail fold ≤ 1 µs per tail leg, tail length reported |
| Trial balance, 100k leaf accounts, at watermark | < 200 ms; certified against fold |
| Full register rebuild from journal (10M legs) | < 10 s on the reference machine; digest-equal to maintained registers |
| Register watermark lag under sustained post gate | p99 < 250 ms behind head; lag is a reported `slo` row, never an invariant |
| Known-at trial balance (any retained seq) | < 2.5× the head trial balance for the pinned retention fixture |
| Close dry-run (1M-entry period, 40 tasks) | < 30 s to statements and diff |
| Restatement diff certificate (3 periods, 200 statement lines) | < 5 s |
| Bundle production (10k entries with evidence heads and proofs) | < 5 s; `fa-verify` of the same bundle < 2 s on a laptop class machine; per-entry inclusion proof verify < 100 µs |
| Lantern: JET suite over 10M legs | < 20 s total; Benford first-two-digits < 3 s; duplicates < 10 s |
| Lantern: `graph.layering` over a 1M-party, 20M-flow projection, 6 hops | < 60 s with CGSE witness; `trace.libr` over 1 instrument-year < 1 s |
| Consolidation (20 entities, 2M entries each) on a branch | < 2 min to certified consolidated statements |
| Accumulator checkpoint | O(log n) peaks; signing < 10 ms; witness round-trip reported, never gated |
| CLI first-try latency (`fa triage --json`, warm daemon) | < 100 ms; bare `fa` with no book < 50 ms |
| MCP tool round-trip (read-class) | < 20 ms over stdio excluding the read itself |
| Memory: bytes per live leg (payload + projections + indexes + registers + accumulator) | reported with component breakdown; provisional ceiling 400 B/leg at steady state |
| Endurance: 24 h sustained post at 50% of gate | no unexplained RSS drift; register lag bounded; compaction debt bounded in the substrate's model terms |

Method: every gate has a bench binary, a committed baseline, a variance budget, and a flamegraph on regression; the harness is deterministic (seeded `fa-gen` workloads, pinned schedules). Performance work follows the house discipline: profile → remove one contention or allocation → re-verify determinism and the oracles → commit with evidence, one lever per change.

---

## 18. Workspace Layout and the Build-It-Ourselves Inventory

### 18.1 Crates (`fa-*` workspace, layered; Cargo-enforced boundaries per the substrate's `workspace_topology.toml` pattern)

| Layer | Crates |
|---|---|
| Foundation | `fa-types` (ids, handles, canonical encodings, claim re-exports), `fa-money` (Abacus), `fa-time` (Almanac calendars and selectors), `fa-registry` (generated registry readers), `fa-claim` (thin re-export of `fgdb-claim` with FA ids) |
| Model | `fa-model` (REA schema, constraints, entry classes, admissibility, labels/edges as typed builders) |
| Kernel | `fa-journal` (Folio posting kernel, write path, projections), `fa-registers` (maintainer, checkpoints, folds), `fa-escrow` (balance-limit adapters), `fa-palimpsest` (supersession, cases) |
| Evidence | `fa-docket` (documents, custody, attestations, bank lines), `fa-notary` (accumulator, checkpoints, bundles, certificates) |
| Rules | `fa-canon` (language, type checker, IR, interim evaluator, VM adapter), `fa-intents` (intent schemas, plans) |
| Analytics | `fa-statements` (definitions, report engine), `fa-concordat` (multi-book, intercompany, consolidation, FX translation), `fa-lantern` (procedures, findings, tracing laws, projections) |
| Governance | `fa-steward` (caveats, SoD, profiles, access audit) |
| Interop | `fa-formats` (ADS, SAF-T, XBRL, camt/pain, BAI2, OFX, MT940, CSV, Beancount/Ledger) |
| Surface | `fa-verbs` (the verb registry and parity checker), `fa` (embedded API facade), `fa-cli` (`fa` binary), `fad` (daemon: writer lease, local RPC, hosts MCP), `fa-mcp` (fastmcp adapter) |
| Verification | `fa-reference`, `fa-sim`, `fa-oracles`, `fa-gen` (synthetic books and scenarios), `fa-bench`, `fa-conformance`, `fa-fuzz`, `fa-verify` (std-only; outside every posture closure except its own) |
| Tooling | `tools/registry-check` (std-only), `tools/xtask` |

Rules: a crate may depend only on its own or lower layers; `fa-reference` and `fa-verify` have registered allowlists; no crate is created before its first real slice (no empty prototype crates); every crate root is `#![forbid(unsafe_code)]`; posture closures (`fa`, `fa-cli`, `fad`+`fa-mcp`) contain no test-only or packaging crates; `fa-mcp` is the only crate allowed to depend on `fastmcp-rust`.

### 18.2 Registries (`registries/`, validated by `tools/registry-check` at G0)

`constitution.toml` (claim classes, constraints FA-CON-01…14, the six bets), `invariants.toml` (FA-INV spine), `evidence.toml`, `slo.toml`, `checker_index.toml`, `proof_lanes.toml`, `threat_model.toml`, `workspace_topology.toml`, `foundation_dependencies.toml` (Appendix H as data: each substrate capability, status, interim posture, tracking bead), `units.toml`, `rounding_laws.toml`, `allocation_laws.toml`, `fx_laws.toml`, `entry_classes.toml`, `period_states.toml`, `admissibility.toml`, `reason_codes.toml`, `relationship_bases.toml`, `intents.toml`, `procedures.toml`, `capability_caveats.toml`, `sod_policy.toml`, `verbs.toml`, `exit_codes.toml`, `refusal_catalog.toml`, `formats.toml`, `robot_schema/*.json`, `bundle_schema/*.toml`, `operation_costs.toml` (Appendix G), `claims_lint.toml`.

### 18.3 Built in-house versus consumed

**Built here:** everything in §2.7. **Explicitly not built:** the storage engine, MVCC/SSI, system time, valid-time contracts, branches, incremental views, indexes, capability compilation, the audit pipeline, replay manifests, RaptorQ, encryption, the lab runtime, networking, supervision, the MCP protocol machinery, graph algorithms. The closed-universe constraint is the moat: every byte of accounting logic is owned, deterministic under lab, and small enough to audit.

### 18.4 Dependency policy

`Cargo.toml` pins `asupersync = { version = "=0.5.0", default-features = false, … }` at the substrate's revision, `frankengraphdb` crates by git `rev` (the only git source; `deny.toml` `[sources] allow-git` lists exactly asupersync and frankengraphdb, `unknown-git = "deny"`, `required-git-spec = "rev"`), `fnx-classes`/`fnx-algorithms = "=0.3.0"`, and `fastmcp-rust = "=0.12.0"` only in `fa-mcp`. `deny.toml` bans tokio, async-std, smol, serde (except through the exact fastmcp and asupersync wrapper allowlist, confined by a per-crate check to the `fa-mcp` closure), rusqlite, sqlx, chrono, time, rust_decimal, bigdecimal, num-bigint, arrow, polars, petgraph, hyper, axum, reqwest, tantivy. `franken-stack.lock` records each foundation's git commit and checksum. `scripts/check-forbidden-deps.sh` and `cargo deny` run in `scripts/check.sh`.

---

## 19. Workstreams and Convergence Gates

No MVP and no substitute architectures. Work is sequenced by dependency and converges through constitutional gate G0 plus four integration gates; the substrate's planned capabilities are consumed when they land (Appendix H), and the interim postures are themselves gated.

**Gate G0 — Constitutional Contracts (before any engine code):** every registry in §18.2 materialized with its schema and first rows; the FA-INV spine of Appendix F with clause activation predicates, checker entrypoints, and `waiver = "forbidden"`; the threat model; the admissibility matrix with its exhaustive generated test; the unit, law, class, intent, procedure, caveat, verb, exit-code, and refusal catalogs frozen at major 1; the canonical object schemas of Appendix A with `BodyDigest` recipes and golden vectors; the bundle and certificate schemas marked `externally_verifiable`; the robot-mode envelope and schema fixtures; the operation-cost registry (Appendix G) with the derivability law; `foundation_dependencies.toml` with every row's status checked against the substrate on the G0 date; `tools/registry-check` green; `scripts/check.sh` with the verdict contract; README/AGENTS synchronization checks. No workstream may invent a missing semantic choice locally.

| WS | Name | Contents | Depends on |
|---|---|---|---|
| W1 | Bedrock | `fa-types`, `fa-money` (exact mul/div, laws, allocation, FX with Lean lanes), `fa-time` (calendars, periods, selectors, exhaustive tests), `fa-registry`, `fa-reference` (the full semantics oracle), `fa-gen` (synthetic books) | G0 |
| W2 | Folio on the substrate | `fa-model` schema install as journaled schema effects; `fa-journal` posting pipeline with the balance law, leaf-only, unit policy, dimensions, idempotency, batches; projections; `fa-registers` maintainer over `delta_since` with checkpoints and verify-by-fold; two-phase entries and the expiry sweep; interim balance limits; subledger constraints; application and matching; the Genesis slice | W1 |
| W3 | Almanac + Palimpsest | Period state machine as control entries; admissibility at commit with SSI witnesses; selectors; close runs as DAGs with dry-run on drafts; auto-reverse and recurring schedules; entry classes; supersession lineage and netting; restatement cases with dual control and diff certificates; erasure and holds; migration | W2 |
| W4 | Docket + Notary | Documents (inline/external), import receipts, attestations and balance assertions, bank statement parsers and bank lines; the journal accumulator in the commit path; checkpoints and witnesses; certificates on every read; bundle format; `fa-verify` with its own BLAKE3 and golden proofs | W2 |
| W5 | Teller | `fa-verbs` registry and parity checker; `fa` facade; `fa-cli` with robot mode, exit codes, refusal catalog, intent inference, mega-commands, doctor; `fad` daemon with writer lease and local RPC; `fa-mcp` over fastmcp with clusters, resources, macros, mistake detectors; Polish Bar regression tests; agent simulations of §15.6 | W2–W4 (early slices from W2) |
| W6 | Canon | Language, type checker, IR, interim evaluator under stripped `Cx`; intent catalog bound to rule families; dry-run plans and `confirm_plan`; golden corpora; backtesting; activation with dual control; VM adapter when R-VM lands | W2, W3 |
| W7 | Statements + Concordat | Statement definitions and the report engine with certificates; comparatives and restatement views; multi-book; intercompany constraint; consolidation runs on drafts/branches; revaluation and translation rules; regulatory schedules; XBRL export | W3, W4, W6 |
| W8 | Lantern | Procedure registry; JET, digit, duplicate, sequence, cutoff, aging, reconciliation, sampling; graph procedures over the money-flow projection with `fnx`; tracing laws; solvency and lookback; findings and workpapers; evidence rows and calibration; precision/recall on `fa-gen` scenarios | W2, W4, W7 |
| W9 | Interop + conformance | `fa-formats` readers/writers; ADS and SAF-T with proofs; Beancount/hledger differential oracle; TigerBeetle semantic corpus; XBRL validation; fuzz corpora | W2, W4, W7 |
| W10 | Verification + release | `fa-sim` scenarios and crash matrices; oracles; metamorphic suites; TLA+ models; gauntlet; benchmark manifests and baselines; papers | all |
| W11 | Post-1.0 | TigerBeetle-compatible transfer API profile; FrankenAccounting over `fgdbd` (networked multi-tenant posture); `fa-frames` packaging boundary; substrate-branch materialization of drafts; Ripple-backed registers; storage-level MMR cross-anchoring; macOS/Windows filesystem profiles as the substrate ships them | 1.0 |

**The Genesis slice.** The first W1–W2 integration proves, end to end and under the lab: create a book → install the chart and calendar as journaled schema effects → post a balanced two-leg entry via `PostEntry` through admit/resolve/laws/plan/commit → the derived legs exist and equal the payload → the register maintainer advances and `balance = fold` → crash at every barrier (between plan and commit, commit and ack, delta consumption and watermark) and recover → `fa tb --json` returns the certified trial balance → `fa verify registers` is green → an unbalanced proposal is refused with exit 7 and the per-unit imbalance → a post into a `Closed` period is refused with exit 2 and the matrix cell → `fa replay` reproduces the trial balance bytes. No stub register, no post-filter capability, no float, no wall clock.

**Gate G1 — "The Journal Lives":** Genesis slice green under lab and live; FA-INV-01/02/04/05/06/09 live with checkers; registers verified by fold on every fixture; idempotency and batches under crash; the reference differential over model-generated histories; the robot-mode envelope and `fa triage`, `fa post`, `fa tb`, `fa explain balance`, `fa doctor` at the Polish Bar; `fa-verify` verifies a produced bundle of the Genesis book.

**Gate G2 — "Time and Truth":** period state machine, admissibility matrix, and SSI-resolved post-vs-close races proven; selectors including `AS ORIGINALLY REPORTED` and `AS REPORTED IN`; supersession netting and restatement cases with diff certificates; two-phase entries with expiry sweeps under lab; documents, custody, attestations, balance assertions; accumulator continuity and witnessed checkpoints; FA-INV-03/07/08/10/14 live; the Beancount/hledger differential green on all fixtures; Canon rules with golden corpora and backtests; dry-run plans with `confirm_plan`.

**Gate G3 — "Agents and Auditors":** the full verb registry across CLI/daemon/MCP with the parity gate green; fresh-context simulated agents complete every §15.6 workflow with zero `useless_error` outcomes in the intent corpus; SoD and caveats enforced at commit (FA-INV-10 full); statements and consolidation certified; Lantern's procedures with evidence rows and measured precision/recall; ADS/SAF-T exports with proofs; `fa demo init` scenarios; the gauntlet's surface-parity and ergonomics scorecards published.

**Gate G4 — "Published":** all activated §17 manifests green and public; conformance matrices (ADS, SAF-T, XBRL, Beancount/hledger, TigerBeetle corpus) published with documented divergences; every FA-INV clause live or its capability absent from the manifest; the papers match the proven scope; `fa-verify` released as a static binary with golden proofs; 1.0.

---

## 20. Risks and Mitigations

| Risk | Reality check | Mitigation |
|---|---|---|
| The substrate is unreleased and several load-bearing surfaces are planned (valid time, branches, Ripple views, escrow, MMR, UDF VM) | True; it is also being completed in parallel by a swarm, and the owner's call is to build on it | Appendix H names every dependency, its status, its interim posture, and its bead; the reference oracle and W1 do not depend on the substrate at all; interim postures are permanent-correct designs (intent-log drafts, journal-level accumulator, `delta_since` maintainer) rather than throwaways; a substrate regression is caught by the pinned `rev` and `franken-stack.lock` |
| Hot-account contention before escrow lands | Real on cash and clearing accounts | Registers off the posting path; SSI-protected limit reads only for limited accounts; the contention gate is reported in both postures |
| Period law and SoD at commit raise abort rates for long-running agent sessions | They will, by design | Dry-run plans are cheap; `PlanInvalidated` carries a fresh plan; agents work on drafts and promote in one batch |
| Exact arithmetic without a decimal crate | `CanonicalDecimal` lacks mul/div; building it is real work | `fa-money` is W1 with Lean lanes and exhaustive vectors; `fgdb-bigint` provides the wide intermediates; nothing else in the system may do arithmetic on amounts |
| Calendar and date arithmetic bugs | The classic source of "wrong period" defects | Brute-force reference over 1900–2100; golden vectors for every calendar kind including 53-week years; no external crate to disagree with |
| Legal and regulatory claims overreach | A plan that says "FRE 902(14)-compliant" is a liability | §13.4's rule: state technical predicates, never admissibility or compliance; counsel maps |
| Forensic detectors produce false accusations | Statistics are not invariants | Claim typing (§11.9); findings are observations with evidence; thresholds are decision cards; precision/recall measured on labeled corpora and published |
| Agent surface drift between CLI, daemon, and MCP | Three surfaces will diverge without a gate | `verbs.toml` is the single source; the parity checker fails CI; the Polish Bar regression tests pin every applied ergonomics change |
| fastmcp_rust pins a different nightly and carries serde/ring | Confined to one posture closure | `deny.toml` per-crate allowlist; `fa-mcp` built on this repo's pin with the drift tracked as a bead; the daemon's local RPC does not depend on fastmcp |
| Scope creep toward an ERP | Every subledger invites workflow | Anti-goals in §0.3; subledgers are modeled as books and control constraints, never as workflow |
| Erasure obligations versus immutability | A real legal tension | Typed tombstones, attributable grade downgrade, legal holds, amounts never in scope (§8.5) |
| Performance versus a single-core batched engine | FrankenAccounting will not match TigerBeetle's transfer throughput, and should not claim to | The §17 gates are derived from the substrate's barrier chain; the product claim is a system of record with proofs, not a payments core; the compat profile states its envelope |
| Restatement semantics misread by practitioners | "Big R / little r" and retrospective application have edge cases | Cases are explicit objects with kinds and disclosure documents; the diff certificate makes the effect visible; the matrix is exhaustive and generated |
| The plan is too long to act on | A fair worry | §19 decomposes into beads with the dependency graph intact; every section names its registry rows and gate |

---

## Appendix A — Canonical Object Schemas (normative contract)

All durable FrankenAccounting objects are properties and payloads of substrate elements and therefore inherit the substrate's Appendix A encoding laws: declared format major/minor; little-endian fixed integers; canonical unsigned LEB128 only where a field says varint; length-before-allocation; checked arithmetic; per-kind maximum sizes; unknown additive-minor fields length-delimited and skipped only under a registered `canonical_default_law_id`; unknown required flags fail closed. Every `BodyDigest<T>` row declares `{domain_separator, schema_major, included_field_tags, excluded_field_tags}` and uses the substrate's recipe `BLAKE3(domain_separator ‖ canonical(schema_major, T excluding exactly the one BodyDigest field))`. The pseudo-schemas below are checked renderings of `registries/object_schemas/*.toml`; a field absent from the registry is unencodable.

```text
Amount            { unit_id: u32, mantissa: i128 }                       // scale from units.toml; no exponent field
Rate              { numerator: BigIntCanonical, denominator: BigIntCanonical }   // exact rational; denominator > 0
DimensionSet      { entries: sorted [(dimension_id: u32, value_ref: VId)] }       // canonical sort by dimension_id
EntryRef          { vid: VId128, entry_digest: [u8;32] }
ApprovalRef       { approval_vid: VId128, approved_digest: [u8;32] }

Entry (schema fa:entry:v1)                                                // §4.2; BodyDigest excludes entry_digest only
  { schema_major: u16 = 1, schema_minor: u16,
    book_id: Id128, branch_id: Id128,
    class: EntryClass (u16 tag from entry_classes.toml),
    effective_date: DateDay (i32 days since 1970-01-01, proleptic Gregorian),
    document_date: Option<DateDay>,
    description: String (≤ 1024 bytes UTF-8 NFC),
    legs: List<LegPayload> (2 ≤ len ≤ max_legs_per_entry),
    unit_totals: sorted Map<unit_id, { debits: i128, credits: i128 }>,
    base_totals: Option<{ unit_id, debits: i128, credits: i128, fx_law_oid: Oid, rate_doc_oids: sorted [Oid] }>,
    idempotency_key: Bytes (1..=64),
    origin: EntryOrigin,
    principal_ref: VId128, session_ref: Option<VId128>,
    approvals: [ApprovalRef],
    evidence: sorted [{ document_oid: Oid, role: EvidenceRole(u8) }],
    supersession: [{ target: EntryRef, kind: SupersessionKind(u8), reason_code: u16 }],
    pending: Option<{ timeout_ns: Option<u64>, resolution_of: Option<EntryRef>, disposition: Option<Disposition> }>,
    external_ids: sorted [{ system: String(≤64), id: String(≤256) }],
    tags: sorted Map<String(≤64), CanonicalPropertyValue> (≤ 32 entries, ≤ 4 KiB),
    entry_digest: BodyDigest<Entry> }

LegPayload (wire type, inline)
  { side: u8 (0 = Debit, 1 = Credit),
    account_ref: VId128,
    amount: Amount,
    base_amount: Option<Amount>,
    dimension_set: DimensionSet,
    memo: Option<String(≤ 512)>,
    settles: [{ target_leg: (EntryRef, ordinal: u16), amount: Amount }] }

EntryOrigin (closed union)
  = Intent     { intent_oid: Oid, intent_kind: u16, plan_certificate_oid: Oid }
  | Rule       { rule_version_oid: Oid, event_ref: VId128, inputs_digest: [u8;32] }
  | Migration  { source_system: String(≤64), source_id: String(≤256), source_recorded_at: Option<i64 ns>,
                 source_entered_by: Option<String>, source_approved_by: Option<String>, batch_oid: Oid }
  | Control    { control_kind: u16, spec_body_digest: [u8;32] }
  | Sweep      { sweep_kind: u8, tick_evidence_oid: Oid }

Disposition = Posts { amount: Amount } | Voids | Expires { at_tick: u64 }

Account           { book_id, code: String(≤64), name, type: u8, normal_balance: u8, posting: u8,
                    unit_policy: Single(u32) | AnyCurrency | AnyUnit, control_of: Option<VId128>,
                    dimension_requirements: sorted [u32], balance_limit: Option<EscrowDomainRef>,
                    _valid_from, _valid_to }                               // valid time via contract or interim property
Period            { calendar_id, code: String(≤32), fiscal_year: i32, ordinal: u16, kind: u8,
                    start: DateDay, end: DateDay (half-open), state: u8 (versioned; every change is a control entry) }
Unit              { code: String(≤16), kind: u8 (+ iso4217 numeric for currencies), scale: u8 (≤ 18),
                    rounding_default: u16 (rounding_laws.toml), symbol, display_scale: u8 }
Register (derived) { key: { book_id, branch_id, account_ref, unit_id, period_ref, dimension_subset_key: [u8;16] },
                    debits_posted: i128, credits_posted: i128, debits_pending: i128, credits_pending: i128,
                    entry_count: u64, watermark: CommitSeq, fold_digest: [u8;32] }
RegisterCheckpoint { definition_oid, commit_seq: CommitSeq, cells_root: [u8;32], cell_count: u64, body_digest }
Document          { oid: Oid (substrate ObjectId of canonical bytes), kind: u8, mime: String(≤128), size: u64,
                    storage: Inline { object_ref } | External { locator: String(≤2048), fetch_proof: { digest, import_receipt_oid } },
                    parsed: Option<{ parser_id: u16, parser_version: u32, projection_oid: Oid }>,
                    redaction: Option<RedactionContractRef>, retrieved_by: VId128, custody: ImportReceiptRef }
ImportReceipt     { source: Upload{principal} | Connector{name, version} | Email{message_id} | Scan{device},
                    digest_at_receipt: [u8;32], transformations: [{ kind: u16, version: u32, output_digest }], body_digest }
Attestation       { claim: AttestationClaim, subject_refs: sorted [TypedRef], principal_ref, signature: { scheme: u16, key_id, bytes },
                    signed_digest: [u8;32], evidence_refs: sorted [Oid], body_digest }
AttestationClaim  = Prepared | Reviewed { against: [Oid] } | Reconciled { instrument_ref, through: DateDay }
                  | RegisterEquals { cell_key, amount: Amount, as_of_effective: DateDay, as_known_at: CommitSeq }
                  | Confirmed { by_party: VId128, balance: Amount, as_of: DateDay } | Examined { bundle_oid } | Custom { kind: u16, body_digest }
Approval          { capability_ref, principal_ref, approved_digest: [u8;32], role: u16, body_digest }   // recorded_at = _commit_time
RestatementCase   { kind: u8, periods_affected: sorted [PeriodRef], disclosure_oid: Option<Oid>, status: u8,
                    rehearsal_certificate_oid: Option<Oid>, approvals: [ApprovalRef], body_digest }
CloseRun          { book_id, period_ref, mode: DryRun | Execute, draft_ref: Option<VId128>, tasks: [CloseTaskRef],
                    rehearsal_certificate_oid: Option<Oid>, status: u8 }
DraftSet          { owner_principal, name, planned_intents: [{ intent_oid, plan_certificate_oid, order: u32 }],
                    status: Open | Promoted { batch_entry_refs } | Discarded { reason } }
Finding           { procedure_id: u16, procedure_version: u32, parameters_digest, coordinate: Coordinate, severity: u8,
                    statistic: CanonicalPropertyValue, population: { count: u64, scope_digest }, cites: [TypedRef],
                    narrative_template_id: u16, status: u8, certificate_oid: Oid, body_digest }
Certificate       { closure: { book_root: [u8;32], branch_head: MarkerRef, known_at: SystemSelector, effective: EffectiveSelector,
                               subject: Definition{oid}|Procedure{id,version}|Plan{intent_oid}|Bundle{scope_digest}|Query{normalized_digest},
                               parameters_digest, registry_epochs: sorted Map<registry_id, epoch>, rule_versions: sorted [Oid],
                               laws: sorted [u16], inputs: sorted [Oid], capability_commitment: [u8;32], numeric_profile_oid },
                    output_digest: [u8;32], replay_command: String, completeness_grade: u8, body_digest }
AccumulatorState  { commit_seq: CommitSeq, leaf_count: u64, peaks: [[u8;32]], root: [u8;32], prev_state_oid: Option<Oid> }
TransparencyCheckpoint { book_id, commit_seq, root, leaf_count, witness_policy_oid: Option<Oid>,
                    signatures: sorted [{ signer_key_id, scheme, bytes }], time_evidence_oid, body_digest }
Bundle (.fab)     { manifest: { book_identity, coordinate, capability_commitment, redaction_contract_oid: Option<Oid>,
                               scope: BundleScope, scope_label: u8, producer_principal, produced_at_seq, checkpoint_oid },
                    entries: [Entry], closures: [{ entry_digest, documents: [Document | DocumentStub], events, rules, approvals }],
                    inclusion_proofs: [{ leaf_index: u64, path: [[u8;32]] }], checkpoint: TransparencyCheckpoint,
                    registers: [{ cell, value, fold_legs: [(EntryRef, ordinal)] }], statements: [{ rows, certificate }],
                    findings: [Finding], manifest_md: String, bundle_digest: BodyDigest<Bundle> }
Capability (metadata only) { token_commitment: [u8;32], issuer_principal, holder_principal, caveats: sorted [Caveat], issued_seq, expires_at, revoked: Option<{ seq, reason }> }
AccessEvent       { capability_commitment, principal_ref, snapshot_seq, query_digest, objects_touched_digest, kind: u8 }
```

Reference semantics: `TypedRef` is the substrate's exact tagged reference union generated per containing schema; `Oid` is a substrate `ObjectId`; `VId128` is the substrate's 128-bit element identity; `MarkerRef`/`CommitSeq` are the substrate's. No FrankenAccounting object stores a float, a wall-clock instant it read itself, or a future object's identity.

## Appendix B — Intent Catalog (normative fields)

Every intent carries the common header `{ book, branch?: draft|branch name, idempotency_key, dry_run: bool, confirm_plan?: CertificateRef, evidence?: [DocumentRef], description?: String, tags?: Map }`. Required capability and admissible classes are registry columns; field types use Appendix A.

| Intent | Fields | Produces |
|---|---|---|
| `PostEntry` | `class`, `effective_date`, `legs: [{side, account: code|ref, amount: {unit, mantissa}|"1234.56 USD" (parsed exactly), base_amount?, dimensions?: {dim: value}, memo?, settles?}]`, `supersedes?`, `pending?` | 1 entry |
| `PostBatch` | `intents: [Intent]` (bounded), `atomic: true` | N entries, all or none |
| `RecordEvent` | `kind`, `occurred_on`, `party?`, `lines: [{quantity: {unit, mantissa}, unit_price?: Amount, item?, dims?}]`, `attributes: Map`, `documents: [DocumentRef]` | event + rule-derived entries |
| `RecordInvoice` / `RecordBill` | `party`, `invoice_date`, `due_date?`, `lines`, `tax_jurisdiction?`, `dims?`, `external_id?` | event + entries |
| `ApplyPayment` / `ApplyReceipt` | `instrument`, `amount`, `date`, `applications: [{open_item: EntryRef|external_id, amount}]`, `on_account?: bool` | entry with `settles` |
| `Hold` / `PostHold` / `VoidHold` | `Hold`: as `PostEntry` with `class: Pending`, `timeout?`; `PostHold`: `pending: EntryRef`, `amount?`; `VoidHold`: `pending: EntryRef` | pending / resolution |
| `Accrue` / `Defer` | `effective_date`, `legs`, `auto_reverse_on?: DateDay` | adjusting (+ scheduled reversal) |
| `Reclass` | `from: [{leg: (EntryRef, ordinal)|account+dims, amount}]`, `to: [{account, dims, amount}]`, `reason_code` | reclassification |
| `Reverse` | `target: EntryRef`, `effective_date?` (default: target's; may be the next open period), `reason_code` | reversal |
| `Replace` | `target: EntryRef`, `replacement: PostEntry fields`, `reason_code` | reversal + replacement batch |
| `Allocate` | `source: {account, dims?, amount|AllOfPeriod}`, `law: AllocationLawId`, `targets: [{account, dims, weight: Rate|Amount}]`, `driver_document?` | allocation |
| `Revalue` / `Translate` | `period`, `law: FxLawId`, `rate_documents: [DocumentRef]`, `scope: accounts|entity` | revaluation entries |
| `Depreciate` / `Amortize` | `instrument|asset refs`, `period`, `schedule_rule` | adjusting entries |
| `MatchBank` / `ConfirmMatch` / `AssertBalance` | `instrument`, `statement: DocumentRef` / `matches: [MatchRef]` / `cell, amount, as_of_effective, evidence` | MATCHES edges / attestation |
| `OpenAccount` / `CloseAccount` / `PromoteToSummary` / `ImportChart` | Appendix A `Account` fields / `code, effective` / `code, effective` / `template_oid` | schema control |
| `OpenPeriod` … `ReopenPeriod` | `period`, `reason`, (`case` for reopen) | period control |
| `RunClose` | `period`, `mode: DryRun|Execute`, `draft?`, `tasks?: subset` | close run |
| `OpenRestatementCase` … `DiscloseCase` | `kind`, `periods_affected`, `narrative_document?` / `case` / `case` / `case` / `case, disclosure: DocumentRef` | case transitions |
| `AttachEvidence` / `Attest` / `ImportDocument` | `target, documents, role` / `claim, subjects, evidence` / `bytes|locator, kind, mime` | edges / attestation / document |
| `Migrate` | `manifest: {source_system, trial_balance: DocumentRef, opening_date, chunks: [...]}` | migration batch |
| `IssueCapability` / `Revoke` / `LegalHold` / `ReleaseHold` / `ErasureCut` | `holder, caveats, expires` / `commitment, reason` / `scope, authority` / `hold` / `subject, authority` | governance control |
| `ForkDraft` / `PromoteDraft` / `DiscardDraft` / `ForkScenario` / `DiffBranches` | `name` / `draft` / `draft, reason` / `name, from_seq?` / `from: Coordinate, to: Coordinate, scope` | drafts / diff |

Amount parsing: `"1234.56 USD"` is parsed exactly to `{unit: USD, mantissa: 123456}`; `1234.56` as a JSON number is **refused** with the exact string form (a float cannot be trusted to be exact); `"1234.567 USD"` is refused as exceeding the unit's scale with the rounding laws listed as explicit options.

## Appendix C — Entry-Class × Period-State Admissibility Matrix

`Admit` = any principal with `post`; `W(cap[, approvals])` = admitted only with the named capability and approval count; `Refuse` = never. Generated from `admissibility.toml`; the exhaustive test covers every cell.

| Class \ State | `Future` | `Open` | `SoftClosed` | `Closed` | `Locked` |
|---|---|---|---|---|---|
| `Original` | Refuse | Admit | W(`post_softclosed`) | Refuse | Refuse |
| `Pending` / `Resolution` | Refuse | Admit | W(`post_softclosed`) | Resolution only, W(`post_closed`) | Resolution of `Voids` only, W(`post_closed`) |
| `Reversal` | Refuse | Admit | Admit | W(`post_closed`) | Refuse (reverse in next open period instead; the refusal says so) |
| `Replacement` | Refuse | Admit | Admit | W(`post_closed`, 1) | Refuse |
| `Reclassification` | Refuse | Admit | Admit | W(`post_closed`, 1) | Refuse |
| `Adjusting` | Refuse | Admit | Admit | W(`post_closed`, 1) | Refuse |
| `Closing` | Refuse | W(`close`) | W(`close`) | Refuse | Refuse |
| `Allocation` / `Revaluation` / `Elimination` | Refuse | Admit (rule) | Admit (rule) | W(`post_closed`, 1) | Refuse |
| `Migration` | W(`migrate`, 2) in the `Opening` period only | Refuse | Refuse | Refuse | Refuse |
| `Revision` | Refuse | Refuse | Refuse | W(`restate`, 1) inside a `Revision` case | W(`restate`, 2) inside a `Revision` case |
| `Restatement` / `PriorPeriodAdjustment` | Refuse | Refuse | Refuse | W(`restate`, 2) inside an `Approved` case | W(`restate`, 2) inside an `Approved` case |
| `PeriodControl` | `Open` only | `SoftClose`, `Close` | `Close`, `Reopen→Open` W(`reopen`, 1) | `Lock` W(`close`, 1), `Reopen` W(`reopen`, 2, case) | `Reopen` W(`reopen`, 2, case) |
| `SchemaControl` / `PolicyControl` | not period-scoped: W(`rule_change`|`schema_change`, 2 for activations) | | | | |

Universal rules: an `Original` is never admissible in `Closed` or `Locked`; a `Restatement` is admissible only inside an `Approved` case; the preparer of any entry in a case cannot be one of its approvers; `post_closed` and `restate` caveats may be bounded by `effective ≥ date` so an auditor's adjustment capability cannot reach older periods.

## Appendix D — CLI/MCP Contract

**Envelope (robot mode, one JSON object per line):** `{"v": 1, "kind": "<schema-id>", "book": "<id>", "coordinate": {...}, "data": ..., "certificate": "<oid>" | null, "warnings": [...], "next_actions": [{"command": "...", "why": "..."}]}`. Diagnostics never appear on stdout. `fa robot-docs schema <kind>` prints the JSON schema; fixtures live in `registries/robot_schema/`.

**Exit codes:** `0` ok · `1` usage/input · `2` safety block · `3` environment · `4` foundation failure · `5` conflict · `6` verification failure · `7` accounting-law violation. Empty results are `0`.

**Refusal object:** `{"refusal_id": "...", "code": "FA-REF-NNN", "exit": n, "what_failed": "...", "where": {"entry|leg|field|period|account": ...}, "why": {"law": "FA-INV-01.per-unit" | "policy": "sod_policy#restate" | "matrix": {"state": "Closed", "class": "Original"}}, "fix": {"command": "...", "or_field_change": {...}}, "alternatives": [...], "docs": "robot-docs#..."}`.

**Refusal catalog (excerpt; full list in `refusal_catalog.toml`):**

| Code | Trigger | `fix` |
|---|---|---|
| FA-REF-001 | Unbalanced per unit | the imbalance per unit; the residual leg suggestion when within one minor unit and a rounding account exists |
| FA-REF-002 | Leg on a summary account | the leaf children, nearest-by-name first |
| FA-REF-003 | Float or over-scale amount | the exact string form at the unit's scale; the rounding laws as explicit options |
| FA-REF-004 | Effective date in `Closed`/`Locked` | the state, the matrix row, the capability needed, and `fa reclass`/next-period alternative |
| FA-REF-005 | Missing required dimension | the dimension and its allowed values |
| FA-REF-006 | Looks like a reversal | `fa reverse <ref> --reason …` |
| FA-REF-007 | `confirm_plan` missing on an irreversible class | the dry-run command to run first |
| FA-REF-008 | SoD: approver prepared an entry in the case | the policy row; who may approve |
| FA-REF-009 | Idempotency conflict | the recorded digest and outcome; a new key suggestion |
| FA-REF-010 | Plan invalidated | what changed; a fresh plan is attached |
| FA-REF-011 | Agent profile write without draft | `fa draft new …` and the same command with `--draft` |
| FA-REF-012 | Capability lacks op/scope | the caveat that blocked; who can issue |
| FA-REF-013 | Pending already resolved | the resolution entry |
| FA-REF-014 | Unknown account/unit/period code | nearest codes by edit distance |
| FA-REF-015 | Instant given where a date is expected | the civil date the policy would derive; `--effective <date>` |
| FA-REF-016 | Unit mismatch in arithmetic | the units; `fa law list fx` |
| FA-REF-017 | Bundle/proof verification failed | the failing check and scope label |
| FA-REF-018 | Daemon holds the writer lease | route via `fad` (automatic) or `fad status` |

**MCP tools:** the clusters of §15.4, each tool documented from `verbs.toml` with Discovery, When-to-use, Parameters, Returns (`next_actions` always), Do/Don't, Examples (JSON-RPC), Common mistakes, Idempotency, Edge cases. Errors are `{error: {type, message, recoverable, data: {fix_hint, suggested_tool_calls, available_options, refusal_id}}}`.

**Determinism:** output ordering canonical; `SOURCE_DATE_EPOCH` honored; `NO_COLOR`/`CI`/`TERM=dumb`/non-TTY suppress styling and prompts; `verify-determinism`, `verify-stdout-stderr-split`, and `verify-non-tty-discipline` are regression tests.

## Appendix E — Working Bibliography (anchors reviewed for this plan)

Accounting theory and patterns: Pacioli, *Summa de arithmetica, geometria, proportioni et proportionalità* (1494), tractate *Particularis de computis et scripturis* · McCarthy, "The REA Accounting Model" (*The Accounting Review*, 1982); ISO/IEC 15944-4 · Ijiri, "A Framework for Triple-Entry Bookkeeping" (1986) and *Momentum Accounting and Triple-Entry Bookkeeping* (1989) · Grigg, "Triple Entry Accounting" (2005) · Fowler, *Analysis Patterns* (1997) ch. 6, "Accounting Patterns" and "Temporal Patterns" (martinfowler.com) · Helland, "Immutability Changes Everything" (CIDR 2015) · Fowler/Young on event sourcing. Temporal databases: Snodgrass, *Developing Time-Oriented Database Applications in SQL* (1999) · Jensen & Snodgrass, "Temporal Data Management" · SQL:2011 system-versioned and application-time tables · FrankenGraphDB plan §4.6 (valid-time contracts). Ledger systems: TigerBeetle documentation (data model, two-phase transfers, linked events, `imported`, `closed`, balance limits), TIGER_STYLE.md, VOPR · Stripe, "Ledger: Stripe's system for tracking and validating money movement" · Uber Engineering, "LedgerStore" · Formance Ledger and Numscript · Modern Treasury Ledgers · Fragment · Beancount (v3), hledger, Ledger-cli documentation (balance assertions, pads, prices) · SAP S/4HANA Universal Journal (`ACDOCA`) · Oracle Fusion Subledger Accounting. Audit and forensic: AICPA Audit Data Standards (Base and General Ledger standards) · OECD SAF-T · XBRL GL and the US GAAP / IFRS taxonomies · ISO 20022 (`camt.052/053`, `pain.001`), BAI2, OFX, SWIFT MT940 · PCAOB AS 2401 ¶.58–.62, AS 1215, AS 2201, AS 2315, AS 2310; AU-C/ISA 240, 230, 500, 505, 530 · COSO Internal Control–Integrated Framework · Nigrini, *Benford's Law* (2012) and *Forensic Analytics* (2011, 2nd ed. 2020) · Wells, *Principles of Fraud Examination* · ACFE *Fraud Examiners Manual* (kiting, lapping, shell companies, Ponzi). Law and regulation (technical predicates only): SOX §302, §404, §802; 18 U.S.C. §1519 · SEC Rule 17a-4(f) as amended 2022 (audit-trail alternative); FINRA Rule 4511; CFTC Reg. 1.31 · FRE 702, 902(13), 902(14), 1006 · FDIC 12 CFR Part 370 · FFIEC Call Report instructions; FR Y-9C · Bank Secrecy Act (CTR/SAR), 31 U.S.C. §5324 · 11 U.S.C. §547, §548; UVTA/UFTA · tracing: *Cunningham v. Brown*, 265 U.S. 1 (1924); the lowest intermediate balance rule in *Restatement (Third) of Restitution* §59. Verifiability: RFC 6962 (Certificate Transparency) · Merkle Mountain Ranges (opentimestamps lineage) · FrankenGraphDB plan §5.8 · BLAKE3 specification. Foundations: FrankenGraphDB plan and `IMPLEMENTATION_STATUS.md` (2026-10-05) · asupersync v4 plan and formal semantics · franken_networkx CGSE doctrine · fastmcp_rust MCP 2026-07-28 conformance record (`99a3b4e8`) · eidetic_engine_cli and frankengit dependency conventions. Agent surfaces: the suite's agent-ergonomics kernel (19 axioms, Polish Bar, eleven dimensions) and the MCP server design principles (mistake detection, structured errors, macros, resources).

## Appendix F — Invariant and Evidence Registries

This table contains exactly sixteen top-level invariant IDs. G0 materializes each as one or more stable subordinate clause records in `invariants.toml`; subordinate clause keys do not create additional IDs. Every clause records its exact statement, activation predicate, dependencies, resolvable checker and negative-test entrypoints, model/proof scope, owner, first gate, status, and `waiver = "forbidden"`. CI verifies the sixteen-ID set and table hash, the dependency DAG, checker/test existence, and the activation closure. Statistical, configuration-model, and empirical claims live in their separate registries.

| ID | Invariant | Enforcement |
|---|---|---|
| FA-INV-01 | **Balance law.** For every committed entry and every unit among its legs, debit and credit totals are exactly equal in that unit (`per-unit`); when base totals are present, base debits equal base credits exactly under the named FX law with the residual on an explicit leg (`base`, `fx-residual`); memo and statistical units balance separately (`memo`); every leg posts to a `Leaf` account effective at the entry's date whose unit policy admits the leg's unit (`leaf-only`, `unit-policy`); required dimensions are present (`dimensions`). | Kernel check at step 5 from the payload alone; Canon compiler proof per rule; reference-engine differential; Lean lane for reversal/replacement/reclassification preservation; fuzzed payload decoder. |
| FA-INV-02 | **Append-only.** Every journaled object (entry, document, attestation, approval, rule version, chart object, period, policy, case, finding, checkpoint) is immutable after commit; correction is a new object with lineage; no path updates or deletes a committed object; schema and registry changes are journaled control effects with their own lineage. | Substrate immutability (FG-INV-13) plus FrankenAccounting's secure-view facade as the only writer; mutation-attempt negatives; recovery rebuilds derived state only. |
| FA-INV-03 | **Period law.** An entry's effective date resolves to exactly one period of the book's calendar; the entry's class is admissible for that period's state under the registered matrix and the principal's capability; period transitions occur only through journaled `PeriodControl` entries with the required approvals; `Locked` admits only case-bound restatement classes; the period-state read is a serialization witness so a transition and a post cannot both commit against stale state. | Generated exhaustive matrix test; SSI oracle over post-vs-close interleavings under DPOR; reference differential; Lean lane for the state machine's reachability. |
| FA-INV-04 | **Registers are folds.** Every register cell, checkpoint, statement row, aging bucket, open-amount cell, and reconciliation state equals the deterministic fold of the visible legs at its coordinate and watermark; derived structures are never authoritative (inherits FG-INV-18); recomputation from the journal reproduces `fold_digest` bit-for-bit; a mismatch is a correctness defect that discards the derived structure. | `fa verify registers` in CI on every fixture; maintainer crash matrix between delta consumption and watermark publication; reference fold differential; metamorphic suite (rebuild equals maintained). |
| FA-INV-05 | **Evidence closure.** Every committed entry has a registered origin; its provenance closure (documents by digest, event, rule version with inputs digest, principal/session, approvals, rate and basis documents, supersession targets) is enumerable and strongly retained for the retention floor; an entry whose origin or evidence references an unknown object is unencodable. | Generated reference checker over Appendix A field rows; retention/GC oracle; `fa explain evidence` conformance; bundle round-trip. |
| FA-INV-06 | **Exactness.** Every amount is an exact fixed-scale integer in a registered unit; every rounding, allocation, FX conversion, and presentation rounding names a registered law; allocations conserve totals exactly; overflow is refused; no float enters any amount path. | Type-level (no float type in `fa-money`); Lean lanes for rounding bounds and allocation conservation; cross-platform determinism harness; property suites. |
| FA-INV-07 | **Bitemporal visibility.** An entry is visible at `(known_at, effective)` iff its recorded sequence ≤ `known_at` and its effective date lies in the effective selector; `recorded_at` is only ever the commit stream's assignment; distinct known-at or effective selectors never alias; a known-at view is immutable once its sequence has passed; `AS ORIGINALLY REPORTED` resolves to the first `Closed` transition and `AS REPORTED IN` to a certificate's closure. | Reference visibility differential; Lean lane; selector golden corpus; negative fixture for any user-supplied recorded time; migration provenance oracle. |
| FA-INV-08 | **Supersession lineage.** `SUPERSEDES`/`RESOLVES` edges form a DAG over existing targets; a `Reversal` is the exact negation of its target; a `Replacement` is paired with its reversal in one batch; a pending entry is resolved at most once; net effects are computable and the originally-posted and currently-stated views agree with the lineage. | Generated reference checker; Lean lane for negation and netting; two-phase resolution model; metamorphic (reverse+replace = replace). |
| FA-INV-09 | **Idempotent intents.** Within one book and principal scope, an idempotency key maps to at most one immutable outcome; byte-identical retries return it; differing bytes are refused; outcomes are durable before acknowledgement (inherits FG-INV-01). | Retry-storm and lost-response tests under lab; key-conflict negatives; outcome-durability crash points. |
| FA-INV-10 | **Authorization before observation; duties segregated.** Capability caveats are enforced before any storage observation (inherits FG-INV-20) or, in the interim posture, by refusal before query construction — never as a result filter; SoD policy is evaluated at commit for every dangerous class; an approval binds the digest of what it approves; a principal cannot approve its own draft's promotion or a case containing its own entries; every external-profile read is logged. | Capability type matrices; SoD negatives for every policy row; approval-digest mismatch negatives; access-log completeness oracle. |
| FA-INV-11 | **Determinism and replay.** Every report, finding, plan, and bundle carries a certificate naming its closure; the same closure reproduces byte-identical canonical output; nondeterministic procedures are seeded and declared; missing or erased closure elements downgrade the completeness grade attributably (inherits FG-INV-19). | Replay CI over every certified artifact; cross-platform digest comparison; erasure-downgrade tests. |
| FA-INV-12 | **Subledger–control reconciliation.** At every committed coordinate the fold of a subledger's detail legs equals its control account's register; external summary feeds must name the detail batch digest they summarize and are refused if the detail does not fold to the summary. | Synchronous kernel check; reference differential; external-feed negatives. |
| FA-INV-13 | **Cross-book and consolidation conservation.** Declared intercompany pairs match under the FX law or carry an explicit difference leg; elimination entries are derived deterministically from matched pairs and the ownership graph; consolidated equity reconciles to the entities' equity plus eliminations and non-controlling interest; book-to-book bridges explain every difference by rule version. | Pair-matching oracle; consolidation replay; bridge completeness test. |
| FA-INV-14 | **Tamper evidence and accumulator continuity.** Each `AccumulatorState` extends the previous (consistency); every checkpoint binds a root the verifier recomputes from the journal prefix; inclusion proofs verify against checkpoints; erasure leaves a typed tombstone whose digest the prior proofs still bind; amounts, dates, accounts, and lineage are never in erasure scope. | `fa-verify` as independent oracle; consistency-proof CI across checkpoints; erasure negatives; rollback-detection tests with witnessed checkpoints. |
| FA-INV-15 | **Two-phase and limits.** Pending amounts are reserved in pending registers and released or posted exactly once; expiry is journaled by sweep under time evidence, never by ambient clock; balance limits are enforced through escrow rights (or, interim, SSI-protected limit reads) and never silently exceeded; `Balancing` legs record the amount actually moved. | Two-phase model under lab with concurrent manual and sweep resolution; escrow conservation inherited from FG-INV-02; limit-breach negatives. |
| FA-INV-16 | **Projections equal payloads.** The derived `Leg` vertices and `HAS_LEG`/`POSTS_TO`/`FOR`/`IN_UNIT` edges of an entry equal its inline legs exactly, are written in the same transaction, and are rebuilt from payloads on recovery; no reader treats a projection as more authoritative than the payload. | Post-commit oracle in sim; recovery rebuild test; projection-drift negatives. |

### Statistical, evidence, and configuration gates (not invariants)

| ID | Qualified claim | Required disclosure/gate |
|---|---|---|
| FA-EVID-01 | Journal-entry-test procedure calibration | population and lookback; per-test parameters; expected flag rate on the clean `fa-gen` scenario; observed rate |
| FA-EVID-02 | Benford conformity | population eligibility rule; digit test; MAD and chi-square with the conformity ranges named; sample size floor |
| FA-EVID-03 | Duplicate and near-duplicate detection | tolerance and similarity thresholds; precision/recall on the labeled corpus |
| FA-EVID-04 | Graph detector performance (layering, kiting, Ponzi motif, shell signature, related-party) | labeled-scenario precision/recall per seed; CGSE policy; complexity witness |
| FA-EVID-05 | Bank-match heuristic confidence | method, features, confidence calibration on confirmed matches; the exact-match rule is not evidence (it is deterministic) |
| FA-CAL-01 | Decision-card threshold tuning | pinned default; tuning principal and engagement; before/after flag rates; fallback |
| FA-CFG-01 | Register watermark-lag capacity model | maintainer throughput model; post rate; predicted versus observed lag; backpressure policy |
| FA-CFG-02 | Expiry-sweep tick capacity | pending population; tick cadence; sweep batch bounds |
| FA-CFG-03 | Retention and durability model | inherits FG-CFG-01 for the book directory; evidence-byte growth model |

## Appendix G — Operation Cost Registry (normative contract)

Each FrankenAccounting operation class maps onto exactly one FrankenGraphDB Appendix G row (its substrate class), and its §17 gate must be derivable from that row's barrier chain. `registries/operation_costs.toml` is the machine-checkable artifact; CI regenerates this projection and byte-compares it.

| Operation class | Substrate class | Substrate transactions | Derived objects minted (FrankenAccounting) | External authorities | Notes |
|---|---|---|---|---|---|
| Balance read at watermark | `SnapshotQuery` | 0 | 0 | none | register cell + bounded tail fold |
| Certified report (TB, statement) | `SnapshotQuery` (reads) + 0 writes | 0 | 1 `Certificate` (persisted lazily on request) | none | pure over registers and tail |
| Single-entry post | Autocommit write, fused arm | 1 | 1 `Entry` + *n* `Leg` + edges + `ExternalId`s | none; a rate lookup is a *document* already in the book, never a synchronous call | group-commit amortized |
| Batch post (*N* entries) | Autocommit write, fused arm (one `WriteBatch`) | 1 | *N* × single-entry census | none | bounded by `max_batch_entries` |
| Draft promotion (*N* planned intents) | Autocommit write, fused arm | 1 | batch census + `DraftSet` transition | none | intent replay with revalidation |
| Period transition | Autocommit write, fused arm | 1 | 1 `PeriodControl` entry | none | SSI witness for racing posts |
| Close run (execute) | sequence of batch posts + transitions | *k* (task count + 1) | per task | none | rehearsal is reads over a draft/scratch book |
| Restatement case post | Batch post | 1 (+1 for the case transition) | case entries + diff `Certificate` | none | dual-control approvals are prior transactions |
| Register maintenance flush | Autocommit write, fused arm (maintenance class) | 1 per flush tick | touched `Register` cells; periodic `RegisterCheckpoint` | none | off the posting path; amortized |
| Accumulator checkpoint | Autocommit write, fused arm | 1 per cadence | 1 `AccumulatorState` + 1 `TransparencyCheckpoint` | witnesses episodic, never synchronous | peaks derived in commit order |
| Expiry sweep tick | Autocommit write, fused arm | 1 per tick | `Resolution(Expires)` entries | time evidence (substrate's profiled observation) | bounded batch per tick |
| Bundle production | reads | 0 | 1 `Bundle` object (optional persist) | none | deterministic |
| Bulk migration (*M* lines) | substrate bulk protocol (staged chunks, one finalizing transaction) | 1 + chunk staging | `Migration` entries; opening attestation | none | gap-free chunk manifests |

Laws: **derivability** (every §17 gate names its class and counting unit and is consistent with the substrate row's barrier floor); **same-change update** (any change adding a substrate transaction, a synchronous external interaction, or a per-entry derived object updates the registry in the same change); **no hot object on the write path** (a class may not add a shared mutable object — register, accumulator peak, counter — to the posting transaction; the registry's "derived objects" column is checked against the write-path code by the topology gate).

## Appendix H — Foundation Dependency Ledger (FrankenGraphDB capabilities, status 2026-10-09)

`registries/foundation_dependencies.toml` is the machine-readable form; each row's status is re-verified at every gate against the pinned substrate revision, and a row whose status regresses fails G0's drift check.

| Row | Substrate capability | Status 2026-10-09 | FrankenAccounting interim posture | Switch-over rule |
|---|---|---|---|---|
| R-API | `fgdb::Database` embedded API, `WriteBatch`, `TxnCx`, GQL reads, `execute_gql_certified`, `delta_since`, `replay` | Live | — | — |
| R-ST | Chronicle system time, `FOR SYSTEM_TIME AS OF SEQ`, retention | Live | — | retention policy per book |
| R-SSI | Block-MVCC + Graph-SSI (strict serializable, Local posture) | Live | — | — |
| R-CAT | Graph catalog (`CREATE GRAPH`) | Absent | label-partitioned regions with `_graph` property | migrate to named graphs with a differential run |
| R-VT | `ValidTimeContract`, slices, `FOR VALID_TIME`, temporal non-overlap | Planned (normative) | `effective_date` and effectivity bounds as indexed properties; `fa-time` interval algebra in the kernel; index-range witnesses | shadow-build/validate/activate with the full §16 temporal suite on both representations |
| R-ESC | Escrow domains (balance limits without hot locks) | Planned | SSI-protected limit reads for limited accounts | registered decision row; contention gate reported in both |
| R-REG | Ripple materialized views | Planned | `fa-registers` maintainer actor over `delta_since` with checkpoints and tail folds | replace the maintainer body; readers unchanged |
| R-SUB | `SUBSCRIBE TO` | Live | used for incremental findings and live triage post-1.0 | — |
| R-BR | Branch fork/merge, `DIFF` family | Read selectors live; fork/merge planned | drafts as intent logs (promotion = replay = merge-ladder rung 1); scenarios as scratch-book replay via `open_memory` | drafts gain optional branch materialization; scenarios become forks; promotion stays intent replay |
| R-IDX | Beacon property indexes; FTS/HNSW | Property indexes live; FTS/HNSW per-call | accelerators only; never semantics | — |
| R-PRISM | `CALL fnx.*` over `SnapshotGraphView` | Live subset | direct `fnx` over Lantern projections where the subset lacks an algorithm | — |
| R-WARDEN | Macaroon caveats compiled to planner predicates; redaction; audit pipeline | Types live; compilation in progress; audit pipeline planned | caveats evaluated by Steward before query construction (refusal, never result filtering); FrankenAccounting access log; redaction by document-class storage separation | adopt compiled caveats and substrate redaction; FA-INV-10 clause text updated by registered decision |
| R-CERT | Plan certificates, `ReplayManifest`, grades | Live for native reads | FrankenAccounting `Certificate` wraps substrate certificates where available | — |
| R-MMR | §5.8 accumulator, transparency checkpoints, witness policies, verifier SDK | Planned | journal-level accumulator and checkpoints (permanent design) | cross-anchor `AccumulatorState` into the substrate MMR; two independent chains |
| R-VM | `fgdb-udf-vm` deterministic bytecode | Planned | Canon IR interpreter under stripped `Cx`; IR frozen | compile IR to VM; differential on every golden corpus |
| R-BULK | Bulk-load protocol with chunk manifests | Planned | bounded `WriteBatch` chunks with FrankenAccounting-level chunk manifests and resume | adopt substrate manifests |
| R-EXP | `ExpiryContract` / epoch advance | Planned | FrankenAccounting expiry sweep control entries under time evidence | adopt the contract for pending-entry visibility; sweep remains for resolutions |
| R-CLI | `fgdb` robot-mode conventions, exit-code dictionary, `doctor` | Live | matched by `fa` | — |
| R-SRV | `fgdbd` server posture, FGP | Live (bounded) | not used in 1.0; `fad` is embedded + local RPC + MCP | post-1.0 networked posture |
| R-LAB | `fgdb-sim`, lab VFS, crash matrices | Live for bounded scenarios | `fa-sim` extends | — |

---

*Fin. The books the 2030s deserve — immutable, bitemporal, evidenced, exact, provable, and operable by machines — built from parts the 2020s already proved: ours.*
