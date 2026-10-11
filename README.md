# franken_accounting

<div align="center">

[![License: MIT + Rider](https://img.shields.io/badge/License-MIT_+_OpenAI/Anthropic_Rider-blue.svg)](./LICENSE)
[![Rust Edition](https://img.shields.io/badge/Rust-2024_Edition-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![toolchain: nightly](https://img.shields.io/badge/toolchain-nightly-purple.svg)](./rust-toolchain.toml)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![substrate: FrankenGraphDB](https://img.shields.io/badge/substrate-FrankenGraphDB-teal.svg)](https://github.com/Dicklesworthstone/frankengraphdb)
[![deps: closed universe](https://img.shields.io/badge/deps-closed_universe-black.svg)](./COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md)

**A universal, evidence-native, double-entry accounting system of record in memory-safe Rust, built on FrankenGraphDB. The journal is the database: every balance is a certified fold over an immutable, bitemporal entry stream; every entry carries its evidence; every correction is lineage, never an edit; every report replays byte-for-byte; every proof verifies offline. Built for CPAs, regulators, litigators, forensic investigators — and for AI agents as the operators.**

</div>

> **Status (2026-10-11): implementation in progress.** The Rust workspace includes the embedded library, persistent CLI, book writer-lease daemon and registered MCP tools, exact money and calendar primitives, chart installation, period transitions, posting and reasoned reversal, register folds and verification, and an independent arithmetic oracle. Trial balances support stock balances, period activity, civil-date cutoffs, and historical commit-sequence snapshots. Trial balances, leaf-account balance explanations, and open-items reports support retained certificates that replay their exact historical results through native certified reads. Gate G0 and the full Genesis acceptance criteria remain open. Signed outsider evidence bundles and the broader workflows below remain design targets.

> **A note on tense.** The rest of this README is written in the **present tense, as if the entire design in [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md`](./COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md) is fully realized**: the 1.0 target state. This is deliberate — it describes the *finished* system so it gets trued-up in place as milestones land (§19's gates G1→G4) rather than rewritten later. Where the plan stages something as future work, this README says so plainly.

### Reporting available now

For a book with posted entries, the current CLI supports:

```bash
# Includes opening history and all postings through the period's last day.
fa tb --book ./books/acme --period FY2026-P03 --json
# Movement in exactly this period; repeated period selectors count once.
fa tb --book ./books/acme --period FY2026-P03 --activity --json
# Effective dates through March 15, using the journal as it stood at sequence 42.
fa tb --book ./books/acme --as-of 2026-03-15 --as-known-at 42 --json
fa verify registers --book ./books/acme --period FY2026-P03 --json
fa registers materialize --book ./books/acme --period FY2026-P03 --json
```

Omitting `--as-known-at` selects the current head; the response records the resolved sequence. A later backdated entry appears at head but cannot change a report at an earlier sequence. `--as-known-at` also accepts an RFC 3339 instant when the book contains retained TimeEvidence ticks. It resolves the latest recorded sequence in the matching tick bucket, reports the original frontier and both brackets under `coordinate.time_evidence`, and refuses an instant before the first tick. Numeric UTC offsets and up to nine fractional digits are exact. `--as-of` remains a civil-date selector. These reports are exact payload folds; `tb` can retain a replay certificate as described below. The [persistent CLI tests](./crates/fa-cli/tests/cli.rs) exercise book creation, chart installation, posting, reporting, retained replay, refusals and recovery with the actual binary.

Reports show posted and pending amounts separately. A hold reserves its original period; a later partial posting releases the entire hold and posts only the explicitly selected sub-vector in the resolution's period. A void releases the hold without posting. Earlier recorded snapshots still show the unresolved reservation. Limited accounts reserve pending outflows; pending inflows cannot fund spending. `fa verify availability` compares each limited account's expected cell, including its account binding, with a journal fold. Library sweeps expire holds using committed ticks; daemon scheduling and full timing simulation remain unfinished.

Register verification compares both amount columns, counts, identity, period membership, watermark and fold checksum against the journal payloads. Rebuilding repairs derived rows and retires phantom cells without changing journal entries. Existing register caches from before the pending-column format must be rebuilt; their missing columns are reported as drift rather than assumed to be zero.

The embedded API's `Book::advance_registers(period)` consumes new committed entry payloads through `delta_since` for native posted/pending period cells. It publishes cells and the consumed cursor atomically; `Book::rebuild_registers(period)` replaces them from a fresh journal fold. Reopening rehydrates the delta window, and an actually retired cursor falls back to a full rebuild. Staged migration chunks stay invisible; finalizing a run triggers a full fold to include newly activated chunks older than the cursor. Pending-sum overflow also falls back to the final fold, so holds released later in the same suffix do not prevent advancement; a genuinely oversized final sum still fails. `verify_registers` also checks the maintenance state against its journal prefix. This slice still scans projection metadata and writes the period's cells; it makes no throughput claim. Reports retain their literal folds. Historical register checkpoints, cadence policies, other register families, supervised daemon maintenance and cached report reads remain unfinished.

### Stored unit identity

New books retain a versioned canonical definition for every unit: its numeric
identifier, code, version, scale, kind, currency ISO number where applicable,
and default rounding-law identifier. The book also commits to the complete
unit table. Reopening reconstructs the runtime table from those stored
definitions and checks them against the executable's supported registry.
Changed definitions, missing members, corrupt payloads and unsupported unit
identifiers fail with exit 5 before amounts are interpreted. Extra units in a
newer executable are not silently installed into an older book.

Financial CLI output checks every amount's unit and returns exit 5 for an
unknown identity. Unit checks for trial balances, explanations and open-items
reports also run before retaining certificate metadata in the book or creating
a requested certificate file.
Library callers can use `Amount::try_render` to
propagate the same typed error; the compatibility `render` method labels an
unknown value as a raw mantissa without guessing its scale.

**Compatibility:** books created before canonical unit payloads and the table
commitment were recorded are refused. Keep the creating executable for those
books. An explicit, authorized backfill that journals the adopted definitions
and their provenance is still pending; reopening never fills missing facts from
the current binary. This does not implement unit evolution or redenomination.

### Certified reports and replay

Retain the exact selector, known-at sequence, accounting journal prefix, registry
versions and native read closure behind a trial balance, leaf-account balance
explanation, or open-items report:

```bash
# Retains the certificate in the book and saves a new external copy.
fa tb --book ./books/acme --period FY2026-P03 --certificate-out march.cert --json
# Verifies the retained inputs and reproduces the original trial_balance line.
fa replay march.cert --book ./books/acme --json
# Reports Current or SupersededBy, with the later relevant entry identities.
fa certificate status march.cert --book ./books/acme --json

# Explain one leaf account, retaining its cells, contributions and history.
fa explain balance 1000 --period FY2026-P03 --as-known-at 42 \
  --certify --book ./books/acme --json
# Retain item balances, their applications and account metadata at that snapshot.
fa open-items --account 1000 --as-known-at 42 \
  --certificate-out cash-items.cert --book ./books/acme --json
fa replay cash-items.cert --book ./books/acme --json
```

Instant-selected certificates also retain their requested instant, observed frontier,
and tick identities. Replay uses those saved brackets even after later ticks or
postings arrive. An open upper bracket is explicit; this is a clock-observation
bucket, without a claim about the physical instant of each commit. The same
instant selector is available on `open-items` and `explain balance`. Ticks are
currently journaled through the existing library API; automatic daemon tick
scheduling remains unfinished.

The original call emits two robot lines: `trial_balance`, `balance_explained`,
or `open_items`, followed by `report_certificate`, with the certificate digest
in both envelopes. The certificate records the report's canonical output format
and digest. `--certificate-out` implies
certification. `--certify` retains an immutable, content-addressed certificate in
the book; repeated retention of the same certificate reuses its recorded sequence.
The second line's `bytes` field is its complete canonical encoding as hex.
`fa replay -` and `fa certificate status -` accept those hex bytes, or canonical
binary bytes, on stdin. Replay and status also accept the retained `oid`, either
as 64 hex digits or with a `C:` prefix, from the original book: `fa replay C:<oid>`
and `fa certificate status C:<oid>`. The optional file
or complete bytes remains useful as an external copy. MCP exposes the same flow through
`fa_read_trial_balance`, `fa_read_explain_balance`, or `fa_read_open_items` with
`certify: true`, followed by `fa_read_replay` or `fa_read_certificate_status` with
the returned `oid` or `bytes` as `certificate`.

Certification writes a metadata object and advances the book frontier; it posts
no accounting entry and does not change balances. Uncertified reports, replay and
status do not publish anything.
The certificate fixes the original `--as-known-at` sequence, including a resolved
HEAD, so later backdated entries can supersede its current status while its
historical report still replays exactly. Before returning `Current`, status also
compares the current report's content with the original. Changes without a later
contributing entry, such as newly created earlier fiscal periods in an as-of
report, refuse with `FA-REF-150`; the original historical report remains replayable.
Stock, `--as-of` and `--activity`
trial balances are supported. The declared scope is `fa-fold-over-prefix` with
`embedded-owner` authority: unsigned replay against retained native history.
Balance explanations bind historical account metadata, evidence references,
reversal lineage, cell history, and the whole-period fold. Open-items certificates
bind the optional account filter, historical account metadata, and application
and reversal lineage. An account absent at the selected snapshot refuses instead
of producing an empty result. All three report families support commit-sequence
and RFC3339 instant selectors; replay preserves the original coordinate even
after later postings or ticks arrive. Signed witness claims, independent offline
bundles, and certificates for additional report families remain unfinished.

### Embedded execution

`AsyncBook<V>` accepts the caller's `PurposeContexts` for each operation and
uses the supplied filesystem for both the journal and external document bytes.
It owns no runtime. The `Book` convenience API creates a production runtime
for its synchronous operations and delegates to the same implementation. This lets a host application or the
lab runtime supply cancellation, budgets, scheduling and filesystem faults
without a second accounting implementation.

Tick recording, bounded expiry and reversal sweeps, and their backlog reads
also use this async core. The `Book` timing adapters accept the caller's
context. The kernel takes automatic effects only from a corroborated committed
tick; a failed description seal aborts the current batch without advancing
its cursor. These are committed-tick semantics, not a guarantee of clock accuracy.

The lab smoke tests cover a posted entry, exact expected register cells,
external evidence, virtual sync latency, crash/reopen, idempotency, caller
cancellation, tick-driven expiry and reversal, and an injected write failure.
The timing test calls the library; it does not run the daemon scheduler.
The full registered crash-point
matrix, concurrency exploration and 1,000-seed Genesis campaign remain open
under `fa-0fl`; these smoke tests do not establish that broader claim.

The posting and period kernels also expose owned prepared transactions.
Their ordinary entrypoints prepare and commit through the same code.
Preparation retains the substrate's original witnesses; commit rechecks the
acting capability's expiry at the current frontier and validates those
witnesses without refreshing them. This permits controlled interleavings
between preparation and publication while preserving the accounting laws.
Period opening also witnesses the population of reversal schedules, including
an empty population, so a newly due schedule invalidates a prepared opening.
The filesystem fault tests currently cover consistently anchored paths;
relative-path alias handling in the substrate simulator is tracked by `fa-n4m`.

### Leg projection verification

`fa verify projections` compares stored leg mirrors and graph edges with the
canonical entry payloads at one committed snapshot:

```bash
fa verify projections --book ./books/acme --json
```

The check derives leg identities from each entry, so a missing `HAS_LEG`
edge cannot conceal a missing projection. It checks exact scalar mirrors,
wide-amount fallback bytes, labels, and all `HAS_LEG`, `POSTS_TO`, `IN_UNIT`
and dimension `FOR` edges. Pending and staged migration entries are included.
The command returns deterministic counts on success or exit 8 with drift
details, and never writes. The same target is available through
`fa_book_verify` in MCP; `Book::verify_projections` and
`AsyncBook::verify_projections` also accept an explicit historical sequence.

Ordinary postings and scheduled reversals now publish unit and dimension
edges together with the entry. Prefixes created by older versions can report
those previously omitted edges as missing. Automatic projection rebuilding
remains unfinished; verification reports that condition without repairing it.
Applied counters and settlement edges retain their separate
`fa verify open-items` check.

### Entry accumulator checkpoints

The CLI can publish an unsigned checkpoint over the book's entry prefix and
recompute the stored chain from the journal:

```bash
fa checkpoint create --grant witness --book ./books/acme --json
fa verify accumulator --book ./books/acme --json
```

Publication requires witness authority; an Agent profile cannot publish on
trunk. Verification reports `verified_through`, the newest checked prefix,
so later postings are covered only after another checkpoint. With no stored
checkpoints it returns `status: "no_checkpoints"` and a null
`verified_through`. A corrupt state or broken chain produces exit 8 and a
finding; checkpoint creation refuses a corrupt predecessor. Verification
and proof generation also reject later rewrites or retirements of checkpointed
entries, even when the original historical snapshot is still readable.
These states cover entries, including control entries. Signed transparency checkpoints,
document-receipt coverage and evidence bundles remain unfinished. The
[CLI tests](./crates/fa-cli/tests/notary.rs) exercise persistence, later
postings, authorization and real storage corruption.

### Exact arithmetic available now

`fa-money` supports the full signed `i128` amount range, including parsing,
rendering, identity conversion and allocation of `i128::MIN`. Posting legs
remain nonnegative. Conversion uses exact arbitrary-precision intermediates;
allocation uses a bounded wide sum of weights. Rates have private, reduced
arbitrary-size integer coefficients supplied by FrankenSymPy. Parsing,
composition, conversion and canonical rate encoding take a caller-owned
`ArithmeticBudget`, which checks `Cx` cancellation and deterministic resource
limits before work. Only the final, law-rounded amount must fit `i128`.
Unit registration rejects unsupported scales and conflicting definitions of
an existing version; historical amounts retain their original scale.
Valuation checks native balance before absorbing a law-bounded rounding
residual. Tests compare conversions under all nine rounding laws against
`fgdb-bigint`; the reference engine retains its own arithmetic and imports
only registry data and calendar primitives. Journaled unit evolution and
complete FX-law integration remain unfinished (`fa-p7r`).

**FrankenSymPy assessment (2026-10-10, corrected after the owner's clarification).**
The owner's own Rust projects — Franken-named or not — are eligible dependencies,
including their recorded transitive dependencies. [`frankensympy`](https://github.com/Dicklesworthstone/frankensympy/tree/bd1ad68a3a06e0a0ed6ee4a9bc76d85dc9e67e2e)
supplies the arbitrary-precision exact rationals used by `Rate`.
Its [`fsym-rational`](https://github.com/Dicklesworthstone/frankensympy/blob/bd1ad68a3a06e0a0ed6ee4a9bc76d85dc9e67e2e/crates/fsym-rational/src/lib.rs)
and `fsym-bigint` APIs provide normalized rationals, cross-cancelled composition
and metered arithmetic. The integration (`fa-pri`) uses those APIs for large
rate coefficients and exact conversion intermediates, with registered rounding
back to fixed-scale `i128` amounts. It includes a `Cx`-backed budget meter,
bounded input decoding, exact dependency pins and recorded wrapper paths.
`fgdb-bigint` remains an independent test oracle; a production `fsym-rational`
calculation cannot also serve as its own independent oracle. The versioned
rate codec rejects nonminimal and unreduced encodings and admits coefficient
storage before allocation. Symbolic rule analysis has no current consumer.
No performance improvement is claimed; verification results and the exact
foundation revision are recorded with the implementation landing.

---

## TL;DR

**The problem.** Every system that holds books today fossilized around a decision made decades ago. ERP general ledgers (SAP's Universal Journal, Oracle, NetSuite) keep posted journals immutable but store balances in mutable summary tables, model periods as flags, re-key reversals, and keep the audit trail in a separate change-document table with no "as known at" selector; small-business tools edit entries in place; TigerBeetle got the primitive exactly right — immutable transfers, 128-bit integers, two-phase holds, deterministic simulation — and is, by design, a two-leg balance engine with no journal entry, no periods, no close, no restatements, no documents, no "the books as of", no relationships; fintech ledger APIs stop at balances and transactions and hold your system of record in their SaaS; plain-text accounting got immutability and reproducibility right and is single-user with filename-grade evidence; audit and forensic tooling begins with "export the GL to CSV". The field solved every hard subproblem in isolation — REA, bitemporal time, event sourcing, Fowler's reversal/replacement adjustments, the AICPA Audit Data Standards, AS 2401's journal-entry tests, Certificate Transparency — and **no shipping system ever composed them.**

**The solution.** `franken_accounting` composes them, on a substrate that already has the hard parts: FrankenGraphDB's immutable content-addressed commit stream (our system time), bitemporal property graph (our REA model and effective dates), git-style branches (our drafts and but-for scenarios), incremental views (our registers), capability security (our segregation of duties), and deterministic replay (our certificates). One codebase, three postures: an embedded library (`fa`), a CLI (`fa`) whose robot mode is the agent contract, and an MCP server (`fa-mcp`) hosted by the `fad` daemon.

| | `franken_accounting` |
|---|---|
| Truth | The journal. There are no balance rows; registers, trial balances, statements, agings, and findings are derived folds, never authoritative, always verifiable by recomputation (`fa verify registers`). |
| Immutability | Append-only. Corrections are `Reverse`/`Replace`/`Reclass`/`Restate` entries with `SUPERSEDES` lineage. Period close, reopen, and lock are journaled, approved control entries — never a flag. |
| Time | Bitemporal by construction: period-scoped entries have a validated **effective date**; all entries have a commit-assigned **recorded sequence**, never user-supplied. Undated Book controls follow registered applicability rules. Instant selectors resolve through retained TimeEvidence. `FOR PERIOD FY2024 AS KNOWN AT 2025-03-03`, `AS ORIGINALLY REPORTED`, `AS CURRENTLY STATED`, `AS REPORTED IN <certificate>` are selectors, not backups. |
| Exactness | `Amount { unit, mantissa: i128 }` at the unit's registered scale; every rounding, allocation, and FX conversion names a registered law and exact error bound. Native residual postings are explicit where the law requires them; base-valuation residuals are recorded and absorbed under plan §5.2. No float ever touches an amount. No tolerance. No auto-balancing. |
| Evidence | Nothing posts without a why: documents, the REA event, the posting-rule version, principal/agent/session, approvals, and every rate and basis document form a content-addressed provenance closure. `fa explain evidence <entry>` walks it. |
| Proofs | A journal-level Merkle accumulator with witnessed transparency checkpoints; evidence bundles (`.fab`) with inclusion proofs; `fa-verify`, a dependency-free static verifier a regulator runs on an air-gapped laptop. |
| Graph | Accounts, entities, parties, instruments, documents, periods, findings are vertices; legs, approvals, ownership, settlement, intercompany pairs, supersession are edges. Tracing (LIBR/FIFO/pro rata as code), related-party exposure, layering, kiting, Ponzi motifs, structuring: graph procedures in the database, certified. |
| Determinism | Same closure ⇒ byte-identical output, with a certificate. A damages schedule computed in 2026 replays in 2029. |
| Agents | Typed intents with dry-run plans; refusals that name the law and the exact fix; drafts that cannot touch trunk without authorized promotion; `fa triage` in one call; robot-mode NDJSON; an MCP server with the same verbs. |
| Safety | `unsafe_code = "forbid"` everywhere, zero unsafe islands. Dependencies are `std`, the pinned nightly and suitable Franken-suite foundations with exact pins and recorded transitive paths. Unrelated third-party crates are not imported directly by accounting code. FrankenGraphDB is the sole book storage engine. |

---

## Quick example

```bash
# A book is a FrankenGraphDB directory. Keys are three lines of 64 hex chars, owner-only.
fa book create --book acme.fabook --key-file fa.keys --base-unit USD --calendar monthly12 --gaap USGAAP
fa chart import --template us-gaap-smb

# Bare `fa` is triage, never a TUI. Agents start here.
fa triage --json

# Post a typed intent. Agent-profile capabilities get --dry-run implied; the plan is a certificate.
fa invoice --party ACME-CUST-17 --date 2026-03-14 \
   --line 'qty=10 unit_price="125.00 USD" item=SKU-9 product=Widgets' \
   --evidence inv-10442.pdf --dry-run --json
#  → plan: legs (1200-AR 1,250.00 D / 4000-Revenue 1,250.00 C / 2300-SalesTaxPayable …), period 2026-03 Open → Admit,
#     SoD ok, register deltas, evidence heads, certificate c:…
fa invoice … --confirm-plan c:… --json          # commits; returns EntryRef { vid, entry_digest } + marker

# Why is this balance what it is? The register, its fold proof, and every contributing entry with evidence.
fa explain balance 1200-AR --for-period 2026-03 --as-known-at '2026-04-02T00:00:00Z' --json

# The books as they stood on a date, for a period — a selector, not a restore.
fa tb --for-period FY2025 --as-known-at '2026-02-01T00:00:00Z' --json
fa tb --for-period FY2025 --as-originally-reported --json

# Corrections are lineage. The original stays.
fa reverse E:… --reason WrongAccount --json
fa case open --kind Restatement --periods FY2024-Q4 --narrative restatement-memo.pdf

# Rehearse the close on a draft, diff it, let a human promote it.
fa draft new close-2026-03 && fa close dry-run --period 2026-03 --draft close-2026-03 --json
fa diff --from draft:close-2026-03 --to trunk --json

# Forensics, in the database, certified.
fa jet --period FY2025 --json
fa trace libr --source P-412 --from 2025-01-01 --to 2025-12-31 --max-hops 8 --json
fa procedure run graph.related_party_exposure --entity ACME --json

# Proofs an outsider can check without the book.
fa bundle produce --scope 'period:FY2025 account-subtree:1000' --with-evidence --out fy2025-cash.fab
fa-verify fy2025-cash.fab --checkpoint ck:…      # std-only; reports the predicates and scope actually verified
```

An account-subtree extract needs authenticated hierarchy and complete account/range coverage, or the complete-prefix fallback. Membership alone does not prove scope completeness. A stock balance also needs its contributing opening history or an explicitly labeled baseline plus complete delta; the verifier reports these predicates separately.

```gql
-- GQL through the substrate, plus the FrankenAccounting profile.
MATCH (l:Leg)-[:POSTS_TO]->(a:Account {code:'1200'}), (l)-[:FOR]->(:DimensionValue)<-[:IS]-(p:Party)
WHERE EXISTS { MATCH (p)-[:RELATED_TO|OWNS|CONTROLS*1..3]-(:LegalEntity {code:'ACME'}) EFFECTIVE AT l.effective_date }
FOR PERIOD 'FY2025' AS KNOWN AT '2026-02-01T00:00:00Z'
CALL fa.open_amount(l) YIELD open, age_days WHERE age_days > 90
RETURN p.name, sum(open) AS exposure ORDER BY exposure DESC;
```

---

## The six bets

| Bet | One-line statement |
|---|---|
| **A1 · One Posting Universe** | The journal is the database. Balances are deterministic, certified folds at a `(book, branch, known-at, effective)` coordinate, materialized incrementally, verified by recomputation. |
| **A2 · Bitemporal by Construction, Period Law Mechanized** | Effective × recorded time are orthogonal selectors; close, reopen, and restate are journaled, authorized events enforced at commit; restatements have first-class lineage and diff certificates. |
| **A3 · Evidence-Native and Outsider-Verifiable** | Every entry carries a content-addressed provenance closure; bundles with inclusion proofs; a dependency-free verifier. |
| **A4 · The Ledger Is a Graph (REA)** | Relationships are first-class; forensic questions are graph procedures over the time-travelable graph with determinism witnesses. |
| **A5 · Exact and Deterministic** | Exact fixed-scale integers, named rounding/allocation/FX laws, certified replayable reports. |
| **A6 · Agent-Native with Counterfactual Branches** | Typed intents, dry-run plans, teaching refusals, branch-per-task, what-if/but-for scenarios with ledger diffs, one verb registry across CLI/daemon/MCP. |

---

## How it works

```
┌──────────────────────────────────────────────────────────────────────────┐
│  TELLER     fa (CLI, robot mode) · fad (daemon, writer lease, local RPC) │
│             fa-mcp (MCP tool clusters, resources, macros) · fa (library) │
│             one verb registry; GQL + the FrankenAccounting profile       │
└──────────────────────────────────────────────────────────────────────────┘
                                     ▼
┌──────────────────────────────┐  ┌───────────────────────────────────────┐
│  CANON   typed intents ·     │  │  STEWARD   capability caveats · SoD   │
│  deterministic posting rules │  │  profiles (Agent/Auditor/Regulator/…) │
│  dry-run plans · backtests   │  │  access audit · holds · erasure law   │
└──────────────────────────────┘  └───────────────────────────────────────┘
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  FOLIO     admit → resolve → canon → abacus → laws → plan → commit → ack │
│            balance law · leaf-only · dimensions · idempotency · batches  │
│            two-phase holds · escrow balance limits · subledger control   │
│  ABACUS    Amount{unit,i128} · rounding/allocation/FX laws · exact wide  │
│  ALMANAC   calendars · periods · state machine · selectors · close DAG   │
│  PALIMPSEST supersession lineage · restatement cases · diff certificates │
└──────────────────────────────────────────────────────────────────────────┘
                  ▼                                       ▼
┌──────────────────────────────────┐    ┌──────────────────────────────────┐
│  DOCKET   documents · custody ·  │    │  LANTERN   JET · Benford · dupes │
│  attestations · bank lines       │    │  graph tracing · kiting · Ponzi  │
│  NOTARY   accumulator · bundles  │    │  solvency · sampling · findings  │
│  checkpoints · fa-verify         │    │  STATEMENTS/CONCORDAT  reports · │
│                                  │    │  multi-book · FX · consolidation │
└──────────────────────────────────┘    └──────────────────────────────────┘
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  FRANKENGRAPHDB   Chronicle (immutable commit stream = system time) ·    │
│  optimistic WriteTxn + point-read witnesses (SSI planned) · certificates │
│  Prism/fnx · lab runtime (asupersync) · valid time / branches / Ripple / │
│  Beacon / Warden as they land (plan Appendix H interim postures)         │
└──────────────────────────────────────────────────────────────────────────┘
```

- **Folio** is the only writer. Every proposal passes admit → resolve → canon → abacus → laws → plan → commit → ack; a dry run is the same pipeline without the commit, and its certificate names the snapshot, so the plan an agent reviewed is the plan that commits — or a typed `PlanInvalidated` with a fresh one. A post racing a close is an SSI conflict, not a nightly finding.
- **Registers are folds.** The posting transaction never touches a register; a supervised maintainer folds the committed delta stream in commit order and publishes a watermark; reads are O(1) at the watermark plus an exact tail fold. `fa verify registers` recomputes every cell from the journal and compares digests.
- **Palimpsest** keeps "as originally posted" and "as currently stated" both first-class. A `RestatementCase` is rehearsed on a branch, approved under dual control, posted as one batch, and disclosed with a certified as-reported-vs-as-restated diff.
- **Notary** maintains a journal-level Merkle accumulator in commit order (never on the write path), signs transparency checkpoints — the auditor's signature on the year-end root is the modern successor of initials on the ledger page — and produces deterministic evidence bundles that `fa-verify` checks with its own BLAKE3 and nothing else.
- **Lantern** registers every procedure as a deterministic, certified computation with a typed evidence row: a Benford statistic is `statistical` evidence, never an invariant, and a finding is a reproducible observation with cited entries, never an accusation.
- **Teller** is built under one rule: the first command an agent instinctively tries must work or be redirected with a copy-pasteable fix, and nothing an agent can type by accident may damage the books.

The full design — every subsystem, the normative object schemas, the intent catalog, the admissibility matrix, the CLI/MCP contract, the sixteen invariants, the operation-cost registry, and the foundation dependency ledger — is in [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md`](./COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md).

---

## Who it is for

| Reader | What they get |
|---|---|
| **CPA auditor** | A GL extract in the AICPA Audit Data Standards layout whose completeness is *proven*; journal-entry tests, Benford, duplicates, seeded reproducible sampling; evidence pulls to the document; a snapshot pinned at engagement start; a witness signature on the year-end checkpoint. |
| **Regulator / examiner** | Point-in-time positions (`--as-known-at`) and schedules (call report lines, FR Y-9C) derived from the ledger with certificates; a scoped, time-boxed, fully logged read-only capability. |
| **Litigation consultant / expert** | But-for scenarios on a branch with a certified damages schedule; hash-certified productions with chain of custody; a methodology that replays years later. |
| **Forensic accountant / investigator** | Follow-the-money across accounts, entities, and banks; related-party closure; layering, kiting, structuring, Ponzi detectors; legal tracing rules as code; legal holds; workpapers with verifiable references. |
| **AI agent** | `fa triage`; typed intents with plans; refusals that teach; stable self-verifying handles; `fa explain`; drafts and scenarios; a sandbox (`fa demo init`); an MCP server with the same verbs. |

What it is **not**: an ERP, a payments processor, a UI, a tax engine or GAAP interpreter, a blockchain, or a SaaS. Judgment — materiality, treatment, recognition — belongs to professionals and the agent skills that act on this system; the system makes every mechanical fact exact and every judgment attributable and reversible with lineage.

---

## Design philosophy

1. **Reuse the Franken suite.** `std`, the pinned nightly and suitable owner-maintained Franken projects are eligible dependencies. Pin and record their transitive paths; own the accounting laws and contracts here.
2. **Memory safety is structural**, with zero unsafe islands.
3. **`Cx` everywhere.** Rules and procedures run under a context with no clock, entropy, network, or filesystem.
4. **Exactness is constitutional.** No float in any amount path; every rounding is a named law.
5. **The journal is the source of truth, and it is append-only.** Derived structures are never authoritative.
6. **Recorded time is never user-supplied.**
7. **Period law and segregation of duties are enforced at commit.**
8. **Authorization precedes observation.**
9. **Deterministic by default**, with certificates and replay.
10. **Claims have types; costs are registered.**
11. **FrankenGraphDB is consumed, never forked.** Capabilities it has not shipped yet have registered interim postures (plan Appendix H).

---

## How it compares

| | `franken_accounting` | TigerBeetle | ERP GL (SAP/Oracle/NetSuite) | Fintech ledger APIs | Plain-text accounting |
|---|---|---|---|---|---|
| Primitive | N-leg immutable entry, balanced per unit | 2-leg immutable transfer | Immutable posted journal; mutable balance tables | 2-leg or N-leg postings | Text transactions |
| Balances | Certified folds, never authoritative | Four balance fields per account | Mutable balance tables | Balances per account | Recomputed from text |
| Journal entry as object | ✓ | ✗ (encode in `user_data`) | ✓ | partial | ✓ |
| Periods / close / lock | ✓ journaled, enforced at commit | ✗ | flags | ✗ | ✗ |
| Restatements with lineage | ✓ cases + diff certificates | ✗ | manual | ✗ | git history |
| Bitemporal ("as known at") | ✓ by construction | ✗ | ✗ | ✗ | git history |
| Evidence model | content-addressed closure | ✗ | attachments | ✗ | filenames |
| Outsider-verifiable proofs | ✓ accumulator + `fa-verify` | ✗ | ✗ | ✗ | ✗ |
| Forensic graph analytics in-DB | ✓ | ✗ | ✗ | ✗ | ✗ |
| Branches / what-if | ✓ | ✗ | ✗ | ✗ | git branches |
| Exact arithmetic | i128 + laws | u128 | decimal columns | decimal/int | decimal |
| Deterministic simulation testing | ✓ (lab runtime) | ✓ (VOPR) | ✗ | ✗ | ✗ |
| Agent-native surface | CLI robot mode + MCP | client libraries | ✗ | REST/GraphQL | ✗ |
| System of record custody | yours (a directory) | yours | vendor/on-prem | SaaS | yours |

> **Target state.** The `franken_accounting` column is the complete design target, beyond the implemented subset described above. Several substrate capabilities it relies on (valid-time contracts, branch fork/merge, Ripple views, escrow, the MMR, the UDF VM) are planned in FrankenGraphDB and have registered interim postures in the plan's Appendix H.

---

## Installation

There are no releases or installers yet. When Gate G1 lands, the quick start will be:

```bash
git clone https://github.com/Dicklesworthstone/franken_accounting
cd franken_accounting
cargo run -p fa-cli -- demo init --scenario retail --seed 7
```

Releases will ship through the suite's self-releaser (`dsr`), never GitHub Actions.

---

## Repository layout (target)

```
COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md   the single source of truth
AGENTS.md                                                   operating rules for agents
registries/        constitution, invariants, evidence, slo, units, laws, entry classes,
                   admissibility, intents, procedures, caveats, SoD, verbs, exit codes,
                   refusal catalog, formats, robot schemas, operation costs, foundation deps
crates/            fa-types fa-money fa-time fa-registry fa-claim fa-sim-harness fa-model
                   fa-canon fa-policy fa-intents fa-journal fa-registers fa-escrow fa-palimpsest
                   fa-docket fa-notary fa-statements fa-concordat fa-lantern fa-query fa-steward
                   fa-formats fa-verbs fa fa-demo fa-cli fad fa-mcp fa-reference fa-sim
                   fa-oracles fa-gen fa-bench fa-conformance fa-fuzz fa-verify
tools/registry-check   std-only validator of the registries (G0)
scripts/check.sh       the one gate (verdict contract: exit code is the verdict)
docs/                  negative evidence, ADRs, threat & trust model
templates/             chart-of-accounts and statement-definition templates (data)
```

---

## License

MIT License with the OpenAI/Anthropic rider — see [`LICENSE`](./LICENSE). The rider is a condition of the license and must accompany every copy and derivative work.
