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

> **Status (2026-10-09): plan stage.** This repository currently contains the comprehensive design plan, the agent operating rules, and the repository scaffolding. There is no code yet. Implementation begins with Gate G0 (the constitutional registries) per §19 of the plan, after the plan's review rounds reach steady-state and are converted to beads.

> **A note on tense.** The rest of this README is written in the **present tense, as if the entire design in [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md`](./COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md) is fully realized**: the 1.0 target state. This is deliberate — it describes the *finished* system so it gets trued-up in place as milestones land (§19's gates G1→G4) rather than rewritten later. Where the plan stages something as future work, this README says so plainly.

---

## TL;DR

**The problem.** Every system that holds books today fossilized around a decision made decades ago. ERP general ledgers (SAP's Universal Journal, Oracle, NetSuite) store balances as mutable rows and bolt an audit log beside them; small-business tools edit entries in place; TigerBeetle got the primitive exactly right — immutable transfers, 128-bit integers, two-phase holds, deterministic simulation — and is, by design, a two-leg balance engine with no journal entry, no periods, no close, no restatements, no documents, no "the books as of", no relationships; fintech ledger APIs stop at balances and transactions and hold your system of record in their SaaS; plain-text accounting got immutability and reproducibility right and is single-user with filename-grade evidence; audit and forensic tooling begins with "export the GL to CSV". The field solved every hard subproblem in isolation — REA, bitemporal time, event sourcing, Fowler's reversal/replacement adjustments, the AICPA Audit Data Standards, AS 2401's journal-entry tests, Certificate Transparency — and **no shipping system ever composed them.**

**The solution.** `franken_accounting` composes them, on a substrate that already has the hard parts: FrankenGraphDB's immutable content-addressed commit stream (our system time), bitemporal property graph (our REA model and effective dates), git-style branches (our drafts and but-for scenarios), incremental views (our registers), capability security (our segregation of duties), and deterministic replay (our certificates). One codebase, three postures: an embedded library (`fa`), a CLI (`fa`) whose robot mode is the agent contract, and an MCP server (`fa-mcp`) hosted by the `fad` daemon.

| | `franken_accounting` |
|---|---|
| Truth | The journal. There are no balance rows; registers, trial balances, statements, agings, and findings are derived folds, never authoritative, always verifiable by recomputation (`fa verify registers`). |
| Immutability | Append-only. Corrections are `Reverse`/`Replace`/`Reclass`/`Restate` entries with `SUPERSEDES` lineage. Period close, reopen, and lock are journaled, approved control entries — never a flag. |
| Time | Bitemporal by construction: **effective date** (which period; user-supplied, validated) × **recorded time** (when the books learned; assigned by the commit stream, never user-supplied). `FOR PERIOD FY2024 AS KNOWN AT 2025-03-03`, `AS ORIGINALLY REPORTED`, `AS CURRENTLY STATED`, `AS REPORTED IN <certificate>` are selectors, not backups. |
| Exactness | `Amount { unit, mantissa: i128 }` at the unit's registered scale; every rounding, allocation, and FX conversion is a named law with a residual leg. No float ever touches an amount. No tolerance. No auto-balancing. |
| Evidence | Nothing posts without a why: documents, the REA event, the posting-rule version, principal/agent/session, approvals, and every rate and basis document form a content-addressed provenance closure. `fa explain evidence <entry>` walks it. |
| Proofs | A journal-level Merkle accumulator with witnessed transparency checkpoints; evidence bundles (`.fab`) with inclusion proofs; `fa-verify`, a dependency-free static verifier a regulator runs on an air-gapped laptop. |
| Graph | Accounts, entities, parties, instruments, documents, periods, findings are vertices; legs, approvals, ownership, settlement, intercompany pairs, supersession are edges. Tracing (LIBR/FIFO/pro rata as code), related-party exposure, layering, kiting, Ponzi motifs, structuring: graph procedures in the database, certified. |
| Determinism | Same closure ⇒ byte-identical output, with a certificate. A damages schedule computed in 2026 replays in 2029. |
| Agents | Typed intents with dry-run plans; refusals that name the law and the exact fix; drafts that cannot touch trunk without authorized promotion; `fa triage` in one call; robot-mode NDJSON; an MCP server with the same verbs. |
| Safety | `unsafe_code = "forbid"` everywhere, zero unsafe islands. Closed dependency universe: `std` + the pinned nightly + asupersync + FrankenGraphDB + `fnx` + fastmcp_rust (MCP posture only). No serde, no tokio, no chrono, no decimal crates, no arrow, no sqlite. |

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
fa-verify fy2025-cash.fab --checkpoint ck:…      # std-only binary; verifies inclusion, consistency, folds, replay
```

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
│  Block-MVCC + Graph-SSI · valid time · branches · Ripple · Beacon ·      │
│  Prism/fnx · Warden · certificates · lab runtime (asupersync)            │
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

1. **The dependency universe is closed.** `std` + the pinned nightly + four foundations. Everything else is built in-house and owned.
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
| Primitive | N-leg immutable entry, balanced per unit | 2-leg immutable transfer | Mutable journal rows | 2-leg or N-leg postings | Text transactions |
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

> **Target state.** The `franken_accounting` column is the design target; nothing is implemented yet. Several substrate capabilities it relies on (valid-time contracts, branch fork/merge, Ripple views, escrow, the MMR, the UDF VM) are planned in FrankenGraphDB and have registered interim postures in the plan's Appendix H.

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
crates/            fa-types fa-money fa-time fa-registry fa-model fa-journal fa-registers
                   fa-escrow fa-palimpsest fa-docket fa-notary fa-canon fa-intents
                   fa-statements fa-concordat fa-lantern fa-steward fa-formats fa-verbs
                   fa fa-cli fad fa-mcp fa-reference fa-sim fa-oracles fa-gen fa-bench
                   fa-conformance fa-fuzz fa-verify
tools/registry-check   std-only validator of the registries (G0)
scripts/check.sh       the one gate (verdict contract: exit code is the verdict)
docs/                  negative evidence, ADRs, threat & trust model
templates/             chart-of-accounts and statement-definition templates (data)
```

---

## License

MIT License with the OpenAI/Anthropic rider — see [`LICENSE`](./LICENSE). The rider is a condition of the license and must accompany every copy and derivative work.
