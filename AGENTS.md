# AGENTS.md — franken_accounting

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 — THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE 0.5 — SUITE-WIDE RULES LIVE IN /data/projects/AGENTS.md

The suite-wide rules in **`/data/projects/AGENTS.md`** bind you here too. Read it. Two sections
are load-bearing and are NOT duplicated below, so they cannot drift out of sync:

- **`## Named Reward-Hacking Patterns (ALL FORBIDDEN)`** — 12 named patterns, several already
  observed in this suite: gate self-weakening (and the exact price of a legitimate gate fix),
  proof-class inflation, golden regeneration reflex, commit-stream pumping, tautological tests,
  easy-lever cherry-picking, close-pump abuse, scope-splitting, spec-editing as progress,
  conformance metastasis, dependency smuggling, bench-path hardcoding.
- **`### Work-Graph Discipline`** — JSONL is truth and `beads.db` is disposable, `br sync
  --import-only` after every pull, single-writer on graph structure, closure on cited evidence
  with blocker beads gated on their named probe, `br dep cycles` stays empty.

The three that most often decide whether a number here is real: a **self-speedup is
MAINTENANCE, not a win** — a win needs the incumbent live in the SAME invocation; **never
weaken a gate to land a change**, and if a gate is genuinely defective, meet the evidence
standard and publish the win/lose split of what the fix admits; and **reporting a loss is a
success** — one line, revert, next lever, no retraction narrative.

**Status note (2026-10-09).** On this machine `/data/projects/AGENTS.md` exists but does not
yet contain the two named sections; the sibling projects (`frankengraphdb`, `asupersync`,
`frankensqlite`) cite them the same way. Until the owner restores them: treat the three
sentences above as the binding summary; the nearest full text of the named patterns is the
"Named Reward-Hacking Patterns (all forbidden)" section of
`/data/projects/hedge_fund_data_tool/AGENTS.md`; the one-line Work-Graph summary above is the
operative text. Do not invent the missing sections.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Branch Policy

- Primary branch is `main`.
- Do not reference `master` in docs/scripts.
- If release instructions require sync, push `main:master` after `main`.

---

## Project Mission

`franken_accounting` (FrankenAccounting) is a **universal, evidence-native, double-entry accounting system of record in memory-safe Rust**, built on FrankenGraphDB and the Franken/asupersync ecosystem. It ships as one codebase in three postures: an **embedded library** (`fa`), a **CLI** (`fa`) whose robot mode is the agent contract, and an **MCP server** (`fa-mcp`) hosted by the `fad` daemon that owns a book's single writer lease (the substrate's embedded handle is single-writer). It is built for CPAs, regulators and examiners, litigation consultants and expert witnesses, forensic accountants and investigators — and for AI agents as the primary day-to-day operators.

The leapfrog is not one trick; it is the *composition* of six bets, each feasible only because the substrate already exists:

- **A1 — One Posting Universe.** There are no balance rows. The journal is the database; every balance, register, trial balance, and statement is a deterministic, certified fold over the immutable entry stream at a `(book, branch, known-at, effective)` coordinate, materialized incrementally and verifiable by recomputation.
- **A2 — Bitemporal by Construction, Period Law Mechanized.** Period-scoped entries have an effective date; all entries have a recorded CommitSeq assigned by the commit stream, never user-supplied. Undated Book controls follow registered applicability rules, and instant selectors use retained TimeEvidence. Close, reopen, and restate are journaled, authorized events with lineage, enforced at commit.
- **A3 — Evidence-Native and Outsider-Verifiable.** Nothing posts without a why: documents, event, rule version, principal/agent, approvals, and computation inputs form a content-addressed provenance closure; any balance is verifiable offline with the dependency-free `fa-verify`.
- **A4 — The Ledger Is a Graph (REA).** Accounts, entities, parties, instruments, documents, periods, and findings are vertices; legs, approvals, ownership, settlement, and supersession are edges; tracing, related-party exposure, kiting, Ponzi motifs, and structuring are graph procedures over the time-travelable graph.
- **A5 — Exact and Deterministic.** Amounts are exact fixed-scale integers in registered units; every rounding, allocation, and FX conversion names a registered law and exact error bound; native residual postings are explicit where the law requires them, while base-valuation residuals are recorded and absorbed under plan §5.2; every report replays byte-for-byte from its certificate.
- **A6 — Agent-Native with Counterfactual Branches.** Typed intents with dry-run plans; errors that name the fix; agents work on drafts that cannot touch trunk without authorized promotion; what-if and but-for scenarios are branches with ledger diffs; one verb registry drives CLI, daemon, and MCP.

**The single source of truth for what we are building and why is [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md`](COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md).** Read it before writing any subsystem.

### What we stand on (the closed dependency universe)

**Owner clarification (2026-10-10): the closed-dependency restriction does not exclude the owner's own Franken projects.** The list below names current foundations, not an exhaustive admission list. Evaluate additional suite projects on technical fit, pin adopted revisions, and register their actual transitive dependency paths. A suite project's third-party implementation dependencies are confined behind that project's boundary; their presence is not a reason to reject the suite project.

- `/dp/frankengraphdb` — **the substrate.** The `fgdb` embedded API (`Database`, `WriteBatch`, `TxnCx`, GQL, certified reads, `delta_since`, `replay`), Chronicle's immutable commit stream (our system time — the `CommitSeq`; wall-clock instants enter only as journaled `TimeEvidence` ticks), bounded optimistic `WriteTxn`s validated by first-committer-wins over explicit point-read witnesses (our post-vs-close correctness today; Graph-SSI is planned upstream), and — as they land, each with a registered interim posture — valid-time contracts, branches, Ripple views, Beacon indexes, Prism + `fnx`, Warden capabilities, plan certificates, and the foundation value crates (`fgdb-types` incl. `CanonicalDecimal`, `fgdb-bigint`, `fgdb-claim`, `fgdb-evidence`, `fgdb-crypto`). Consumed at an exact git `rev` (it is unpublished). **Never forked, never copied into this repo.** Capabilities it has not shipped yet are listed with their interim posture in the plan's Appendix H and `registries/foundation_dependencies.toml`.
- `/dp/asupersync` — the operating system: structured-concurrency runtime (regions, obligations, `Cx` capability contexts), the **lab runtime** (virtual time, DPOR, chaos, crashpacks), networking, channels, Spork supervision, macaroons, metrics/OTel, statistical governance. Consumed as-is at the git rev FrankenGraphDB pins (`78b64636`, = 0.5.0) with `default-features = false`, plus `[patch.crates-io]` to that rev so fastmcp's registry pin resolves to the same crate — one `Cx` type per closure, proved by `cargo metadata` in CI.
- `/dp/franken_networkx` (`fnx-classes`/`fnx-algorithms` at the git rev `fgdb-prism` pins, `9d710b1c`, never a registry version) — the forensic algorithm brain, through Prism and directly over Lantern's projection graphs; CGSE determinism witnesses on every ranking.
- `/dp/fastmcp_rust` (`fastmcp-rust` `=0.12.0`) — the MCP framework, in the `fa-mcp` posture only.
- `/dp/frankensqlite` — **not linked** (plan §2.5 records the decision); its designs already live inside FrankenGraphDB.

---

## Product Shape

The project must be all three at once:
1. A reusable Rust library — `fa::Book::open(path | :memory:)` → `session(capability)` → `plan(intent)` → `commit(plan)`; certified reads (`trial_balance`, `balance`, `explain_balance`, `statement`, `query`); drafts, scenarios, diffs; bundles and verification. Every method takes `&Cx`.
2. A CLI `fa` with **robot mode** (agent-first, `event`-discriminated NDJSON envelope exactly as `fgdb`'s, `fa robot-docs schema`, `fa capabilities --json`, the exit-code dictionary `0 ok · 2 usage · 3 accounting-law/query refusal · 4 environment · 5 foundation/I-O · 6 conflict · 7 safety block · 8 verification failure` — a strict superset of `fgdb`'s; `1` is never emitted) and a human mode of plain-text tables. Bare `fa` prints triage and exits; it never opens a TUI, and there is no TUI in 1.0.
3. A daemon `fad` that holds the book's writer lease, serves the CLI over a local socket, and hosts the MCP server `fa-mcp` (tool clusters of ≤ 7, resources, macros, structured errors with `fix_hint`).

One **verb registry** (`registries/verbs.toml`) is the single source for all three surfaces; a parity gate fails CI when they diverge. Query language is **GQL** (through the substrate) plus the namespaced FrankenAccounting profile: `FOR PERIOD`, `AS KNOWN AT`, `EFFECTIVE AT|BETWEEN`, `AT BRANCH`, `AS ORIGINALLY REPORTED`, `AS CURRENTLY STATED`, `AS REPORTED IN <certificate>`, `CALL fa.*`, `EXPLAIN (CERTIFICATE)`.

---

## Spec-First Workflow

Implementation follows the plan, not ad-hoc invention. Read in this order:
1. [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md`](COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md) — the six bets, every subsystem (Folio, Abacus, Almanac, Palimpsest, Docket, Canon, Lantern, Statements/Concordat, Notary, Steward, Teller), the verification doctrine, the workstream/gate sequencing (§19), and the normative appendices (object schemas, intent catalog, admissibility matrix, CLI/MCP contract, invariant registry, operation-cost registry, foundation dependency ledger).
2. **The Invariant Registry (Appendix F / `registries/invariants.toml`)** — exactly sixteen load-bearing invariants (FA-INV-01 … FA-INV-16) with stable IDs, statements, and enforcement mechanisms. **CI cross-checks that every ID has a live checker.**
3. **The object schemas (Appendix A), the intent catalog (Appendix B), the admissibility matrix (Appendix C), and the CLI/MCP contract (Appendix D)** — the normative contracts a new crate must honor.
4. **The foundation dependency ledger (Appendix H)** — before relying on a substrate capability, check its row: live, or interim posture with its switch-over rule. Never assume a planned capability is live; never copy substrate code to fill a gap.

**Hard rule: no subsystem ships against an unenforced invariant.** A workstream exit gate (G1–G4, §19) cannot pass while any invariant it depends on lacks a live checker in `invariants.toml`. Promote a design assumption to enforced only after the checker exists.

**Planning discipline.** The plan is refined through review rounds (GPT Pro Extended Reasoning is the house choice; fresh-context agent reviews are the local substitute) until steady-state, then converted to beads with the dependency graph intact. Edit the plan in place; never create `PLAN_v2.md`. Record the review round and what changed in the commit message.

---

## The FrankenAccounting Engineering Doctrine (READ THIS BEFORE WRITING CODE)

These are the constitutional, non-negotiable rules from §1 of the plan. Violating any of them is memorialized in `docs/NEGATIVE_EVIDENCE.md` — whether the repair is a revert or, as the Backwards Compatibility rule requires, a fix in place.

1. **The dependency universe is closed to unrelated third-party additions, not to the owner's own projects — Franken-named or not (e.g. `fastapi_rust`).** Allowed: `core`/`alloc`/`std`, the pinned nightly, and suite foundations including `asupersync`, `frankengraphdb`, `fnx-*`, `fastmcp-rust` (in `fa-mcp` only), and other technically suitable projects written by the owner, Franken-named (e.g. `frankensympy`) or not (e.g. `fastapi_rust`). Adopted projects have exact source/version pins and recorded transitive closures. Accounting semantics — rounding and FX laws, period law, rules, evidence and format contracts — remain owned here; reuse suitable suite implementations beneath those contracts. **First-party code does not directly import unrelated serde, tokio, chrono, rust_decimal, bigdecimal, arrow or SQLite bindings.** Foundation-owned transitive dependencies are permitted through their exact wrapper allowlists in `deny.toml`, confined to the postures that consume them. Those allowlists must be updated for an adopted suite project, not used to veto it. FrankenGraphDB remains the sole book storage engine (§2.5).
2. **Memory safety is structural, with zero unsafe islands.** `unsafe_code = "forbid"` at the workspace and `#![forbid(unsafe_code)]` at every crate root. There are **no** `fa-unsafe-*` crates and there will be none; a raw-pointer need is routed upstream to the substrate's ledgered boundary crates.
3. **`Cx` everywhere.** Every function that performs I/O, takes a lock, allocates from a shared arena, or can block accepts `&Cx` or one of the substrate's purpose-typed wrappers. **The sharpest instance:** Canon posting rules and every Lantern procedure execute under a `Cx` with **no clock, entropy, network, or filesystem capability**. A rule that wants "today" receives it as a declared input.
4. **Exactness is constitutional.** `Amount { unit, mantissa: i128 }` at the unit's registered scale; checked exact wide intermediates as specified in plan §6.1; every rounding, allocation, and FX conversion names a registered law. Native residual postings require its named account; base-valuation residuals are recorded and absorbed under plan §5.2. Every residual satisfies its law-specific domain and exact error bound. **No float in any amount path, no tolerance, no silent auto-balancing.** A residual leg suggested by a refusal is never silently inserted into a commit.
5. **The journal is the source of truth, and it is append-only.** Committed entries, documents, attestations, approvals, rule versions, chart objects, periods, policies, cases, and findings are immutable; correction is a new object with `SUPERSEDES`/`RESOLVES` lineage. Registers, statements, agings, indexes, and findings are derived and **never more authoritative than the journal** (FA-INV-04); recovery discards and rebuilds them; `fa verify registers` must always be green.
6. **Recorded time is never user-supplied.** `recorded_at` is the `CommitSeq` of the entry's creating `MarkerRef`; wall-clock instants enter the book only as journaled `TimeEvidence` control entries (plan §7.1a), and migrations carry legacy timestamps as `migrated_from` provenance. There is no API, flag, or test helper that sets recorded time. (The lab runtime's virtual clock is the one legitimate way to control the ticks, and only under `fa-sim`.)
7. **Period law and SoD are enforced at commit.** The posting kernel resolves effective date → period for every period-scoped entry, including every monetary posting, checks the Appendix C matrix against the principal's capability inside the serializable transaction that reads the period's state, and evaluates `sod_policy.toml` for every dangerous class. Book-scoped controls have no posting date or period: their registered authority, SoD and applicability rules govern admission and known-at state; extract-row selection is distinct from required control/evidence closure (plan §7.1). Missing class rules/checkers mean unsupported behavior, never an implicit exemption. A race between a post and a close is an SSI conflict, never a cron job's finding.
8. **Authorization precedes observation.** Capability caveats are enforced before any storage observation (inherited FG-INV-20), or — in the interim posture before the substrate compiles caveats — by refusal before query construction. **Never as a result filter.**
9. **Prohibited shortcuts (constitutional).** No mutable balance column presented as a register; no "soft delete" or void bit; no edit-in-place of any journaled object; no period flag flip; no separate audit-log table that could diverge from the journal; no posting rule that reads the wall clock; no user-supplied recorded time; no detached background thread; no serde-derived enum as a durable format; no "interim" global writer lock; no second storage engine. Early code may implement a *subset* of a final abstraction — **never a substitute for it.** A slice that stubs the period law, writes a register directly, or auto-balances is a prototype, and prototypes are prohibited.
10. **FrankenGraphDB is consumed, never forked.** When a substrate capability is not live (branches, materialized views, valid-time contracts, escrow, the MMR, the UDF VM — Appendix H), the interim posture is a permanent-correct FrankenAccounting-level mechanism (intent-log drafts, the `delta_since` register maintainer, the journal-level accumulator) or a feature-flagged absence, with the switch-over rule registered. Never a copy of substrate code.
11. **Correctness outranks speed, always.** The reference oracle (`fa-reference`) and the verification ladder (§16) come first; performance work follows profile → remove one contention/allocation → re-verify determinism and the oracles → commit with evidence. A faster path that drifts a fold is reverted, not landed.
12. **Claims have types; costs are registered.** `invariant > proof > bounded_model > statistical > slo > benchmark` via `fgdb-claim`; a forensic detector's score is `statistical` evidence and never an invariant; every §17 number is an `slo.toml` row derivable from `registries/operation_costs.toml`.

### Accounting doctrine agents get wrong (do not do these)

- Do not "fix" an entry. Post a `Reverse`/`Replace`/`Reclass` with a reason code. The original stays.
- Do not pick an effective date to dodge a closed period. The matrix decides; the refusal tells you the admissible class and capability.
- Do not fabricate, infer, or "reconstruct" evidence. Every class has a registered evidence minimum (`evidence_policy.toml`); an entry below it is refused, a document you uploaded yourself is graded `AgentUpload` and needs a human `Reviewed` attestation before promotion, and the honest alternative to a missing document is an explicit `ManualAssertion` with a reason code — never a plausible PDF.
- Do not balance an entry by inventing a leg. Report the imbalance per unit; a residual leg exists only where a rule or intent names the registered rounding account and law.
- Do not convert currencies with a rate you typed. Rates are documents; conversions name an FX law.
- Do not write to trunk from an Agent-profile capability. Work on a draft; promotion is someone else's approval.
- Do not treat a register, aging, or statement as truth. Truth is the fold; `fa verify` proves it.
- Do not call a statistic an invariant, a detector's flag an accusation, or a hash a legal conclusion. State the technical predicate; counsel maps it.

---

## Adaptive-Decision Contract (decision cards)

Every adaptive decision — a bank-match heuristic, a forensic threshold, a sampling plan's stratification, a register checkpoint cadence, a bundle's evidence-inlining policy — emits a replayable **decision card** under a versioned policy epoch, carrying the state space, candidate actions, observed features, the expected-benefit interval, and a deterministic **pinned fallback** so the lab runtime replays the decision bit-for-bit. Learned scores are admissible **only as advisory features** with the analytic procedure as the fallback. No adaptive controller ships without its conservative deterministic fallback, and no decision card may change a committed amount.

---

## Code Editing Discipline

### No Script-Based Changes
**NEVER** run a script that mass-edits code files. Brittle regex transforms create more problems than they solve. Make code changes manually (use parallel subagents for many simple changes; do subtle/complex changes methodically yourself).

### No File Proliferation
Revise existing files in place. **NEVER** create `journalV2.rs` / `folio_improved.rs` / `abacus_enhanced.rs`. New files are reserved for genuinely new functionality; the bar is incredibly high. New crates appear only with their first real slice of a final abstraction (§18.1) and a `workspace_topology.toml` row.

---

## Backwards Compatibility

We are in early development with **no users**. Do things the **RIGHT** way with **NO TECH DEBT**. Never create compatibility shims or wrappers for deprecated APIs. Just fix the code directly. (Durable formats — object schemas, the bundle, the robot envelope, the registries — are the one exception: they are versioned additive-minor/breaking-major from day one, per Appendix A and the substrate's format law.)

---

## Toolchain

- Rust 2024 edition. Nightly toolchain pinned by date in `rust-toolchain.toml` (`nightly-2026-08-31`, matching FrankenGraphDB and asupersync). Bump together with the foundation pins and `franken-stack.lock`.
- `#![forbid(unsafe_code)]` at every crate root and `unsafe_code = "forbid"` at the workspace — and `forbid` can never be lowered. No exceptions, no ledger, no boundary crates.
- Cargo only, with crate-boundary enforcement per §18.1 (foundation → model → laws [`fa-canon`, `fa-policy`, `fa-intents`: pure, stripped `Cx`] → kernel → evidence → analytics → governance → interop → surface → verification). The kernel calls *down* into the laws layer for rule evaluation and authorization; nothing calls up; the facade `fa` orchestrates cross-layer workflows. `deny.toml` + `scripts/check-forbidden-deps.sh` + `franken-stack.lock` enforce the closed universe. Durable run state rides the substrate's commit stream — never an external database.
- Builds go through `rch` (see below); never hardcode a `/tmp` `CARGO_TARGET_DIR` (suite rule).

---

## Mandatory Checks After Substantive Changes

```bash
bash scripts/check.sh                   # the whole chain, including the non-Rust gates (G0 deliverable)
```

**Tier 0, before anything lands on main (fa-1qk0):** `bash scripts/tier0.sh` (`cargo fmt --all --check` plus `cargo check --workspace --all-targets`; exits 0 only on `tier0 PASS`). It proves the tree compiles and is formatted, nothing about tests. An agent without a Rust toolchain dispatches `.github/workflows/tier0.yml` (manual dispatch) on its train branch and lands only on success; "UNRUN" means do not land yet, never land anyway.

or, run piecemeal:

```bash
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
ubs $(git diff --name-only)
```

If any check fails, fix root causes before handing off.

**The piecemeal list does not cover a change that is not Rust.** Every `cargo` step is a no-op on anything but `.rs`, and `ubs` prints `no supported languages detected … nothing was checked (this is NOT a pass)` and **exits 0** on a `.toml`, `.sh`, `.jsonl`, or `.md` file. `scripts/check.sh` (a G0 deliverable, modeled on FrankenGraphDB's) covers it with shell lint, registry validation (`tools/registry-check`), the claims lint, the parity gate (`verbs.toml` vs CLI vs MCP), the robot-schema fixture pin, and the forbidden-deps check. It does **not** yet run a file-coverage closure (every tracked file claimed by a gate or declared exempt with a reason), a README/AGENTS sync check, `br dep cycles` or a tree-integrity step; check.sh's STEPS header lists these as never implemented (fa-vz7e), so a green run says nothing about them. So: if you touched anything that is not `.rs`, run `scripts/check.sh`.

### Reading a gate — use the exit code, never a grep

**The exit code is the verdict.** Every gate script exits `0` only when every expected check executed and passed. Read `$?`. Do not decide a gate is green by grepping its output. **Gate drivers and shell wrappers written by agents must capture `rc=$?` immediately after the command (`some_cmd ...; rc=$?`) — never read `$?` after a `$(...)` command substitution (such as `$(date)`), pipeline, or logging helper on the same line, which overwrites `$?` with the subshell's exit status.** Gates share the substrate's verdict contract (`scripts/lib/gate_verdict.sh`, adopted verbatim): the transcript is stdout; every failure emits an anchored `FAIL ` line at column 0; the vocabulary is closed (`PASS`, `FAIL`, `RED`, `UNRUN`); three states, not two — *ran and passed*, *ran and failed*, *did not run* — and only the first is green; exit `0` iff zero `FAIL` and zero `UNRUN` lines were emitted and the gate reached its verdict. Compiling steps require positive completion markers (`Remote command finished: exit=0` plus `Finished` or `>= 1` `test result: ok.` line with a positive passed count) and a matching test-inventory witness (`scripts/gate_evidence_check.sh`); removing a test requires a `Retired-tests:` commit trailer and reducing per-crate negative-test or `assert` counts requires a `Weakened-tests:` commit trailer.

### The `cargo test` gate (green-bar requirement) & Canonical Warm Gate (`fa-u7u`, `fa-aj8`, `fa-xrl`)

`cargo test` is a **hard gate**: it MUST exit `0` before any change is handed off or a bead is closed. **This project does not use GitHub Actions** (suite ruling, 2026-09-03; releases go through the `dsr` self-releaser). `.github/workflows/`, when added, holds the hosted recipe for manual dispatch only; "CI-enforced" means **locally proved**: `bash scripts/local_proof.sh` runs `scripts/check.sh` against the exact committed tree, refuses a dirty worktree, records per-step verdict records and pool warmth in `tools.txt`, and writes a checksum-bound format-v2 manifest (`scripts/local_proof_verify.sh`) binding the verdict to that commit and tree hash (and publishing a git note under `refs/notes/fa-verdict` with `--publish-note`). Split runs across workers unite via `bash scripts/local_proof.sh --resume-from <prior-proof-dir>` only when the prior run was on the exact same tree and toolchain with zero `FAIL` steps, and `bash scripts/crate_verdicts.sh` (`scripts/crate_verdicts.py`) computes per-crate content-addressed input closures and composed Merkle roots so leaf changes reuse proved sibling crates without breaking conservative invalidation on registry edits. `bash scripts/close_bead.sh <id> --manifest <proof-dir> --reason "..."` verifies that the manifest is a stable `pass` whose commit contains the bead's landing commit. **Never gate from a new ad-hoc worktree path (`fa-aj8`):** `rch` target pools are keyed by `(worker, project_path)`, so candidates are checked out into the permanent canonical gate worktree (`/data/projects/franken_accounting-gate`, configured alongside designated workers `hz2` and `vmi1152480` in `scripts/gate_workers.conf`). A green `scripts/check.sh` in a dirty tree is not a verdict.

Beyond the bare gate, **every verification domain in §16 is a permanent gate** — the reference differential, the Beancount/hledger oracle, the crash-point matrix, the admissibility exhaustive test, register verify-by-fold, the parity gate, the Polish Bar regression tests, `fa-verify` of produced bundles, and complexity-witness locks on Lantern procedures. A release may bypass a gate only with a public, expiring waiver recorded in the ledger — and never an invariant checker.

### No toolchain? Push to `staging` or `train/<bead>-<agent>`, never `main` (`fa-u7u`, `fa-qu8v`, `fa-cat`, `fa-7dx`)

**An environment that cannot run the pinned Rust toolchain must push only to `staging` or a merge-train branch `train/<bead>-<agent>`.** `bash scripts/merge_train.sh run` (or `run-batch` for queued `refs/heads/train/*` branches with binary-search bisection on `RED`, `UNRUN` preservation, `--check-claims`, and replayable batch-size decision card `fa:decision-card:merge-train-batch:v1`) is the only path to `main`: it merges in the canonical gate worktree, proves the exact tree with `scripts/local_proof.sh` and `scripts/local_proof_verify.sh`, and fast-forwards `main` only on a verified pass, recording the verdict as a git note under the `merge-train` ref (`bash scripts/merge_train.sh dry-run` prints the canonical gate path, designated workers, and expected pool warmth). Client-side discipline is enforced by `bash scripts/install-hooks.sh` (`scripts/hooks/pre-push` blocks unproved pushes to `main`), `bash scripts/trunk_audit.sh` audits commit history for unproved pushes and claim-before-code compliance, and `bash scripts/stale_claims.sh` warns or clears stale `in_progress` bead claims without recent train branches or landings. In addition, `bash scripts/owner_watch.sh` (`--once`, `--loop`, `--status`, `--self-test`) watches `origin/main` in `/data/projects/franken_accounting-watch`, runs `clippy --keep-going` + `test --no-fail-fast` via `rch`, records `GREEN|RED|UNRUN` notes under `refs/notes/owner-watch`, and automatically files a P0 repair bead with the de-ANSI'd compiler error on any `RED` tip. An honest "UNRUN" paragraph in a commit message is a disclosure, not a verdict.

---

## Testing Policy — the Verification Ladder (plan §16)

This is a design pillar with its own budget, not a QA appendix. From cheapest to strongest:

- **The reference oracle (`fa-reference`).** A deliberately simple, single-threaded, obviously correct implementation of the full accounting semantics (balance law, period law, admissibility, SoD, idempotency, registers as literal folds, bitemporal selectors, supersession netting, two-phase, escrow bounds, laws, statements, naïve procedures, a literal Merkle accumulator) over canonical maps. Compiled for tests only; never shipped; never optimized; dependency-allowlisted to `std` + `fa-types`/`fa-time` + generated registries, with **its own limb arithmetic** (not `fa-money`/`fgdb-bigint`) so a shared arithmetic bug cannot make the differential green. Importing an engine or substrate crate is a CI-rejected boundary violation. **It exists before the first engine line.**
- **Simulation-first (`fa-sim`).** The entire system — Folio, the register maintainer, the expiry sweep, Canon, Lantern, Notary, `fad` with MCP — runs under asupersync's lab runtime and the substrate's lab VFS: virtual time, seeded scheduling, torn writes, bit flips, ENOSPC, fsync lies, crash points at every pipeline barrier, DPOR over post-vs-close, concurrent application, promotion-vs-trunk, restatement-vs-reopen, sweep-vs-manual-void. Every failure is a seed with a crashpack and a replay command.
- **Consistency oracles (in-sim, continuous):** balance law; register-equals-fold; subledger-equals-control; admissibility at commit; SoD on approvals; idempotency stability; supersession acyclicity and exact negation; accumulator consistency; escrow conservation; bitemporal monotonicity; projection-equals-payload; erasure leaves amounts intact.
- **External oracles:** Beancount/hledger/ledger-cli balance differential on every fixture; the TigerBeetle semantic corpus; AICPA ADS and SAF-T round trips; XBRL calculation-linkbase validation; `fa-verify` as the independent verifier of the producer; `fsci_stats` for statistical procedures (test-only).
- **Differential, metamorphic, property:** model-generated intent histories against both engines; fold invariance under commutative reorder; reverse+replace = replace; draft promotion = trunk post; scenario replay = branch; export→import identity; rebuild = maintained; bundle determinism; compaction/retention never change certified results; redaction never changes an amount; calendar generation vs brute force; exhaustive admissibility and refusal-catalog suites.
- **Formal anchors (scoped, honest):** Lean for `Amount` group laws, rounding bounds, allocation conservation, balance-law preservation under supersession, netting, bitemporal visibility, the period state machine, escrow bounds; TLA+ for the close DAG under crashes, the restatement case life cycle, two-phase with expiry, draft promotion against a moving trunk. Every model states its bounds.
- **Fuzzing:** every `fa-formats` reader, the Canon parser/IR, the bundle and certificate decoders, robot-mode request parsers, MCP argument normalizers.
- **The gauntlet** before every release: oracles, differentials, metamorphics, surface parity, the Polish Bar scorecard with fresh-context simulated agents, honest perf vs pinned baselines, a release-readiness scorecard whose every row names its evidence class.

Certificates make **production** results replayable: `fa replay <certificate>` ⇒ byte-identical re-execution (FA-INV-11).

---

## Agent Ergonomics Requirements

AI agents are the primary users. The agent-ergonomics Polish Bar is a **release gate** (G3): first-try success on bare `fa` and `--help`; `--json`/robot mode on every read; `fa capabilities --json` and `fa robot-docs guide|schema|exit-codes|examples` in-tool; the `fa triage`/`fa explain balance`/`fa next`/`fa doctor` mega-commands; the exit-code dictionary (`0` ok, `2` usage, `3` accounting-law or query refusal, `4` environment, `5` foundation/I-O failure, `6` conflict, `7` safety block, `8` verification failure; `1` never; empty results are `0`); every refusal names what failed, where, the law or policy row, and the exact command to run instead (`registries/refusal_catalog.toml`); Levenshtein-1 flag/verb correction and the alias set agents try first; dangerous operations require `--yes` or a `confirm_plan` certificate and always name the safe alternative; byte-deterministic output (canonical ordering, `SOURCE_DATE_EPOCH`); `NO_COLOR`/`CI`/`TERM=dumb`/non-TTY suppress styling and prompts; stdout is data, stderr is diagnostics; no TUI on bare invocation; never silent-fail. Every applied ergonomics change lands a regression test. The MCP server exposes the same verbs (parity gate), with tool docs generated from `verbs.toml` in the Do/Don't/Discovery/Examples/Common-mistakes form, structured errors with `fix_hint` and `suggested_tool_calls`, mistake detectors (floats, instants-for-dates, summary accounts, closed periods, self-approval, placeholders, broadcast scopes), and macros for the workflows agents actually run. The system's own runtime (sessions, capabilities, drafts, close runs, findings, decision cards, access events) is a read-only, access-controlled graph queryable in GQL. Dogfood it.

---

## Session Completion ("Landing the Plane")

Before finishing a work session you MUST:
1. File beads issues for remaining work (anything needing follow-up).
2. Run quality gates (if code changed) — tests, clippy, fmt, `cargo deny`, `ubs`, and `scripts/check.sh` if anything non-Rust changed.
3. Update issue status — close finished work, update in-progress.
4. `bash scripts/br_sync.sh <id> [<id>...]` with the exact bead IDs intended for this landing, then stage the JSONL only after the helper reports that exact set.
5. Hand off — summarize what changed, gates run + results, remaining risks/gaps, concrete next steps.

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer for agents to coordinate via MCP tools/resources: identities, inbox/outbox, searchable threads, advisory file reservations with human-auditable Git artifacts.

- **Register identity:** `ensure_project(project_key=<abs-path>)` → `register_agent(project_key, program, model)`.
- **Reserve files before editing:** `file_reservation_paths(project_key, agent_name, ["crates/fa-journal/**"], ttl_seconds=3600, exclusive=true, reason="fa-###")`.
- **Communicate with threads:** `send_message(..., thread_id="fa-###")`, `fetch_inbox`, `acknowledge_message`.
- **Prefer macros:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`.
- Common pitfalls: `"from_agent not registered"` → `register_agent` in the right `project_key` first; `"FILE_RESERVATION_CONFLICT"` → adjust patterns / wait / use non-exclusive.
- **Never** run `am service restart|stop`, `am doctor fix|repair|reconstruct`, or kill an `am` process (suite rule). If `am` is unreachable, retry once, then proceed without it.

---

## Beads (br) — Dependency-Aware Issue Tracking

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`). Issues live in `.beads/` and are tracked in git. **`br` is non-invasive — it NEVER runs git.** Issue prefix is `fa`.

```bash
br ready                 # issues ready to work (no blockers)
br list --status=open
br show <id>             # full detail with dependencies
br create --title="..." --type=task|bug|feature|epic --priority=2   # 0=critical..4=backlog (NUMBERS)
br update <id> --status=in_progress
br close <id> [<id2> ...] [--reason "..."]
br dep add <issue> <depends-on>
br sync --flush-only     # export to JSONL at session completion (until scripts/br_sync.sh exists)
```

Conventions: use the bead ID (e.g. `fa-123`) as the Agent-Mail `thread_id` and prefix subjects with `[fa-123]`; put the issue ID in the file-reservation `reason`; include `fa-###` in commit messages. Map beads to workstreams (W1 Bedrock … W10 Verification) and gates (G0–G4) from §19. The plan is converted to beads only after its review rounds reach steady-state; beads without dependency edges are a conversion bug.

---

## bv — Graph-Aware Triage

`bv` computes PageRank/betweenness/critical-path/cycles over `.beads/`. **Use ONLY `--robot-*` flags — bare `bv` launches a blocking TUI.** Start with `bv --robot-triage` (counts + top picks + quick wins + blockers). `bv --robot-plan` for parallel tracks; `bv --robot-insights` for full metrics (check `.Cycles` — must be empty).

---

## UBS — Ultimate Bug Scanner

`ubs <changed-files>` before every commit. Exit 0 = safe; exit >0 = fix & re-run.

```bash
ubs file.rs file2.rs                    # specific files (< 1s)
ubs $(git diff --name-only --cached)    # staged files — before commit
ubs --only=rust,toml crates/            # language filter
```
Parse `file:line:col` → location, 💡 → suggested fix. Fix root cause, not symptom. Critical (always fix): memory safety, UB, data races. Important: unwrap panics, resource leaks, overflow — and in this codebase an unchecked `i128` operation on an amount is a **critical** finding.

---

## RCH — Remote Compilation Helper

RCH offloads `cargo build/test/clippy` to remote workers to avoid local compilation storms. Installed at `~/.local/bin/rch`, hooked into Claude Code's PreToolUse — usually transparent. Manual: `rch exec -- cargo build --release`. Health: `rch doctor`, `rch status`. The canonical cargo shim is fail-closed; do not invoke cargo by absolute path. **Codex/GPT users:** no auto-hook — manually `rch exec -- <cmd>` for heavy builds. When the shim refuses, registered gates report **UNRUN (retryable), never FAIL** — an offloader refusal is not a product regression. Read `$?`, not grep.

---

## ast-grep vs ripgrep vs warp_grep

- **`ast-grep`** when structure matters (refactors/codemods, policy checks, safe rewrites): `ast-grep run -l Rust -p '$X.unwrap()'`; `ast-grep run -l Rust -p '$A as f64'` is the float-in-amount-path hunt.
- **`ripgrep`** for raw text/literal hunts and pre-filtering: `rg -n 'FA-INV-' registries/`.
- **`mcp__morph-mcp__warp_grep`** for exploratory "how does X work?" — an AI agent expands the query, reads files, returns line ranges with context. Don't use it to find a known symbol (use `rg`); don't use `rg` to understand architecture (use `warp_grep`).

---

## cass — Cross-Agent Session Search

`cass` indexes prior agent conversations so we can reuse solved problems. **Never run bare `cass` (TUI)** — always `--robot` or `--json`.

```bash
cass search "period law ssi witness" --robot --limit 5
cass view /path/to/session.jsonl -n 42 --json
```
stdout is data-only, stderr diagnostics, exit 0 = success. Treat it as a way to avoid re-solving problems other agents already handled (this project's kickoff research — the FrankenGraphDB study, the TigerBeetle data-model review, the foundation crate survey — lives there).

---

## Note for Codex/GPT agents — unexpected working-tree changes

If `git status` shows edits you did not make (in `Cargo.toml`, `crates/**/*.rs`, `registries/**`, etc.), those are from the **other agents working on this project concurrently** — a normal, frequent occurrence. **NEVER** stash, revert, or overwrite another agent's work. Treat those changes exactly as if you made them yourself. Do not stop to ask about them.

---

## Note on Built-in TODO Functionality

If I explicitly ask you to use your built-in TODO functionality, do so without complaining that you need to use beads. Always comply with such orders.

For any web requests you must make with curl or otherwise, identify yourself honestly: use a User-Agent that names this project, e.g. "franken_accounting-agent (+https://github.com/Dicklesworthstone/franken_accounting)". Never borrow another product's or company's crawler or client User-Agent, and never spoof a client to get past a block.
