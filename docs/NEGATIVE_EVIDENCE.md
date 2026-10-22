# Observed defects and repairs

This record is required by the engineering doctrine. It names observed
counterexamples and the code that prevents their recurrence; it is not a
release certificate.

## 2026-10-10 — fa-pri / fa-p7r arithmetic review

- **Native imbalance absorbed as valuation rounding.** The former
  `value_legs` code admitted a residual of one even with no converted legs
  (`bound.max(1)`). Thus `Dr USD 1 / Cr USD 2` could become base valuations
  `2 / 2`. This is a helper-level violation of the exact pre-rounding balance
  premise; no claim is made that a committed journal entry bypassed the
  posting kernel. The helper now checks exact balance per native unit before
  conversion. `native_imbalance_is_never_absorbed_as_rounding` covers both
  base and foreign inputs, all nine laws, and balanced positive controls.
- **Wrong residual bound for directed rounding.** Five debit legs of one EUR
  minor unit and a credit of five at `99/100`, with `Floor`, produce base
  totals `0 / 4`. The former half-law bound rejected this lawful residual.
  The helper now uses the selected law's bound; the regression requires the
  four-unit adjustment on the lowest-ordinal tied leg without adding a leg.
- **Resource admission in the initial integration was incomplete.** Review
  found byte-to-limb allocation undercharging and different encode/decode
  size policies in the unlanded accounting codec. It now admits rounded
  coefficient storage and shares the caller's frame policy. Review also
  found uncharged native output repacking in pinned FrankenSymPy addition
  and division. The upstream repair is
  `bd1ad68a3a06e0a0ed6ee4a9bc76d85dc9e67e2e`; arithmetic pins change together
  with the caller tests. Full CAS verification is separate from accounting's
  numeric-consumer verification.
- **Reference dependency leak.** Before the registry split,
  `fa-reference -> fa-registry -> fa-money` pulled production arithmetic into
  the reference's normal closure. Registry unit rows are now plain data;
  executable unit/law binding lives in `fa-money`. The resolved dependency
  gate refuses a path from the oracle to production arithmetic.

The corresponding regression and full-gate execution results belong to the
exact landing revision in Beads (`fa-pri`); source inspection alone is not a
passing test. Journaled unit evolution and full FX posting laws remain open
under `fa-p7r`.

## 2026-10-11 — fa-p7r valuation boundaries

- **A native base-unit leg absorbed a foreign rounding residual.** USD
  `Dr 100 / Cr 100` together with EUR `Dr 1, Dr 1 / Cr 2` at `1/2`
  under `HalfUp` produced raw base totals `102 / 101`. The former helper
  selected the largest deficient credit, changing the native USD credit
  from 100 to 101. The residual recipient is now restricted to converted
  legs, retaining largest-value selection and lowest-ordinal tie-breaking.
  The old-code regression failed with actual 101 versus expected 100;
  the repaired money suite passed 49 tests, including all nine rounding
  laws and both side orientations. This is helper-level evidence; it does
  not claim that functional-currency postings are implemented.
- **Unchecked entry-level FX totals escaped the posting guard.** The kernel
  refused `leg.base_amount` but did not inspect `base_totals`. Structural
  validation checked the aggregate's reference ordering and residual
  ordinal, without enforcing its law, rates or claimed sums. The posting
  kernel now refuses that unsupported aggregate before storage observation.
  The regression includes balanced, imbalanced and negative claims, checks
  an unchanged frontier, then posts a valid native entry with the same key.
  Previously admitted unsupported aggregates are also refused on retry;
  the fix does not rewrite their journal objects.
- **Control publications could carry valuations without legs.** Independent
  review found that policy activation and migration run controls seal
  caller-supplied proposals without passing through the monetary posting
  guard. Their admission checks now reject `base_totals`, because those
  controls have no monetary legs to value. Generated controls already set
  it to `None`. Regression tests require typed refusals without advancing
  the journal or lifecycle state, alongside ordinary positive operations.
  These are publication guards: the durable decoder and digest golden
  vectors are unchanged, so historical journal bytes remain inspectable.

The old-code regression at `86c6ec3` admitted unchecked base totals and failed
its refusal assertion. The corrected `827f757` passed the 247-test combined
`fa`, `fa-journal`, `fa-registers` and `fa-money` run, including the control
publication cases. The final integration gate remains pending on `fa-p7r`;
these admission checks do not implement the full journal FX-law contract.

## 2026-10-11 — fa-syy approval binding after balancing

The posting kernel checked approvals against requested legs before resolving
the balancing extension. With a requested expense of 100 and an account cap
of 40, the sealed proposal could contain 40 while its recorded approval still
named the proposal for 100. Reconstructing the original request for an
idempotent retry does not change the committed proposal's digest contract.

For balancing, the repair resolves the actual legs before checking approvals.
It then binds each cited digest to that complete proposal before reading the
approval record and checking identity, book, policy epoch and segregation of
duties. All these witnesses remain in the same posting transaction, before
anything is staged. The request extension remains part of the approved
proposal and retry identity. Other posting classes retain their existing
check order; balancing account and limit refusals now precede approval errors.

An initial private repair instead authenticated a caller-selected common
approval digest early, then checked it against the resolved proposal. Review
rejected that approach: it could expose existence, epoch or SoD information
about an unrelated approval before refusing the post. It was replaced before
runtime submission or landing. The additional regression distinguishes both
a real foreign self-approval and a missing foreign approval from a correctly
bound approval, and preserves the unlimited-account positive path.

The regression uses a real capped account, a Closed-period Adjusting entry
and a separately recorded Human approval. It pairs refusal of the old amount
and changed effective date with a successful posting of approved resolved
effects and an identical-request retry. The old-code run at `86c6ec3` failed
the resolved-approval assertion; its foreign-approval observation control
passed. The corrected regression passed in the 247-test run at `827f757`.
The final integration gate remains pending on `fa-syy`.

## 2026-10-11 — fa-e00 finalized historical detail in balance proofs

The joined FullDetail implementation excludes pre-opening detail already
summarized by Opening chunks. Notary's v1 balance proof only checked for a
Finalize leaf and then counted every selected migration chunk. Producer and
independent verifier could therefore agree with one another while disagreeing
with the register. In the new prior-year fixture, a 300-unit rent debit
appears in both historical detail and its Opening summary: the register
counts 300, while the unguarded proof would count 600. This is a
source-derived counterexample; runtime reproduction is pending.

The interim repair derives visibility only from journal OPEN and Finalize
records and refuses selected migration history dated before OPEN. OPEN binds
the opening date but does not embed the run body, so v1 cannot distinguish
summarized history from legitimate sole-source history before that date.
Both conservatively refuse with an explicit diagnostic. Inclusion proofs
and finalized chunks on or after that date retain their semantics. Missing,
duplicate or contradictory migration records fail closed. Full support
needs authenticated run-mode and sole-source metadata as well as Finalize
witnesses in the proof format; fa-e00 remains open.

An initial private repair (29ded4c) used the run's mutable state projection
and unauthenticated body to authorize proofs. Review rejected it: a false
Finalized projection or changed sole-source flag must not authorize a
balance proof. The replacement uses journal leaves alone. Review also found
that its first planted-state test was masked by a separate pre-opening
chunk. The corrected test plants false finalization while only the Opening
chunk is staged, then restores state, stages history and finalizes for real.
The new regressions and final integration gate have not executed yet.

## 2026-10-11 — fa-vn4 surface fixture corrections

The first CLI run at `069e608` passed 24 tests and failed two fixture checks.
The new fiscal-year advance test incorrectly assumed only twelve normal
periods. The calendar also creates Opening, Closing and Adjustment periods;
the existing CLI selector includes all fifteen, sorted by code. The corrected
fixture admits that existing behavior: five successful publications before
the damaged March refusal, then all fifteen periods on the repaired retry.
It still rejects missing, extra or reordered output, wrong refusal coordinates,
publication by the failed period, and duplicate writes on any already
maintained period. No production selector or register law changed.

The existing event-coverage workflow also lacked an invocation of the new
command. It now advances its genuinely stale register and independently
verifies the result; its exact declared-versus-emitted event comparison stays
unchanged. The same run's real MCP test passed, including byte-identical CLI
and MCP no-op data. The compiled schema was compared before editing its pin:
exactly `registers_advanced` was added (34 events to 35); every old event,
ordering, shape and envelope field was unchanged. The corrected Rust fixtures
and final integration gate still require execution.

## 2026-10-12 — RECON catch-up: certificate row capacity and the MCP error contract

- **Retained certificates outgrew one substrate row.** A comparative statement
  certificate with later and backdated postings is 17,205 encoded bytes, and the
  pinned substrate refuses a vertex row above 16,384, so main's own retention
  test failed on the first gate that ran it. Certificates whose payload scalar
  exceeds 12 KiB encoded are now retained through the book's content-addressed
  blob store under the certificate digest, with a versioned descriptor as the
  vertex payload; small certificates are stored as before, an exact retry
  compares canonical bytes rather than a recomputed placement, and a missing or
  changed blob is refused, never substituted. Regressions cover a directory
  book's reopen, missing and damaged blobs, and a historical inline record above
  the new bound.
- **Resource refusals lost their structured data, and the first repair weakened
  the test.** The stdio end-to-end client negotiated the legacy 2024 era by
  sending `initialize`; the pinned framework's legacy adapter forwards only the
  code and message of a handler error, so `error.data` with the launch
  authority never reached the client. The first attempted repair (909cf25)
  replaced the structured assertion with a message check; it was withdrawn on
  review as a gate weakening (e53572b restored the assertion byte for byte).
  The repair moves the server and the test client to MCP 2026-07-28
  (`server/discover`, per-request `_meta`), refuses legacy `initialize`, and
  keeps the structured assertions. That tree landed as part of 538af18 on
  2026-10-12 with the complete gate green (run 3 on hz4, 772 tests).
- **Host-path refusals vanished behind the modern router's schema refusal,
  and the first repair narrowed the proof.** After the move to MCP
  2026-07-28 the framework validates tool arguments against the declared
  schema before the handler runs, so an agent that sent a host path alone on
  a tool with a required inline property (`plan`, `certificate`) received the
  generic "Tool arguments do not match the declared input schema." instead of
  the promised structured `forbidden_path` refusal (two stdio tests on the
  3e02da1 gate). Repair 24 (fc97b75) first made those calls schema-valid,
  which proved the refusal only for well-formed calls and no longer exercised
  the ordinary mistake; review caught it. Repair 25 keeps both: an
  `on_response` middleware enriches exactly the router's generic refusal
  content for a registered tool call with the same authority-first,
  path-second structured refusal the handler applies, with the launch
  authority attached, while requests, schemas and admission stay untouched
  and ordinary missing required inputs keep the generic error. The landing
  gate on that tree (538af18, run 3 on hz4) passed every step with 772
  tests green and reached origin/staging at 16:39:42Z on 2026-10-12.

## 2026-10-11 — Reality-check security and threat-model findings (`fa-oaz`)

The 2026-10-11 codebase reality audit identified five security, provenance, and
verification gaps between the plan's threat model (§14.1, §8.5) and the surface
posture at the time, each tracked by an explicit repair bead and cross-referenced
in `registries/threat_model.toml` and `docs/THREAT_AND_TRUST_MODEL.md`:

- **Unbound MCP session authority vs. launch-bound session config (`fa-23r`, closed).**
  Early MCP tool handlers accepted caller-selected capability grants per tool call
  rather than binding the session principal, profile (`Profile::Agent`), and
  permitted operations at `fa-mcp` server launch. Repaired in `fa-23r`:
  `ServerConfig` binds the session authority at startup and rejects per-request
  privilege escalation (`FA-THR-03`, `TB-04`).
- **Local CLI embedded capabilities (`--as` / `--grant`) without cryptographic token
  verification (`fa-v62`, `fa-r3q` — EP-AUTH, open residual risk on `FA-THR-04`).**
  Outside launch-bound `fa-mcp` / `fad` sessions, the local CLI constructs
  `Capability::embedded` from command-line flags. `threat_model.toml` records this
  explicitly under `FA-THR-04.residual_risk` until journaled cryptographic capability
  issuance, attenuation, and verification (`fa-v62`, `fa-r3q`) replace embedded CLI
  grants.
- **Unverified caller-supplied `base_totals`, `plan_certificate`, and non-`Intent`
  `EntryOrigin` on public `post` (`fa-cw1`, closed; `FA-INV-05.registered-origin`).**
  Public `post` previously accepted caller-supplied `EntryOrigin::Rule|Sweep|Schedule|Control`
  and unverified `base_totals`. Repaired in `fa-cw1`: public `post` admits only
  `EntryOrigin::Intent`, refuses caller-supplied `base_totals` or unverified plan
  certificates before publication without consuming identity (`FA-REF-100`,
  `FA-REF-101`), and requires sweep/schedule/control entries to enter through their
  dedicated kernel minting paths.
- **Invariant checker-strength inflation (`fa-rez`).**
  Several live clauses in `registries/invariants.toml` reused a positive differential
  test in `negatives` (e.g., `FA-INV-04.open-amount` and `FA-INV-08.unsettle` both
  citing `kernel_and_oracle_agree_on_a_generated_history` as their negative) or did
  not distinguish unit assertions from differential/exhaustive/negative-fixture
  checkers. Tracked and repaired under `fa-rez`.
- **Untrusted document/memo content in agent-facing JSON/MCP responses (`fa-9rw`).**
  Imported document bytes, external descriptions, and party fields returned to AI
  agents over `--json` and `fa-mcp` lacked explicit untrusted-data boundary markers
  to defend against indirect prompt injection (`FA-THR-03`). Tracked and repaired
  under `fa-9rw`.


## 2026-10-20 — Reality check: fabricated verification evidence (`fa-hlnd`)

- **§17 performance evidence was hand-entered (`fa-e75k`).** All 20
  `registries/slo.toml` rows were `activated = true` over `bench/manifests`
  baselines typed by hand: a 10M-leg register rebuild at p50 2.8 ms, a
  20-entity × 2M-entry consolidation at 3.1 ms, a 24 h endurance run at
  3.4 ms. The benches under those names timed corpus generation or a kernel
  witness; the incumbent was the same closure run twice;
  `validate_comparison(&manifest.worker_class, true)` compared the manifest
  with itself; bytes per leg was the constant 284. Withdrawn: every row is
  `activated = false`, the baselines are removed, `fa-bench` reports every
  §17 benchmark as `bench_unmeasured`, and an activated row whose manifest
  has no measured `[baseline]` is refused
  (`activated_slo_row_without_measured_baseline_is_refused`). Real
  measurement is `fa-ykbp`.
- **Formal evidence was asserted, not checked (`fa-2lsv`).** `FA-INV-06.proofs`
  was live at evidence class `proof` on a text search for `sorry`; no Lean
  file is compiled anywhere in the gate. Its negative test exercised a
  `verify_olean_and_fln_gate` that returned `Pass { declarations_checked:
  23 }` for any bytes starting with `olean`, and `Pass` whenever two paths
  existed, without running either tool. The theorems themselves are thin
  (`largestRemainder_conserves_total` proves `baseSum + (total - baseSum) =
  total`; `RoundingLaws.lean` proves no law meets its bound). The fake
  verifier is removed, the clause is dormant until `fa-09q8` compiles real
  proofs, and the TLA+ test is renamed to say what it checks (a spec
  declaration and a Rust model of one spec; TLC is `fa-dj6j`).
- **External-oracle agreement was claimed, not computed (`fa-kkxl`).**
  `probe_external_oracle_binary` returned `Verified { cells_checked: 0 }`
  when `bean-check --version` or `hledger --version` succeeded; neither tool
  evaluated a journal. `docs/conformance/beancount.md` claimed "exact
  per-account balance agreement across FrankenAccounting, Beancount v3, and
  hledger" from a matrix whose `observed` column was a string literal typed
  equal to `expected`. The TigerBeetle "corpus" runs an in-house simulator,
  not the posting kernel; the ADS, SAF-T and XBRL rows were round trips
  through this project's own readers and a hand-written linkbase. Now the
  probe reports `Present`, never a verification; the Beancount/hledger rows
  are computed from the actual self round-trip; the three conformance
  documents, the format summaries and the crate description say what ran.
  The real differentials are `fa-sa4w`, `fa-w3n6` and `fa-ipom`.

## 2026-10-21 — Signed solvency basis (`fa-8j3g`, partial)

The retained binary probe in
`/private/tmp/fa-reality-check-20261021.d9HmEI` posted equipment 100 against
payables 50 and equity 50, followed by expense 80 against accumulated
depreciation 80, using the shipped US GAAP chart. The trial balance showed
signed assets 20 and liabilities 50; `solvency.balance_sheet_test` returned
zero findings. This is evidence about the identified older binary, not an
exact-tree gate. Source inspection found the same defect: clamping each
asset account's debit-minus-credit net at zero discarded credit
contra-assets. Debit contra-liabilities were likewise discarded. Ordinary
historical `RegisterEquals` claims could also replace the current balance,
although they are reconciliation assertions without valuation authority.

A second older-binary probe independently reproduced that substitution.
Funding cash 100 against debt 50 and equity 50, then spending cash 80,
produced the correct 30 deficit. Recording a genuine `RegisterEquals` for
cash at the funding sequence made the finding disappear, while the trial
balance still showed cash 20 and debt 50. Both the recording and subsequent
native assertion check returned `holds=true`. The binary SHA256 is
`5da52e3660586a140482405a9fa99e6267fb3c23477e5fcf691a1d3e50786078`;
commands, outputs and the synthetic book are retained under
`/Users/jemanuel/.codex/artifacts/fa-solvency-20261021/historical-assertion-x8q6s1mb`.
The initial attempt correctly refused summary account 1000; the completed
probe uses template leaf 1010 and preserves the refusal transcript.

Method version 2 folds signed native assets and credit-minus-debit
liabilities per unit, then applies the declared haircut once to a positive
net asset basis with exact truncation. Negative assets stay negative.
Reconciliation assertions do not override either side. The certificate
allowlist moves with the method version; unsupported v1 methods refuse
rather than silently replaying with v2 semantics. Findings cite every
contributing account and entry or refuse an oversized scope, and their
population counts only the reported unit's asset/liability legs.

Regressions cover the literal 30 deficit, historical/effective selection,
ordinary assertions through separate native and CLI cases, haircut netting,
currency isolation, negative bases,
overflow, citation capacity, the template chart through the real CLI, and
versioned certification/replay. At the time of this entry, execution is
UNRUN: strict remote admission timed out behind an occupied worker; no
local fallback ran. Test results and exact source identity belong in the
bead when execution completes. Typed, evidenced valuation adjustments
remain unimplemented in this same open bead; this repair is a book-basis
screen and does not establish fair value or a legal solvency conclusion.

Update 2026-10-22: the focused Rust run exited 0 with seven tests passed
(one facade certificate case, two real CLI cases and four Lantern cases).
The authenticated historical assertion, signed basis and temporal controls,
numeric/citation boundaries, method-version refusal and retained replay all
executed. The RCH receipt binds base `1b1c1853` and test overlays to tree
`b53fcc8752d4a8f8853269e434c2274f22e28cd2`; the complete transcript is
`/Volumes/trj-data/projects/franken_accounting-verification-output/solvency-rooted-20261022.log`.
This is focused development evidence. Shared main advanced to `324eeec4`
during that run and needs its own verification; neither the canonical full
gate nor typed documented valuations are complete.

## 2026-10-22 — Aggregate plans rebased across report metadata (`fa-r19j`, open)

The identified older CLI binary (SHA256
`5da52e3660586a140482405a9fa99e6267fb3c23477e5fcf691a1d3e50786078`)
prepared a native fiscal-year Closing plan at sequence 11 in a fresh
synthetic book. A real `tb --certify` retained a report certificate at
sequence 12. The unchanged close plan then committed at sequence 13 with
the original plan certificate digest. This violates plan §5.10's exact
aggregate-prefix rule even though the report metadata changes no amount.
Commands, outputs and the synthetic book are retained at
`/Users/jemanuel/.codex/artifacts/fa-solvency-20261021/older-aggregate-plan-8sgsdvtd/result.json`.
This proves behavior of that older binary, not current-source acceptance.

Source inspection found that portable plan publication and retained-outcome
recognition both used the point-plan metadata tolerance for aggregate
Closing and source-bound Revaluation entries. The drafted repair applies
the shared aggregate-basis law to those families, preserving point-only
metadata tolerance and judging exact retries at their original publication
coordinate. Native and real-CLI regressions require stale refusal without
publication, fresh-plan success and later exact retry. The direct substrate
test also includes both publication orders and an actually published
guard-bypassed control.

The first five-package Rust run was cancelled by RCH's stuck detector during
pinned `fgdb` compilation (job `30075807208571128`, daemon history exit 130,
local shell 143), before any test result or remote completion marker. Later
strict development runs establish the following narrower results:

- At exact `95c6239d`, all 13 substrate and 146 journal `genesis` tests pass,
  including metadata invalidation, point-plan/exact-retry controls, both
  aggregate publication orders and a guard-bypassed stale native publication.
- At exact original `522f2979`, the one metadata regression fails because
  the stale Closing actually commits at sequence 12. Its expected-failure
  run exits 101; it is not a normal green test run.
- The registered dependency-class slice and foundation-probe registration
  pass 75 registry/validator tests and scoped clippy at `ae2f8622` plus the
  recorded foundation-ledger overlay. The hash-checked prebuilt substrate
  inversion runs its actual selected test and fails as expected.

Logs are retained under
`/Volumes/trj-data/projects/franken_accounting-verification-output/` as
`aggregate-native-positive-95c6239d.log`,
`portable-negative-warm-522f2979.log`,
`aggregate-registry-ae2f8622.log`, and
`aggregate-inversion-artifact-one-thread-95c6239d.log`. These are distinct
source cuts and development evidence, not one composed canonical verdict.
The CLI request at `95c6239d` timed out in admission with exit 103 and ran
zero tests; the later export call repair at `1f98e137` still needs its CLI
run. Full original acceptance and the canonical complete gate remain open.

## 2026-10-22 — Circular-flow search charged only after completion (`fa-1tvm`, open)

At `1f98e137`, the ordinary procedure meter already enforces runtime work
budgets and cancellation during charges. However, `graph.round_trips` with
`max_hops > 2` calls `cycles::find` to completion and only then charges its
search steps. The recursive search enforces its separate maximum-search
bound, but cannot observe the caller's smaller work budget or cancellation
while traversing a root's continuations. This is a source-observed breach
of doctrine 3, not a newly executed runtime result.

The repair passes a fallible checkpoint callback into each actual root and
recursive-edge charge. The adapter supplies the existing procedure meter
and propagates its original refusal; it no longer charges the same work
again afterward. The search receives no time, entropy, filesystem or
network handle. Existing motif and independent exhaustive-subset oracle
cases remain, with new actual-meter recursion interruption tests and a
native three-transfer corpus. A real CLI regression requires budget seven
to refuse at the eighth charge, no partial findings or head change, and
identical complete findings/work under sufficient and unrestricted budgets.
These new tests are drafted and runtime verification is still UNRUN. No
claim is made about every procedure, snapshot-acquisition cancellation,
full stripped-context acceptance, or the complete canonical gate.

The same source also lacks a cancellation check at run entry and completion:
an empty native procedure never charges the meter, and cancellation arriving
after the last periodic check can leave a short procedure returning findings.
The runner now checks those boundaries without inventing charged work. A
retained first refusal still wins if the procedure swallowed an earlier
budget error. Additional regressions require an already-cancelled empty
native `jet.weekend` run to refuse at zero work, an uncancelled empty run to
complete at zero work, and late cancellation to withhold the result while
preserving any preceding budget refusal. These are source changes and
unexecuted regression requirements; both the original-code request and the
complete selected positive request on this resume timed out in RCH admission
with exit 103 and executed zero tests. No runtime gate passed in this block.
