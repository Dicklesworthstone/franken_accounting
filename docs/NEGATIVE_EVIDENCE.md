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

Snapshot acquisition is another source-observed gap at `7f215518`: it takes
no context while reading and decoding the book, and the direct `run` API
also drops the caller's cancellation source. The follow-on draft requires
`QueryCx` for both entry points, checks before selecting a storage prefix,
between bulk reads, during entry/approval/vertex decoding, and before returning
the snapshot, and carries that same context into the procedure meter. The
facade, certification/replay paths and native corpus callers pass their
existing query context. Procedures still receive only the meter. Runtime
context negatives and uncancelled digest/work controls are added but UNRUN.
Bulk storage reads, sorts, hashing and role/open-item folds remain indivisible
at this boundary; this is not a claim of bounded cancellation throughout
snapshot acquisition or completion of `fa-1tvm`.

Formatting and whitespace checks pass for this draft. The ten-file static
scan exits 1 with one critical report and 1,149 warnings. Its critical is the
unchanged `panic!("fresh late entry must commit")` in the bank-reconciliation
test helper, also present at `7f215518`; the assertion and scanner are retained.
This is a red static verdict, not a passing gate. Rust tests, clippy and the
complete exact-tree gate remain UNRUN: the only disk-qualified Linux worker
reports critical memory pressure even while its local slot is free. No
pressure threshold, worker cap or acceptance criterion is weakened.

## 2026-10-23 — Admitted runtime results and chart retry contract (`fa-1tvm`, `fa-r19j`, `fa-kxc4`, open)

The newly configured `trj` worker admits the strict development run after
source and native build-filesystem SBH checks pass. At `5492f2c6` plus
overlay `97b0afe805d2405fce7390732b29b8009b106fa9be67f0b29ab0cfe37f842a7a`,
the complete requested `fa`, `fa-cli`, `fa-gen`, and `fa-lantern` test run
exits 101: 1,308 passed, eight failed, none ignored. All eight meter/context
regressions, nine cycle unit cases, real CLI circular-flow budget refusal,
saved-close invalidation after report certification, and saved-FX-review/plan
invalidation after a later invoice pass by name. These replace UNRUN only
for those cases at this source cut; the four-package verdict is RED.

The failures expose four fixture/consumer mismatches and a real kernel gap:
Unix socket fixtures exceed `sun_path` under long RCH `TMPDIR`; `tru 0.1.1`
serializes integer JSON values as `6.0`; the bound-operation matrix supplies
the forbidden global `--yes` flag before it can test missing operations;
and the positive catalog fixture omits the journaled roles its procedures
require. The chart-role CLI test also expects an exact chart retry to return
its recorded outcome, whereas an older template test expects that same retry
to refuse. `install_chart` has no recorded-outcome branch and stages live
identities again, violating the normative idempotency contract in plan §5.9.

The fixture repairs retain the assertions they were meant to reach. Socket
probes use short retained unique directories with an explicit portable length
bound. The external reference adapter strips only an exact `.0` numeric suffix
outside strings, without floating arithmetic; fractional/exponent/overflow,
malformed-number and wrong-integer controls still refuse or compare unequal,
and the production JSON reader still refuses `6.0`. Real native role controls
populate the positive catalog, with a missing-role/unchanged-head negative
beforehand. The operation matrix keeps every operation check and separately
requires `--yes` to refuse without changing the head.

The chart repair recognizes an existing journal entry only after current
authorization and SoD checks, compares the canonical or decrypted semantic
request identity, and returns the original `ChartInstalled` without writing.
New controls require a nonce-independent exact retry after a role control,
same-key changed account/reason conflict, new-key duplicate refusal, and
unauthorized retry refusal, all with unchanged head. The template gate's
win/lose split is explicit: an exact retry now passes with the original
identity and birth; a distinct request over existing accounts still refuses.
The old exact-retry refusal assertion was inconsistent with plan §5.9; no
plan, threshold, refusal policy, or format is weakened to preserve it.

The first fixture-only rerun at `bb5a0485` plus its four recorded overlays
exits 101 with 112 passed and one failed: the four socket cases, TOON
differential and new reference-adapter controls pass, while the chart retry
still fails. The combined kernel/catalog/matrix run then passes 577 tests
with remote and client exits zero at `bb5a0485` plus overlay fingerprint
`06e89c5c171bb20c0634805845c5c6737de0e9aff122ee64af34d95a5b0be987`.
Workspace all-target Clippy first refuses a manual-range assertion in the
recursive cancellation test. Its equivalent inclusive-range form passes
Clippy with warnings denied, nine cycle tests, and 75 registry/validator
tests at the same base plus final overlay fingerprint
`9e7a6a0134931e9b59d7328b71ad5ec2ab41fb3cd706f8db98bdee3dc2e1f8d3`.
The RCH receipt's `tree=fef081eed09666df4fa6b97188cf5f1ed1b06830`
is the baseline commit's tree, not the composed overlay tree. The source
identity here is the named base plus overlay fingerprint and retained patch;
the baseline tree alone cannot qualify the repair.

The original circular-flow native regression also executes at exact
`1f98e137` with only its frozen test-file overlay: one test runs and fails,
remote/client 101, because budget seven is reported at eleven work units
after the search, rather than being interrupted at eight. The same named
native case and its real CLI counterpart pass in the repaired candidate.
This is an actual expected-failure control, not a queue timeout or a passing
ordinary test run. Its log is
`cycle-original-native-negative-1f98e137-20261023.log`.

Logs are `snapshot-aggregate-positive-5492f2c6-20261023.log`,
`cli-fixture-repairs-bb5a0485-20261023.log`, and
`admitted-repairs-bb5a0485-20261023.log` under the verification-output directory.
Whole static scanning and the complete canonical exact-tree gate remain
unqualified; no Bead is closed from these selected results.

## 2026-10-23 — Network tracing charges the caller after completion (fa-1tvm)

The exact `836009e9` workspace-built CLI, SHA256
`ebc3e3998f9082f947fdfde1dd479476bf6f8e5e483b2d5d40dfcb425c5e65e2`,
reproduces the remaining charge-after-return defect on a separately retained,
explicitly synthetic book. A source100.00USD and transfer80.00USD leave the
literal expected20.00/80.00 under all four network laws. Budget6 is refused
only after520 work units for every law; budget520 is refused after1636 for
FIFO/LIFO,625 for LIBR, and623 for pro rata. Every refusal is one error event,
exit3, and the complete before/after book-info envelopes are unchanged.
The executable was copied and hash-checked before and after the probe, while
the original exact-source workspace campaign retained its own source bytes.
The manifest and all command/stdout/stderr records are retained under
`franken_accounting-verification-output/network-runtime-probe-836009e9-20261023/`.
This is a current compiled CLI counterexample; it is not a passing repaired
Rust test or a canonical gate verdict.

The draft correction charges each projection cell estimate before allocating
its matrix, then forwards the caller's fallible meter to every existing engine
step. It retains the independent `max_*` limits and preserves the original
typed caller refusal without returning a partial report. A successful engine's
reported work must reconcile exactly to the caller's counter delta; it is not
charged a second time. Native regressions require projection refusal at260
with budget6, engine refusal at524 with budget520, unchanged exact-budget
findings/work, all four literal20/80 schedules, and deterministic cancellation
injection. Pure-law controls compare the complete unchanged schedules and work
counts and stop each law at its tenth callback. The repaired runtime results
remain unrun at this checkpoint. Indivisible sorts, arbitrary-precision
arithmetic, bulk storage readers, registered per-procedure budgets, structural
stripped-context admission, and full complexity coverage are still separate
unmet acceptance within the original open fa-1tvm; this callback wiring does
not establish a universal wall-time checkpoint bound.

## 2026-10-23 — Full workspace exposes blocked MCP discovery and daemon fixtures

The complete `cargo test --workspace --all-targets --no-fail-fast` campaign
at exact committed `836009e9`, with no overlays, compiles and terminates
remote/client101:3075passed,31failed,0ignored across197 target summaries.
Nineteen real MCP stdio tests fail at `server/discover`: catalog growth made
the emitted instructions exceed fastmcp0.12.0's unchanged16384-byte protocol
limit. Eleven daemon integration cases fail before their intended assertions
because RCH's private `TMPDIR` makes the real Unix socket path too long. The
remaining failure is a daemon version unit assertion still expecting14 epochs;
the registered stack and its existing registry test require15, including the
`foundations` fingerprint. The transcript is
`workspace-tests-836009e9-rooted-20261023.log` in the verification-output directory.

The MCP correction removes only catalog text duplicated by `tools/list` and
`resources/list`, retaining every cluster description, accounting/authority
rule, workflow macro and resource URI. It registers the same tools/resources
with their full descriptions and validates the constructed server's actual
discovery before returning from `build_server`. The new boundary test enables
all on-demand clusters with a256-byte quoted principal, uses the pinned
protocol validator and checks the retained guidance, names and authority.
No framework cap, schema, accounting admission or existing stdio assertion is
relaxed. The daemon fixture uses short retained `/tmp` roots with a portable
socket-byte bound; actual processes, sockets and event/authority checks stay.
The version check now requires the complete literal15-name epoch inventory,
in addition to the existing foundation pins and digest checks. Its win/lose
split admits the registered foundations fingerprint and still refuses an
omitted, reordered, duplicated or unexpected name; it does not replace the
expected inventory with the implementation's own count.

The shared committer preserves these drafts through `f812bacd`; this agent
does not issue those commits or push them to main. The earlier original-engine
Rust test-only request expires103/queue_timeout with zero tests; the separate
current-CLI network counterexample above remains actually executed. Two
strict-remote network/MCP/daemon attempts against `f812bacd` plus only the
daemon test's rustfmt layout overlay stop before any Cargo output with
`RCH_SCOPED_COMPLETION_UNCONFIRMED` (remote255/client1). Both original durable
wrappers are recovered through `rch jobs recover`, with terminal acknowledgement
and delivery255; recovery's own exit0 is not a test pass. The retry follows
that acknowledgement and a fresh passing source/native disk preflight. The
retained transcripts are
`network-mcp-daemon-repaired-f812bacd-20261023.log` and
`network-mcp-daemon-repaired-retry-f812bacd-20261023.log`.

A subsequent non-compilation launch control refuses source namespace creation
(permission denied, client103); its separate wrapper is also terminally
acknowledged through supported recovery. It uses a different source namespace
and does not reproduce the compilation launcher failure. A read-only native
process-census diagnostic times out at1s with zero captured bytes, then completes
in1.683s with4632 rows under a5s diagnostic bound. The installed launcher's
unchanged1s observation bound could account for the earlier refusals, but the
diagnostic does not prove their sole cause. No observation deadline, admission
policy, worker configuration or peer process is changed. The Mac Data volume
remains disqualified for heavy local work. Three-/four-file static scans
separately exit0 with zero critical findings; neither qualifies the complete
static or canonical exact-tree gate. Repaired runtime execution is UNRUN and
no Bead is closed.

After two fresh native census controls complete within the unchanged1s bound
(0.949s/4704 rows and0.983s/4713 rows), and both mounted source and native disk
preflights pass19.2122% free, one further ordinary request uses the exact
committed review candidate `aab87ea4` with no overlays. It also stops before
Cargo, remote255/client1. Original wrapper
`rchw-1eab1b99-62c2-43b7-94bc-8d5bb16ab7d0` is recovered with delivery255 and
terminal acknowledgement. The transcript is
`network-mcp-daemon-committed-aab87ea4-20261023.log`; recovery is recorded in
`rch-recover-72123-20261023.json`. The positive standalone census controls do
not establish launcher health. All three repaired campaigns are UNRUN. Stop
retries and retain the review train, original acceptance and canonical gate.

## 2026-10-25 — Work-witness evidence schema and unmeasured procedure calibration downgrade (`fa-vtzt`)

The work-witness evidence ledger (`registries/evidence_artifacts.toml` and `evidence/**`)
requires every `calibration = "corpus"` or `"planted"` procedure in
`registries/procedures.toml` to cite a `calibration` artifact carrying
per-procedure TP/FP/FN/TN confusion counts (`TP + FN >= 1`). Only the 12
procedures measured in `registries/lantern_calibration.toml` (`FA-ART-CAL-01`)
currently have empirical confusion-matrix counts; the remaining 56 procedures
previously labeled `calibration = "planted"` had unit tests over planted books
without retained confusion-matrix counts and are therefore recorded as
`calibration = "uncalibrated"` until per-procedure calibration manifests land.
