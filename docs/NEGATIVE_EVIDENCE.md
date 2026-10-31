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

## 2026-10-25 — False closures found by the 10-20 check (`fa-ldfy`)

The 2026-10-20 reality check (`fa-hlnd`) audited closed and open beads at
`0d338c0` and identified 15 closed beads whose acceptance criteria were unmet at
closure time (hiding remaining vision scope from `br ready`) and 6 open beads
whose descriptions had drifted behind landed slices. Rather than silently
reopening another owner's closure where a dedicated corrective bead already
exists under `fa-hlnd`, each of the 15 closed beads now carries a dated audit
comment citing exact `file:line` evidence, reproduction commands, and its
corrective bead ID(s):

- **`fa-tu58`, `fa-i5s` (§17 benchmarks and SLO baselines):** Baselines were
  hand-entered and benches timed fixture setup rather than the stated workloads
  (`crates/fa-bench/src/lib.rs:1057-1134`, `registries/slo.toml`). Retracted in
  `fa-e75k` (closed); real §17 measurement harness tracked in `fa-ykbp`.
- **`fa-uqq`, `fa-8x9` (Lean 4 formal proof lanes):** Lean was never compiled in
  the gate and a synthetic `.olean`/`.fln` header check stood in for `lake build`
  (`crates/fa-money/tests/formal_anchors.rs:323-357`). Retracted in `fa-2lsv`
  (closed); real Lean compilation and theorem-inventory witness tracked in `fa-09q8`.
- **`fa-6dw` (TLA+ merge-train model):** Spec was not wired to
  `scripts/merge_train.sh` and TLC state exploration was unrecorded. Tracked in
  `fa-dj6j` and `fa-apde`.
- **`fa-npi`, `fa-faim` (external plain-text and standards oracles):**
  Beancount/hledger differential was a self-oracle and XBRL checked a 28-element
  internal fixture rather than a real taxonomy calculation linkbase. Retracted in
  `fa-kkxl` (closed); real external oracles tracked in `fa-sa4w` and `fa-ipom`.
- **`fa-oz3` (`RestatementCase` and `Reclassification`):** `RestatementCase` was
  library-only at closure (later surfaced in `fa-75j4`), and
  `EntryClass::Reclassification` / `fa reclass` remained refused (`FA-REF-102`).
  Tracked in `fa-xvba`.
- **`fa-os2` (calendars and time zones):** `Custom` calendar kind, surfaced
  business-day calendars, non-UTC `time_zone_policy`, and golden vectors through
  2100 were absent. Tracked in `fa-94qd`.
- **`fa-vn4` (register checkpoints):** `crates/fa-registers/src/maintainer.rs:1-20`
  had no journaled `RegisterCheckpoint` object or checkpoint-bounded historical
  rebuild. Tracked in `fa-9xf9`.
- **`fa-i9yn`, `fa-pbm` (custom statement definitions and regulatory schedules):**
  Statement lint, custom `StatementDefinition` objects, and FFIEC 031/041 / FR
  Y-9C schedules were library-only with zero CLI/MCP callers. Tracked in
  `fa-qh60` and `fa-doa9`.
- **`fa-12x` (Polish Bar simulated-agent corpus):** Closure cited a
  simulated-agent corpus with zero `useless_error`, which did not exist in the
  tree. Tracked in `fa-nmk4`.
- **`fa-hlvs` (metamorphic relations):** Substituted `plan+commit` for genuine
  `draft-promote == trunk-post` and lacked retention/compaction and real fixture
  `export -> import` identity checks. Tracked in `fa-eid6`.
- **`fa-f3bo` (provenance closure):** Full provenance closure enumeration
  (`fa explain evidence`), closure digest in certificates, and complete bundle
  closure packaging remained incomplete. Tracked in `fa-ge0y`.

In addition, the 6 open beads with stale descriptions (`fa-4o0`, `fa-6l9`,
`fa-3ock`, `fa-ehd`, `fa-z5u`, `fa-i7e`) now carry dated `Current state 2026-10-20`
notes distinguishing landed slices from remaining scope, and `fa-8jcr`
mechanizes evidence-bound closure (`scripts/close_bead.sh --verdict`) so future
code/script beads cannot close without their named `acceptance-tests` passing in
a verified verdict note.

## 2026-10-24 — fa-94qd: no-entity genesis skipped calendar validation

At `57f52353`, the native `create_book` API committed a monthly-calendar book
whose opening date was January 2, outside the registered Normal-period starts.
The new regression expected refusal but received `CommitSeq(1)`. An early
`db.write` for books without declared entities bypassed `BookSpec::validate`;
declared-entity books already ran that validator. Empty calendar identifiers
and overlong names had the same missing admission path.

`93fa44aa` moves the existing validation before both publication paths. The
unchanged regression checks three malformed inputs in both entity postures,
exact head/row preservation, and a valid corrected retry in the same database.
It passes within the source-bound 273-test journal/register/CLI selection.
The native-entity capacity test also exposed an invalid older FX fixture date;
the fixture now uses February 1, preserving its locked January 1 Opening period.
The earlier 10-pass/1-fail FX run is retained; no calendar rule was weakened.

This is bounded constructor evidence, not a historical-book repair or complete
calendar qualification. Full canonical proof and the original fa-94qd
acceptance remain open. Beads retains the counterexample, repair and gate limits.

## 2026-10-24 — fa-715: scoped reports exposed whole-book tail metadata

The initial authorized HEAD reader at `e5ef2004` admitted the requested report
but then inspected a resident delta window covering the whole book. A March
reader could receive its global decode count, including an April posting.
This violated authorization before observation even when the reported amounts
were correct. The preserved local control `d2dfa72b` uses the old handler with
the final regression: it fails with `Maintained` tail count 3 for that scoped
reader. The identical test blob passes at `d3c07a1e` after the existing
whole-book authority check is applied before inspecting the optimization.
Narrower admitted reports retain explicit-prefix literal reads; no policy is
relaxed. The native regression and real CLI head/history/restricted-token
workflow also pass in the later runs. This does not complete the broader
physical-observation or reader-complexity acceptance.

The broader run exposed a separate `fa-apdv` integration defect: the capacity
scan added every vertex as an old preparation witness, making an unrelated
document invalidate a lawful post. `01ae8771` checks current journal capacity
under the native exclusive writer borrow while retaining the preparation's
original accounting and authority witnesses. `2f180531` preserves the existing
exit-6 contract when a competing financial publication exhausts capacity.
The previously failing unrelated-document case, new capacity-race case and
all 193 journal integration tests pass at that source. No mutable balance or
new writer lock is introduced.

At `40368380`, all 122 CLI integration tests, both robot-schema tests and all
49 daemon tests pass; workspace all-target compilation and affected Clippy
exit 0. The `fa` library run at `2f180531` remains 548 passed / 11 failed,
including ten unvalued foreign-application fixtures and an over-cap detector
fixture. Canonical proof is unavailable, the legacy evidence helper reports
UNRUN on RCH's completion format, and UBS remains non-pass. No release, main
landing, complete-project verification or Bead closure follows.

## 2026-10-27 — fa-ze0y: consolidation broke the runtime verb registry

The consolidation `7f075b7d` rewrote the daemon's eight usage strings as a
multiline TOML array. Standard TOML accepts it, but the deliberately bounded
`fa_registry::toml` reader consumes single-line values. This agent introduced
the incompatible representation. Peer repair `28867aec` reports that every
`fa` invocation failed before dispatch with exit 5 and
`verbs.toml: toml line 79: unsupported value '['`.

`28867aec` restores one flat array. An independent standard-TOML comparison
confirms no parsed registry value changed in that repair; all eight strings
and their order also match `7f075b7d` and the current source. Standard-parser
acceptance and Rust formatting are not execution of the production reader.
The peer commit reports two harness-verbs tests and the real CLI `_selftest`
passing; those native results were not independently reproduced here.

Once the registry loaded, the peer reported a stale period-routing assertion
in `fa-verbs`. Local checkpoint `53ea8bf8` tests the current shared operation
contract: both planning forms select Read first, all five transitions name
Close or Reopen for commits, and adding planning flags cannot turn commit
inputs into read authority. Unknown verbs and transitions still have no
route. This intentionally stops asserting that the shared registry has no
period-commit route; it does not grant an MCP session confirmation or those
operations. Production registry rows, launch ceilings, CLI confirmation
checks and their separate refusal tests are unchanged.

All nine original `fa-verbs` test names remain. Formatting and the scoped UBS
scan exit 0 (zero critical findings, 156 warnings). A source-derived registry
diagnostic matches 27 cases and detects reordered rules and a removed
commit-input guard; it is not native Rust proof. Native tests, Clippy and
Tier 0/Tier 1 remain UNRUN because the unchanged disk preflight exits 1.
The original `fa-ze0y` and `fa-mg2j` acceptance remains open; no full-project
pass or closure follows from this repair.

## 2026-10-27 — Native qualification: access receipts and cache recovery

The full workspace run at `e58191e8` reproduced three CLI access-log
failures. A Human operator token holding only Hold was sent through the MCP
launch ceiling, even though that token's Human authority was valid. The
operator-token route now recognizes Hold alongside Approve, Close, Reopen
and Witness. The existing regression checks the original token bytes and
caveats and still rejects binding that authority to MCP. Neither MCP ceiling
is widened. A native candidate run passed all 76 CLI library tests and the
previously failing Hold/Witness access-history workflow; that run still
failed the other two access-log cases.

The bound NDJSON export had constructed its journal inside
`BookSource::open_admitted`'s admission callback. The callback runs before
the access receipt commits, so the returned HEAD export observed sequence
13 while its receipt was recorded at 14. The candidate admits the requested
reach in the callback, then constructs the export after the receipt. HEAD
is resolved then; explicit historical selectors and proof cuts keep their
own prefix. The existing HEAD assertions remain exact, and an additional
historical-export regression posts a later entry and requires its exclusion,
the selected stream/header coordinate and exactly one current access
receipt. Native qualification of this export correction is pending.

The other negative case called `finding list` without its now-required
certificate selector. It received usage exit 2 before reaching authorization.
The fixture now supplies a syntactically valid nonexistent certificate;
unauthorized callers must still receive the same exact safety refusal,
disclose no coordinate or book, publish no access receipt and never look up
that handle. This changes the input to exercise authorization; it does not
change error precedence or relax a denial assertion.

The same baseline failed a register-cache expectation. Damaging a mutable
cell correctly rejects that cell, but an intact immutable checkpoint and
exact tail can still answer a whole-book authorized read. The old assertion
incorrectly required a literal fold after damaging only the cell. The same
test now independently requires the cell-only path to fall back to Literal
and register verification to detect drift, then requires checkpoint recovery
to equal the complete literal report bytes without changing the journal or
graph. It finally damages only the disposable checkpoint head and retains
the original literal fallback assertions when both cache paths are unusable.
This intentionally admits valid checkpoint recovery; damaged cells, changed
amounts, incorrect cursor/tail coordinates and read-time writes remain
rejected. Assertions increase and production cache code is unchanged. The
exact original test passed natively with the candidate overlay: 1 passed,
0 failed, 619 filtered. That is not a passing 620-test library target.

The lab fixture also boxes its existing Send future before task creation,
preserving lazy ambient-Cx capture, seed, budget, scheduler, quiescence and
cancellation-completion checks. Real whole-library code generation no longer
emitted the recursive Send proof's future-incompatibility warning; it still
reported 610 passed and 10 failed before the cache-test correction. There is
no recursion-limit increase, lint suppression or unsafe Send implementation.

These results are source-scoped repair evidence, not a release verdict.
The complete baseline run and combined successor qualification remain
pending. Foreign settlement-group fixtures still require lawful source
valuation and carrying-value inputs; their currencies and positive scope
remain intact. Full Tier 1 and original Beads acceptance remain open.

The frozen `e58191e8` workspace run subsequently completed with exit 101:
4,444 passed, 43 failed and 3 ignored in 20 failing targets. All 4,490
inventory names have an outcome after normalizing only Rust's `should panic`,
`compile` and `compile fail` display suffixes. This is the older baseline's
result, not the newer main's failure count. The three ignored cases remain
unexecuted; no filtered subset replaces the original full scope.

At `05c193bb` plus the five declared repair overlays, migration-proof and
served-read targets passed all six tests. The broader CLI candidate passed
76 library, 4 disclosure and 9 scope tests; access-log passed 5 and failed 2,
and CLI passed 137 and failed 1. Both remaining access checks requested
`known_at` from the NDJSON header, whose actual field is `known_at_seq`.
This agent copied that wrong field into the new historical regression.
The candidate now checks the documented header field against the same exact
receipt or historical sequence; the response-coordinate assertions remain.
No export format or expected sequence changes to accommodate the fixture.

The CLI failure was a newly added draft-batch negative that supplied `--yes`
with an Agent token. Launch-bound Agents cannot supply host confirmation,
so usage exit 2 preceded the intended promotion safety check. The candidate
omits that invalid override, retains expected exit 7 and additionally
requires the capability refusal, unchanged head and unchanged complete draft.
The original lawful Human promotion, exact member order, retry, rejection of
overapplication and historical replay assertions remain. These last fixture
corrections still require native execution.

## 2026-10-28 UTC — Extraction context contract remains unmet

Original bead `fa-646` explicitly requires extraction under a `Cx` with
filesystem/process capability, only in the facade/CLI posture. At
`47fdfb6a`, `fa-docket/src/intake.rs` is unchanged from `6254c9f6`:
`resolve_binary_in_path` observes PATH and file metadata without a context;
`probe_tool_version`, `run_focr_extraction` and `run_fw_extraction` invoke
blocking `Command::output` without a `Cx` or purpose-typed wrapper. The
historical five Docket and two journal tests did not establish that promise.
The original bead is reopened with its owner, description and dependencies
preserved. No replacement task or reduced acceptance substitutes for it.

This is a source-established missing capability/runtime contract, not an
executed exploit or an OCR/ASR accuracy result. Preserve the implemented
missing-tool/model UNRUN outcomes, advisory AgentUpload/non-replayable
grading and DERIVED_FROM lineage. The repair must admit context before
environment/filesystem/process observations and provide structured,
bounded, cancellable child execution. Removing extraction or adding an
unused context parameter would not meet the original contract. That repair
and its native qualification remain pending.

The frozen `6254c9f6` Tier 0 check also completed with Cargo exit 101:
`fa-registers/tests/migration.rs:2344` had mutation-match arms returning
`&mut WriteBatch` versus `()`. Peer commit `e4a756cc` already fixes that
typing error on current main. The driver exited 1 and voided its overall
single-tree verdict because live HEAD moved to `47fdfb6a` during execution;
no Tier 0 PASS note was produced. The frozen compiler diagnostic agrees
with the frozen source, but does not establish a current-main failure.
Current native requalification remains UNRUN under the unchanged disk
reserve check (exit 1); no threshold, gate or test scope was weakened.

## 2026-10-28 UTC — Human token routing omitted registered authority

At `47fdfb6a`, `from_operator_token` recognized only Approve, Close,
Reopen, Witness and Hold. A valid Human token granting only SchemaChange,
for example, fell through to the MCP Preparer ceiling and was rejected
before reaching the existing chart-control handler. The same classification
omitted PostClosed, Restate, Migrate, RuleChange, IssueCapability, Erase,
Privileged and Receivership. These are source-established routing omissions;
no new runtime result is claimed here.

The candidate recognizes a Human-profile, Human-operator token when its
exact operation set exceeds both existing MCP launch ceilings. It retains
the token, commitment, caveats and issuance admission. Neither MCP ceiling
changes; tokens admissible under either ceiling cannot gain operator
confirmation. The existing exact-token regression now covers all fourteen
operations outside those ceilings. Negative coverage retains the full
Preparer ceiling without confirmation and rejects AI operator kinds even
for operations that the base Agent vocabulary permits.

The real operator workflow regression issues a SchemaChange-only token,
opens and closes an account, verifies exact retry without a new commit,
and requires missing authority and missing issuance to leave the head and
chart unchanged. The existing binary test also issues and loads that token
through `fa --token`, retaining its original confirmation checks. These
new checks remain unexecuted. Formatting and the three-file static UBS scan
exit 0 (zero critical, 284 warnings); native compilation, tests, Clippy and
full gates remain UNRUN under the unchanged disk reserve. Original
`fa-mg2j` remains in progress with its full acceptance intact.

## 2026-10-28 UTC — PPA scenario authority and native qualification

The original CLI event test exposed a prior-period-adjustment scenario
refusal at `e88200e4`: the caller supplied Read and Post, but the scratch
request retained only posting operations. The kernel correctly refused
its retained-earnings role lookup. The scenario repair retains Read for
that registered adjustment only after admitting the original planner's
Read and whole-book reach. Missing Read and restricted reach return the
original policy refusal before scratch role observation. No authority is
invented, and the period, role, approval and posting laws stay in force.

On immutable `41645e7e`, native execution passes all 230 tests in the
complete CLI library, access-log, CLI, operator-token and write-authority
targets. The original event test now passes its PPA/equity/proof workflow.
The complete journal genesis target passes 275 tests; the statement and
standalone-verifier libraries pass 56 and 379. Each target's inventory
matches its outcomes, with zero failures, ignored or filtered cases.
These results also execute the schema-only Human-token workflow. Its new
unissued-token negative initially supplied no stdin and got usage exit 2;
supplying the valid account document retains expected safety exit 7,
FA-REF-156 and unchanged head/chart, and all five token tests then pass.

The dedicated facade case has no runtime verdict. Its vmi attempt lost SSH
with exit 255 after compilation progressed; the exact wrapper is
`rchw-8995d92d-f5fc-49e7-8f79-cd104321da16`. Supported recovery and cancel
have not acknowledged retirement. The complete workspace inventory at
`41645e7e` compiles and lists 4,667 tests, including the corrected case, but
artifact retrieval fails and terminal acknowledgement remains false for
`rchw-d3214c27-5d7c-4300-9266-01762f0a4f28`. The following full runtime
request refuses with exit 103 before Cargo because that pair has an
unfinished owner. The newly added facade no-Read/scoped controls therefore
remain unexecuted. No lock/cache clearing, shared-daemon restart, local
fallback or replay bypass supplies a result.

Our exact-tree Tier 0 attempt at `6be52597` returns driver exit 2: format
passes, while the remote compile is UNRUN after queue timeout. No PASS
note is produced. A separately published `45b40a1e` Tier 0 note has
matching format/check log hashes on its named host; it is historical
compile evidence, not a runtime result or qualification of newer main.
The 940 scoped passing tests do not establish the full workspace or
Tier 1. The separately named CLI PPA acceptance tests are still absent;
monolithic coverage does not silently replace that inventory contract.
Original `fa-0hs4.8`, `fa-mg2j` and `fa-ze0y` remain in progress with their
full acceptance and prior comments preserved.

At 04:27 UTC the two originally named acceptance tests now exist:
`equity_roll_forward_shows_prior_period_adjustments_and_ties` and
`equity_roll_forward_prior_period_line_verifies_offline`. They exercise an
FY2026 adjustment relating to closed FY2025, independent approvals, exact
retry, the equity/balance-sheet tie, historical certificate replay, and
offline recomputation. The omission control pins the same independently
selected certificate and checkpoint key as its positive control, omits the
actual posted PPA payload, and expects `record_completeness`; it does not
substitute a mismatched receipt for the accounting-input check. This is
authored coverage, not an executed result. The first native attempt at
`c748c2bd` plus exactly those two test files refused before Cargo with
namespace teardown status 73 (client exit 103). Supported recovery of our
`rchw-77aee738-c2e2-4697-a0f1-075957a07489` returned terminal acknowledgement
true and original exit 1. No shared namespace, cache, lock or daemon was
cleared.

Source review then corrected the new fixture's assumption that a posted
case member retains the scenario's input idempotency key: the kernel derives
that member key from the case and plan. The test still locates the exact
posted entry digest and asserts its PPA class, effective date and two exact
amounts; retry additionally compares the complete returned member list.
No production law or original test was relaxed. Current formatting exits 0
and the two-file static-only UBS scan exits 0 with zero critical findings
(993 warnings, 138 informational findings). These checks do not type-check
or execute the new tests. Their native result, the complete facade case,
current strict Clippy, exact-tree Tier 0 and full Tier 1 remain unproved.

At 04:33 UTC a fresh journal read supersedes the earlier VMI ownership
observation: supported recovery of `rchw-8995d92d` now confirms completed,
exit 101 and terminal acknowledgement true, with its source pair retired.
The lost-stream log still has no test outcomes and the named remote
completion file is absent, so the particular compiler/runtime failure is
unadjudicated. The old TS1 inventory wrapper is absent from the current
journal and supported recovery refuses because its lease file is absent;
this does not establish its retirement or a passing runtime.

After that VMI pair's confirmed retirement and a fresh passing disk
preflight, a new two-target inventory attempt used `8ed9dbb3` plus only
the current `statements.rs` and `proofs.rs` files. It exits 1 before Cargo:
clean-baseline transfer times out at 69 seconds, followed by a 30-second
ownership-recovery timeout. Wrapper
`rchw-662d6f81-e58a-4a73-b2b5-541946680fa9` / build
`30083054965883416` is then recovered by the supported command: recovery
exits 0, original exit 1, terminal acknowledgement true. This is a
source-transfer failure, not a native test result. No timeout, capacity,
source policy or gate was changed to obtain admission, and it was not
replayed.

### 2026-10-28 20:45 UTC — conflicting equity restatement selectors

Source review found that `statement_equity_roll_forward` refused the
unsupported original-issuance selector but did not validate
`--as-currently-stated`. With that switch beside `--known-at` or
`--as-known-at`, `known_at_flag` could select a historical prefix while
silently ignoring the request for the current view. The existing
`issuance::reported_view` parser already enforces exclusivity for the
ordinary period statements. The equity path now invokes that same parser
before capability creation or book observation. The valid current-view
path is exercised by the original cross-year PPA acceptance; an additional
real-binary test requires usage exit 2 for six conflicting combinations
against an absent book. The retry assertion now also requires one actual
posted member, so two missing member lists cannot compare equal.

This is a source-level defect and candidate repair, not a reproduced
native failure or executed fix. A fresh preflight exits 1 with
142,055,874,560 free bytes, below the Mac's configured reserve. The proposed
worker-verified source-content transfer was therefore not submitted.
One-run remote-only permission is pending; no reserve setting, gate,
timeout, worker configuration or source policy has been weakened. The
unsupported original-issuance equity selector and full native qualification
remain open on the original task.

### 2026-10-28 — source-verified PPA target run: 55 passed, 3 failed

After the owner's reply to the pending one-run remote-only request, the
failed Mac reserve check remained recorded as exit 1; no reserve setting
or gate was changed. The exact approved command ran through RCH's
source-content mode on `vmi1152480`, build `30084504618008603`, wrapper
`rchw-3b201bdb-4644-40c5-bc51-50f245f90aea`. This transfer reached real
Cargo in place of the previously failing clean-baseline path. The actual
source tag was `53c6e9539a723f2d2da12466cf2fabb852d1f348-dirty`, including
concurrent case, cash-flow and read-authority work. The emitted receipt
root is `4400648619303d4f51bacd28d28e414dd105e423a193eb1f77367d803e4c03d1`.
Before correcting any fixture, all 1,471 receipt files matched local
SHA-256 hashes, byte lengths and executable bits (34,217,343 bytes).
RCH returned completed/remote/101 with terminal acknowledgement true.

The complete `fa-cli` proofs target ran 41 tests: 40 passed, 1 failed.
The complete statements target ran 17: 15 passed, 2 failed. Both report
zero ignored and zero filtered tests. The current/historical selector
conflict regression passed all six combinations. The two PPA tests
compiled but stopped at the close prerequisite: `period close` requires
an explicit registered `--reason`; `--yes` supplies no reason. My initial
status diagnosis called the flag unsupported; the retained refusal is
specifically the missing reason. The fixtures now add `--reason Scheduled`
while retaining `--yes`, the closed-period prerequisite and every expected
successful PPA assertion. No production period rule changed. Financial
assertions after that close were not reached in this run.

The other failure was
`retained_statement_certificates_bridge_and_trace_without_reselecting_head`:
its audit assertion expected `statement diff`, while the registry declares
`statement` with an empty subcommands list. The existing audit constructor
therefore records command `statement` and binds the exact operation and
arguments in `request_digest`. The test now requires that canonical family
and the exact digest of `statement diff`, both retained certificate IDs and
`--json` in canonical flag order; principal, access count, observed/recorded
frontiers and no-write refusals remain checked. The source-predicate
win/lose split is explicit: a correct family and full request digest is
newly admitted; a wrong/missing digest is refused; an unregistered
`statement diff` command string that the old assertion alone admitted is
now refused. This comparison is source analysis, not a rerun or a claim
that the corrected test passes. No registry, audit producer or gate was
changed to match the observation.

The fixture corrections pass formatting and a two-file static-only UBS
scan (exit 0, zero critical, 1,010 warnings, 139 informational findings).
Their native rerun remains pending. The original one-run exception has
been used; an explicit extension for continued remote-only qualification
has been requested. The 55 passing tests are scoped evidence, not a
workspace PASS, Tier 0, Tier 1, original PPA closure or release result.

## 2026-10-28 UTC — PPA case fixture mixed two independent refusals

The complete `fa::restatement_case` integration target on the new equity-view
source (base `3323cf0c`, three source overlays) ran all eight tests: seven
passed and `a_prior_period_adjustment_case_posts_its_approved_manifest_once`
failed at line 825. Client and remote exit were 101, with RCH terminal
acknowledgement and retirement true. Receipt root
`a7399d157c41430cc1d1217d51f8839b453442cf8ef75a30b7bdfa37f5172875`
matched all 1,477 local source files before the repair. No ignored or
filtered tests were reported; assertions after the failing check were not
reached in that PPA test.

The failing check expected `FA-REF-178` when deriving a Restatement member
from a plain Original posting. Its shared template now carries the
mandatory PPA `relates_to` extension, so it is no longer that plain input.
The existing `derive_member` law first refuses a PPA marker on a non-PPA
case (`FA-REF-202`), before checking the delta-law class/supersession shape.
My initial status diagnosis called the marker missing; reading the exact
call and predicate showed that the incompatible marker is present.

The test now checks both contracts separately: the unchanged marked
template must refuse with `FA-REF-202`; a clone with only the registered
PPA extension removed must still refuse with the original `FA-REF-178`.
The original marker-bearing proposal and positive case workflow remain
unchanged. A new head-equality assertion confirms these derivations write
nothing. The admitted/rejected split is therefore two valid negative
fixtures with their distinct strict refusals; no production validator,
authority, amount, expected success, original assertion or gate is relaxed.
This source analysis is not a passing rerun. The full target and current
successor qualification must actually execute before any closure.

## 2026-10-29 UTC — Stale surface tests after correction reviews and native report work

The complete CLI package reported 708 passes, eight failures and two existing
ignored Tier-2 tests on the preceding source cut. Concurrent source changes
invalidated its final source-content barrier; the native exit 101 and subsequent
supported recovery/acknowledgement are retained as historical observations,
not qualification of the merged tree. The next candidate uses immutable base
`7cf701ed2713a88d7982b2bb6f3f6561efafae47` plus explicit RCH overlays. Its
complete kernel target passed 288/288 and its complete restatement-case target
passed 8/8, with no ignored/filtered tests and acknowledged remote exit zero.
Those results do not supply a full workspace verdict.

The eight CLI fixture repairs preserve the actual accounting contracts:
missing correction drafts require `FA-REF-157`/exit 3; due-date reconciliation
without an account requires the account-specific usage refusal; a raw reversal
intent uses `post` with class `Reversal`; open-items includes the fully applied
receipt alongside the invoice, now checked by exact original/applied/open
amounts and application identity; closing emits four exact routed legs over
three accounts, rather than netting the two retained-earnings legs. The
subledger fixture adds bounded real cash/revenue history so its unchanged
16-KiB size check actually exercises chunked retention without changing either
AR/AP control total. The refusal harness now triggers `FA-REF-202` and checks
that its account choice and independent case approvals remain a preparer's
judgment, not a mechanically invented fix. No production accounting law, gate,
golden, ignore, timeout or permission is changed to admit these fixtures.

The complete MCP package on that pinned candidate ran 108 tests: 105 passed,
three failed, none ignored or filtered; client/remote exit 101, acknowledgement
and retirement true. Two failures required `reason`/`intent` unconditionally
in discovery even though the registered retained-review form supplies those
sealed inputs. The tests now check their declared types and the `review` and
`digest` alternative, while retaining real missing-input/no-write refusals.
A fresh reversal without a reason must specifically refuse `FA-REF-054`/exit 3
in the accounting dispatcher, rather than the former transport-mapping exit 2.

The third MCP failure required every explanation contribution to cite a
document directly. `evidence_policy.toml` registers a Reversal's minimum as
`target`, with zero direct documents. The independent verifier's existing
`provenance_retains_registered_reason_and_evidence_heads_exactly` test already
admits an empty direct-evidence reversal and rejects changed target provenance.
The MCP fixture now checks the original's exact document oid, the reversal's
exact target digest and Reverses kind, equal amount and opposite side, and its
empty direct-document list. This verifies the authenticated evidence chain;
it neither duplicates citations in production nor permits an unsupported
source. All signed-bundle, fixed-prefix, receipt and wrong-certificate checks
remain. These MCP repairs require an actual complete-package rerun before
being credited as passing.

## 2026-10-29 UTC — Follow-up native failures are retained

The complete pinned CLI package subsequently finished with 718 passes, five
failures and the same two existing ignored tests; remote/client exit 101.
The complete `fa` package finished with 908 passes and 25 failures, exit 101.
Neither is a workspace PASS. The later merged canonical source is a different
cut; these failures are not silently relabeled against it.

Two shared fixture builders wrote maturity extensions on schema-minor-0
entries. Eight due-date and three portable aging tests therefore stopped at
`FA-REF-100` before reaching their intended assertions. They now name the
current schema minor, retaining all installments, amounts and mutation checks.
The raw draft-reversal fixture also supplies its actual effective date, which
the generic `post` contract requires. Event coverage now invokes the real
`replacement_reviewed` path and checks that reviewing publishes no book change;
the exact equality between observed and registered events remains intact.

The first subledger-size repair was wrong: longer descriptions and more
unrelated journal entries do not enlarge the embedded trial-balance result.
That attempt really failed its unchanged size assertion. The replacement
fixture uses distinct non-control asset cells and one balanced entry so the
actual certified result grows. It retains the AR/AP gross totals, the 16-KiB
and public inline-threshold checks, and all replay/wrong-scope checks.

The send-phase timeout control assumed an 8-MiB encoded request exceeded the
socket buffer. A read-only probe of the failing worker found a 16-MiB default.
The test enlarges its valid frame while retaining its 300-ms deadline, joined
peer, watchdog and exact SendingRequest expectation. No timeout or phase is
relaxed. Its first qualification attempt failed SSH before native outcomes;
supported recovery acknowledged that job. That transport result is not a test
failure or pass.

The claimed-T case selftest exposed a distinct validator defect: the runner
compared a retyped R row with its already-inferred R type, so it could accept
the original T claim. The separate gate repair compares with the declared
claim type. Its existing failing negative and every positive case remain
unchanged; the complete case target must qualify the admitted/rejected split.
This is a gate strengthening, not evidence that the accounting product gained
a capability, and it does not authorize any original Bead closure.

Finally, the case-post crash matrix stopped before fault injection because
its PPA template omitted `relates_to` and credited current expense. Its setup
now journals an Equity retained-earnings leaf and role, identifies February,
and posts the same 50,000 minor units through that leaf. All seven crash points,
approval identities, recovery/retry and register/journal assertions remain;
new assertions also require the retained-earnings leg to survive atomically
with cash and forbid a current-expense effect. These changes still need native
qualification. The separate foreign-cash carrying-policy, cross-target digest
and pinned-producer failures remain unresolved; their controls are preserved.

### Follow-up qualification and integration boundary

The corrected PPA crash matrix passed in the complete pinned library and
statements run (684 passes, nine preserved foreign-currency group failures,
exit 101). All eleven formerly schema-blocked maturity/aging cases passed.
The complete CLI library passed 76 tests with the larger valid socket frame;
neither its 300-ms send deadline nor its three-second watchdog was increased.
The CLI and plans follow-up targets passed 139 and 36 tests respectively.

The remaining subledger fixture failed during chart import: its single retained
schema row was 16,670 bytes, above the substrate's 16,384-byte limit. The next
candidate uses 32-account imports and eight balanced 32-cell postings. This
keeps all 256 report cells, the aggregate 2.56 USD offset, exact AR/AP totals
and original certificate-size and replay checks. Qualification is pending.
The full repository check also caught an intermediate unused `mut` in this
edit; that compile-lint failure remains recorded, and the `mut` was removed.

Concurrent integration admitted a161b652's substitution of BTC/AnyUnit for
the original EUR/AnyCurrency group scenarios. This makes the group mechanics
green without proving foreign-currency relief. The original EUR expectations
are restored; the new explicit missing-carrying-basis refusal remains. The
PPA fixture also retains the stronger candidate's February-and-March source
certificate and exact retained-earnings/no-current-expense atomicity checks.
Neither an earlier scoped pass nor this integration is a current-tree verdict.

Two functional-export tests expected a pinned producer to authorize export's
current journal/checkpoint integrity reads. The current whole-book reach
guard correctly refuses that scope. The candidate tests now require exact
`FA-REF-011`/exit 7 and no publication, then export the same historical
certificate with current whole-book authority. Exact residual/output and all
original-rate, receipt, signature and forged-receiver controls remain. The
production guard is unchanged, and native qualification is pending.

The claimed-type causal control initially failed to distinguish old and new
runners: clean 1eab06bf's original runner passed the existing single negative
(one pass, 73 filtered, 104 seconds). That test accepts an overall case failure,
which can also come from its unchanged wall-time budget. Its row still prints
PASS/R, so those assertions alone do not prove the original T claim was refused.
The candidate now additionally requires `rows_ok == false`, as the runner's
existing contract recommends for tests of non-budget behavior. All previous
assertions and budgets remain. The earlier complete 74-test pass does not
qualify this stronger test body; both bodies must be compared on the same base.

## 2026-10-30 — XBRL parent equity included the minority's share (fa-yugf.99)

`write_format_journal_xbrl_xml` grouped every Equity account into
`us-gaap:StockholdersEquity`, including registered noncontrolling interests.
Its type-level linkbase also added unclosed earnings to StockholdersEquity to
reach total equity, admitting a parent-equity concept that omitted current
income. These are incorrect concept predicates, even when the balance sheet
foots. The source-bound SunPower case deliberately excluded parent equity and
recorded the mismatch in `X-NCI-BINDING`; that exclusion is historical evidence,
not an external conformance result.

The correction carries the actual historical role set in the interop journal,
binds it to the coordinate digest, and preserves it across owned format round
trips. Parent equity is total equity less the registered minority balance;
total equity is parent equity plus MinorityInterest. The changed linkbase
admits the correct 600.00 parent / 400.00 minority / 1,000.00 total split and
rejects a one-cent minority substitution. With 25.00 of unclosed parent
income, it admits 625.00 parent / 400.00 minority / 1,025.00 total and rejects
the old omitted-income parent value. The former equation would reject that
correct inclusive parent amount by double-counting income. The exact-byte
test's parent-equity amount changes for that semantic reason; its other
facts, contexts, ordering and duration checks remain pinned. No validation
tolerance or negative control is removed.

The feature bead requested six T comparisons per SunPower year. Minority
interest is one unchanged, directly posted amount, so the existing K-TAUT
guard correctly classifies its export comparison as R. The candidate keeps
that guard, adds parent equity as the fifth T target, and adds separate NCI
R rows X-R-05/X-R-06. Six exported concepts are checked without inflating
their evidence class. The focused XBRL tests, all 58 fa-formats tests, the
historical-role export test, workspace all-target checking and affected-crate
Clippy have passed. All three native XBRL case tests also pass, including
the role-removal negative that observes the original wrong parent value
and missing minority fact; the final positive renderer exactly matches
the refreshed case README. The complete repository gate remains a
separate qualification; these scoped results are not a release verdict
or authority to close the bead.
