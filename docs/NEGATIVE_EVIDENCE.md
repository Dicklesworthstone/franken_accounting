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

## Reference period laws shared the production implementation (fa-vfu)

Source review found that the reference oracle called the same admission,
transition and calendar functions as the kernel. Agreement could
therefore preserve a wrong accounting law. The oracle now contains a literal
Appendix C table, explicit transition edges, kind restrictions and a linear
half-open period resolver, retaining its unique-match check. Special-period
classes retain the independent raw registry reader. Its application law and open-item fold use its own
limb arithmetic, narrowing only admitted, bounded output values.

New tests compare every posting class/state/disposition, expiry cell, period
kind and transition action. A planted Original/SoftClosed production cell
admits without `post_softclosed`; the oracle receives that same matrix as
policy data and must refuse FA-REF-011, then post when authority is supplied.
A separate real-kernel differential checks that refusal without mutation and
the subsequent successful posting and register fold. Application tests cover
joint over-application, exact i128 leg bounds and an intermediate above i128.
These reference and focused kernel tests passed in build 1099 on 2026-10-12;
this was not a full mutant-kernel run.

Calendar generation and fiscal-year selection now walk civil days using
independent month/week boundaries and year-end candidate enumeration. Source
tests cover each calendar family, all year-end months and weekdays, both
year-end rules, 52/53-week years, century dates and DateDay endpoints. These
tests still share primitive date operations; policy parsing also remains
shared. Reparenting onto current main also requires the calendar prerequisite:
reject unsupported adjustment counts instead of clamping, validate directly
constructed month fields, check adjacent-year arithmetic, and continue past
an unrepresentable adjacent fiscal year when a valid containing year exists.
These use main's checked date helpers and preserve its newer civil-date APIs.
Constructor and boundary regressions passed in build 1099 (40 fa-time unit
tests and 28 fa-reference unit tests). Integrated full-gate proof remains pending.

The differential request adapter also replaced each declared leg and
settlement unit with USD. It now preserves those units. A fixed 32-seed
campaign exercises USD, JPY, BTC and ETH through actual kernel postings,
applications, reversals, retries and register folds, with literal balance
checkpoints and isolated per-unit imbalance refusals. After representable
near-boundary totals, an additional balanced posting crosses a register
column to i128::MAX + 1: the oracle retains that exact value, while the
production fold, report and maintainer must refuse overflow without publishing
partial cached state. This documents the current report bound; it does not
claim arbitrary-size production registers. All 32 seeds passed in build 1099.
The seven longer generated-history tests now each run 32 fixed distinct
seeds, with the original seed first, unchanged assertions and a replay command
printed for each seed. Their coverage floors remain intact; any newly exposed
failure must be investigated rather than excluded. Build 1099 passed the
limited-account, period-authority and per-entity campaigns, but failed four
other campaigns as detailed below. The 10k-seed worker campaign and actual
mutant-kernel receipts remain open.

Repeated oracle `create_periods` also overwrote transitioned period states.
It now checks all identities before mutation and returns a typed error for
duplicates or invalid ranges. The kernel comparison requires its actual
AlreadyLive refusal with unchanged period rows and frontier, followed by
successful creation of another year and the original authorized posting.
Invalid-year controls retain the oracle's existing definitions and states.

A per-crate Clippy configuration now lists the eight production calendar,
resolution, transition and admission methods. Normal oracle library builds
forbid those calls; existing comparison tests expect each configured lint
separately, including an alias and a re-export. The mandatory Clippy pass
must execute before this boundary can be claimed enforced; that Clippy run
remains pending. No valid-history arithmetic panic has been
demonstrated; the arithmetic change removes shared fixed-width decisioning.

### Public register-cell subtraction (fa-645, 2026-10-11)

Source review found unchecked subtraction in `Cell::net()`. Valid folded
cells have nonnegative columns and a representable difference, but callers
can construct public cells such as `(debits = i128::MAX, credits = -1)`.
The method now returns `RegisterError::Overflow` for an unrepresentable
difference, and its migration-test caller explicitly requires a valid net.
New tests pin exact positive and negative boundaries, cancellation, and both
overflow directions. Build 1099 passed all 22 fa-registers unit tests and all
14 migration tests. The complete gate remains pending. No journal-produced cell
overflow or enlargement of the register's column bound is claimed.

### Generated-history failures exposed by the wider campaign (2026-10-12)

Build 1099 on `74c69f9` exited 101: 127 tests passed and four differential
tests failed. The original transcript is retained; no seed or assertion was
removed. These were caller/coverage failures, not observed engine/oracle
disagreements:

- Seed `9e3779b97f4a7c15` asked `explain_balance` for summary account `1`
  and unwrapped its `InvalidSelection`. The test now asserts that refusal
  explicitly and retains every leaf-account contribution and history check.
- Seed `7135eed50fa0c7f2` recorded no Closed-period expiry. Random manual
  resolutions could consume the planted holds, and final-drain expiries were
  omitted from the state counters. Additional real holds now reach their
  exact deadline immediately after close/lock and must expire through the
  actual sweep. Every returned final-drain batch is counted as well.
- Seed `0badc0de5eed124a` hit an exact budget boundary only once. After all
  640 original generated steps, two untouched periods receive real exact-cap
  holds and one-unit-over-cap refusals, checked against the oracle and stored
  cells; the refusals must preserve the frontier.
- Seed `5c4ed01ed0af7e75` minted only one reversal at Open. Two additional
  March accruals scheduled for April 1 now become due before April opens;
  the Open helper must return both actual reversal identities.

The original 32 seeds, generated step counts and coverage floors remain.
The repairs are awaiting a new runtime verdict and do not close `fa-vfu`.

Build 1110 on `095a797` exited 101 on 2026-10-12: 129 tests passed and
two differential tests failed. All 32 seeds passed for the multi-unit,
period-authority, budget, limited-account, scheduled-reversal and per-entity
campaigns. All reference, register-cell, migration and calendar tests passed.
The two remaining failures exposed additional generator coverage gaps:

- Seed `9e3779b97f4a7c16` posted applications but no random reversal undid
  one. After all 640 generated steps, a history with zero undos now reverses
  a real applying receipt in untouched June. The test checks exact released
  amounts against both implementations, then verifies projections and open
  items. The later corruption probe retains its live application targets.
- Seed `7135eed50fa0c80b` exercised `FA-REF-097` once, below its floor of
  three. After all 600 generated steps, missing cases now create distinct
  timed holds in open March and reach their exact deadline. Posts must
  refuse without changing either journal; Voids must then succeed using
  the refused request's key. Due backlogs and pending registers are checked
  against the independent oracle before and after resolution.

Neither failure showed an engine/oracle disagreement before the coverage
assertion. All original seeds, random draws, floors and assertions remain.
The two affected campaign wrappers now retain each panic diagnostic and run
the remaining independent histories before failing with every failed seed.
No failed history can become a passing test. These two new repairs have
passed source review and static checks; their runtime verdict, the actual
Clippy boundary checks and the final integrated gate remain pending.

### Reversal ancestry can strand a live application (2026-10-12, fa-wck)

Build 1120 on `791216f` ran all 32 generated histories. Twelve failed:
ten stopped at evidence-refusal coverage floors, one lacked reversal-shape
refusal `FA-REF-051`, and seed `9e3779b97f4a7c2d` exposed a product defect.
At commit sequence 182, open-item verification found entry
`284225560683079585833914309786111446645`, leg 0, with an applied mirror
of 57,917 but a literal journal fold of zero. The kernel and reference
admission had agreed before this independent mirror check failed. The
separate timed-expiry campaign passed all 32 seeds, including the formerly
deficient `7135eed50fa0c80b`. Cargo reported one passed test and one failed
test after 2,703.83 seconds of test execution; the complete run remains red.

Source inspection identifies a matching counterexample: reverse an invoice,
reverse that reversal to revive the invoice, apply a payment to it, then
reverse the second reversal. Admission previously checked only the immediate
target's legs. A reversal cannot receive applications, so its zero mirrors
hid the live application on the invoice ancestor. Both literal folds correctly
exclude that now-inactive invoice. The old log does not record this particular
entry's complete lineage, so attribution of that exact runtime identity to
this sequence remains an inference until replay.

The repair witnesses and authenticates the full reversal ancestry before
admission and applies the existing live-application refusal to every affected
ancestor. The reference independently traverses its journal indices and
counts applications from its own fold. A short real-kernel regression requires
the third reversal to refuse without writes, then allows the identical
proposal after the payment is reversed. Direct receipt undo remains supported;
unsupported reapplication by reversing its reversal remains refused.

An existing 67-reversal test explicitly required the defective admission.
Its correction preserves all 66 lawful reversals and the successful payment,
adds the exact `FA-REF-073` refusal and unchanged frontier/mirror, reverses
the actual payment, requires the same 67th proposal to commit, and retains
the final `FA-REF-070` refusal on another payment. This changes a demonstrably
wrong expectation; it does not drop the positive chain or weaken the mirror
verifier. Independent source review found no blocker. On `b1a8d83`, both
reversal regressions and the SoftClosed and reversal-period controls passed
in remote build 1129. Three isolated production mutations then failed their
intended real-kernel differential, after the independent reference decision
had already been asserted:

- Build 1131 stopped ancestry inspection at the immediate target. The kernel
  committed the third reversal at sequence 14 instead of refusing FA-REF-073.
- Build 1132 changed Original/SoftClosed admission to unconditional admission.
  The kernel committed at sequence 9 instead of refusing FA-REF-011.
- Build 1133 removed the production reversal-period check. The kernel
  committed an April target's reversal in March at sequence 16 instead of
  refusing FA-REF-053.

Each mutant was the sole source change and exited 101 from the intended
assertion, not setup or compilation. After removal of every mutation, the
source was byte-identical to `b1a8d83`; all four positive controls passed
again in build 1134. The wider repaired campaign, mandatory Clippy boundary
checks and final integrated gate remain pending. These results are bounded
runtime evidence, not a general proof or a closure of `fa-vfu`.

The generator's separate coverage gaps are supplemented only after all
640 original draws, in untouched August. Each deficient evidence case must
produce the independent evidence oracle's actual refusal without changing
frontier, journal, or folds; corrected evidence must then post under the same
key. The missing reversal-shape case uses a balanced same-period reversal
with the wrong leaf account, followed by its exact side-swap under the same
refused key. All 32 seeds, original draws and coverage floors remain. The
SoftClosed mutation probe also now captures both kernel and independent
oracle verdicts before asserting refusal, so an admitted mutant cannot panic
before the reference decision is observed. The coverage supplements still
await their full generated-history runtime verdict.

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


## 2026-10-12 — Bundle producer and verifier size admission (fa-5hs)

Source review found that external evidence can exceed the independent
verifier's 16 MiB inline-document bound, while the producer cloned those
bytes into a bundle without that admission check. Balance requests also
lacked the verifier's 4096-proof bound. This was a source finding; no
pre-repair runtime verdict is claimed.

The producer now refuses these two over-limit requests with FA-REF-129.
Balance count is checked before requesting cited documents. Inline size is
checked against verified metadata after authority, revocation and disclosure
admission, before fetching the external blob, and again before assembly
hashes or clones supplied document bytes. A redacted view never invokes the
full-document callback. Stub production still reads and verifies available
source bytes; it does not fabricate evidence when the blob is missing.

The verifier's bounds and decoder behavior remain unchanged. Independent
production constants are compared in dev-only contract tests, preserving
the verifier's empty normal dependency set. Tests retain the exact 16 MiB
inline and 4096-proof positive boundaries, the 16 MiB-plus-one stub positive,
missing-blob and denied-authority precedence, and independent over-limit
decoder refusals. A fresh large-document stub and its signed receipt are
also passed to Cargo's built standalone verifier, with a one-byte commitment
mutation that must fail only the public-commitment check. These new runtime
tests and the final integrated gate have not executed yet.

The first static scan of the partial scratch copy classified an unchanged
genesis integration-test panic as library code because that crate's Cargo
manifest was absent. Supplying its exact existing manifest changed the
classification; the same Rust source then scanned with zero critical issues.
No test assertion, scanner rule or exclusion changed. Both transcripts are
retained; this static result does not establish runtime correctness.
