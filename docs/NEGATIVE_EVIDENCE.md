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
  keeps the structured assertions. The gate on that tree has not run yet.
