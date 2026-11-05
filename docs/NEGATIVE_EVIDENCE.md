# Observed defects and repairs

This record is required by the engineering doctrine. It names observed
counterexamples and the code that prevents their recurrence; it is not a
release certificate.

## 2026-11-05 — interrupted proof retained a log that changed after finalization

The `a44bc511` shared-slot full-gate attempt recorded global check and Clippy
as UNRUN. Its first native `fa` library job exhausted six offloader attempts
without executing: queue timeouts were followed by source-namespace initializer
refusals. The owned check driver was then terminated, and the next owned RCH
job was cancelled and recovered with exit 137, acknowledged and source-released.
No native passing result is credited to that invocation.

The producer finalized a RED/partial proof with exit 143 while that child was
still settling. Subsequent verification correctly rejected its checksum
closure: `steps/test-jobs/fa.test.access_accumulator.log` changed after the
manifest was sealed. The raw proof and logs remain unchanged; no checksum was
regenerated and no step was relabeled. This interrupted invocation cannot
authorize closure, publication or split-run reuse. Fresh qualification is
required after integration.

## 2026-11-04 — native payment differences need application parity at commit

Integrated source `224d31b9` executed the complete facade (727/0), model
(85/0) and determinism target (2/0), with no ignored or filtered tests.
Its next native packet returned 101: 592 tests passed and three failed.
All operator-token, write-authority, bank and policy cases passed, including
the scheduler's explicit System/PostClosed case. The new native and CLI
payment-chain tests both encountered the existing FA-REF-102 refusal when
reversing an application reversal. The new raw-post retry test expected
reserved alias FA-REF-009 instead of the live FA-REF-032 registry row.

The corrective native projection walks authenticated reversal ancestry and
alternates the original application's exact effects. Reapplication witnesses
the target's current lineage and remaining native capacity before emitting
derived SETTLES effects; ordinary undo emits UNSETTLES. Scoped footprint,
one-reversal identity, exact side-swap, and point-witness checks still apply.
Foreign-valued ancestry remains unsupported rather than substituting native
amounts for its recorded valuation relief. New negative cases consume the
released capacity elsewhere or reverse the source item; both require refusal
without any publication. The existing positive chain now continues through
four reversals. Native `36f6b828` subsequently executed 595 passing tests and
one failure: all 14 CLI subledger cases and all ten typed-difference native
cases passed, including the new parity and current-capacity negatives. The
remaining older native test still expected unsupported FA-REF-102. Its
scenario restores 300.00 after a different receipt consumed 250.00 of an
invoice's 500.00, so the current accounting refusal is FA-REF-072. Its
corrected expectation retains refusal and adds exact required/open amounts,
applied-mirror equality, and full unchanged-row/head checks. No negative test
was removed or changed into acceptance. Final native and exact-tree gates
remain required.

The pending module separately executed five passing tests and one failing
test on `224d31b9`. Its disjoint-account case still shared the original
source document. Diagnostic `9db316b7` retained every assertion and printed
the failed vertex: LabelId(16), the retained fixture Invoice document at
VId(111580638931722348158306021880142259661), not an account or period.
Both shared-document cases correctly conflict after the first publication.
Separating accounts and the source document still failed on `b8fa97b3`.
Unchanged-assertion diagnostic `713dcf85` identified the second point as
VId(199322935102087367386372612645850268979), LabelId(8), FY2026-P03.
Separating periods on `966d8bed` still failed; diagnostic `9964f7c6`
identified VId(248219180475393197307962412840611490853), LabelId(6), USD.
Four real competing-hold cases therefore retain strict conflict negatives,
identify the exact document, period or unit witness, and then require a fresh
preparation of the unchanged intent to commit with two holds. The positive
unchanged-witness case instead advances the prefix through a new unrelated
native source document while the delayed hold remains prepared. It must
publish without re-preparation and reproduce the exact pending count.
The first attempt was refused
by the offloader with exit103 before execution and earns no test credit.
The diagnostic is preserved and excluded from product ancestry.

## 2026-11-04 — native integration exposed six failures

The integrated `a2cc11bb` native run completed with 1,715 passing tests and six
failures across four targets. Its complete CLI cases passed 97/0, and the
large batch capsule-boundary regression passed unchanged. The six failures
were an expiry expectation, missing dimension-command authority coverage,
the symbol-67 witness change below, a staged duplicate-resolution diagnostic,
a shared-evidence concurrency fixture, and scheduled closed-period
execution that ignored an explicitly held operation.

Expiry correctly returned registered FA-REF-014, while the new offline test
expected FA-REF-011 for every denial. The repaired test retains all twenty
capability/certificate/checkpoint combinations and every unchanged-head
assertion; only expiry expects FA-REF-014. This exact repair executed under
`32d5ccaf`. The matrix now exercises `dimension constrain` under Read and
SchemaChange rather than exempting the command from coverage.

A second resolution in one transaction encountered the first staged entry,
but committed-only outcome verification obscured its target-derived conflict
as FA-REF-032. A distinct resolution key now receives FA-REF-062 after the
existing authority, scope, common-key and staged-entry checks; it never returns
a recorded outcome or discharges any accounting law. Same-key provenance
checks remain. The pending-prefix fixture also expected a commit after changing
a retained document it had read. The original shared-source case now requires
the observed FCW conflict and no publication. Changing only the accounts was
insufficient; the later diagnostic above identifies that mistaken assumption.
Later diagnostics identified the shared period and unit as well. The final
fixture retains those conflicts, requires safe fresh-preparation retries, and
uses an unrelated native document append for the unchanged-witness positive.
The point-witness law is unchanged.

Finally, the scheduler classified every conditional Reversal cell using only
its default `post` operation. Execution now tests the actual admitted executor
against the registered operation, requiring zero additional approvals in this
bounded schedule profile. Closed still requires explicit `post_closed`; Locked
still refuses. Read-only inspection retains its conservative default profile.
The native corrective tests and final exact-tree proof remain required.

## 2026-11-04 — symbol 67 changes authenticated certificate inputs

DimensionConstraint=67 extends the compiled and registered symbol table.
The native `a2cc11bb` Genesis campaign consequently disagreed with all 36 old
LAB04 pins; current-table diagnostic `32d5ccaf` also failed the cross-target
certificate pin while all four financial-output pins agreed. No pin was
changed before the following counterfactual executed.

The first inverse, `2bf027d9`, omitted only the compiled label. It restored all
36 old LAB04 hashes and both cross-target tests, but 22 functional fixtures
correctly refused its mismatched registry. The consistent inverse `c117e4cd`
also omits that single registry row. It executed 727 facade tests and both
cross-target tests with no failures, ignored tests or filters; remote and outer
exits were zero. All old pins and original assertions remained intact. These
controls deliberately disable the new label profile and must never be landed.

Across all 36 current/inverse runs, the native heads, trial-balance byte digests
and register folds agree. The seed-1 certificate remains 3,076 bytes; its 287
differing bytes lie only in nine 32-byte fields: seven snapshot bindings, the
Book input commitment and the trailing certificate digest. The current and
inverse cross-target outputs likewise have equal fold/TB/BS/IS byte digests;
only three certificate digests and the resulting bundle digest change. This
is input-change maintenance on x86_64, not an arithmetic or performance win
or an aarch64 qualification. The prior complete manifest and registry remain
Git blobs `03f0e08e059b5478b59d55bf23825e5b5743d8b1` and
`04dadb419c96824791bcf70797b2c53f7abb2580`. The updated product source still
requires its own full native and exact-tree gates.

## 2026-11-05 — full verdict inventories exceeded the process argument limit

The unmodified verifier failed before content validation on the retained
473,204-byte `9bc4c99a27c1` verdict note: Python could not launch because the
whole note occupied one command-line argument. The reader now opens the exact
immutable Git blob selected by the note reference and parses its UTF-8 stream.
The publisher already uses standard input and remains unchanged. No inventory
is truncated, and the existing format, source, checksum, step, test-name,
ancestry and closure rules remain in force.

The actual note now verifies as RED/partial with `check_exit=143`; closure still
refuses it. Producer-generated synthetic notes larger than that reproduction
exercise all 20,000 simulated native test names, strict tampering refusals,
RED inspection and closure rejection. The actual closure command also checks
named acceptance and landing ancestry against a large synthetic PASS proof.
These fixture tests establish proof transport and validation, not native Rust
execution or accounting correctness. The first closure-fixture assertion
missed the producer's existing shell-test witness; the corrected assertion
requires the exact ordered 20,001-name inventory and 20,000 simulated native
results. Both complete selftest scripts subsequently exited zero.

## 2026-11-04 — historical procedure framing lost registered identities

The `bef2ace9` decoder retains three historical extended procedure identities.
A source-history audit of 26 catalog revisions found 42 historical identities
with the same six-population native input layout. The other 39, including the
removed `damages.but_for` and `recon.book_to_book` names, were rejected before
the replay path could identify their unavailable registry epoch. The original
`benford.first_digit` version 1 also lacked its original-closure request path.

The extended decoder now enumerates those 42 identities and requires all six
native witnesses in their registered order. Retained Benford version 1 uses
its original closure. Extended framing refuses unknown identities, unregistered
intermediate versions, missing witnesses and reordered populations. Replay
continues to require the pinned registry and exact algorithm version; the
broader RegistryEpoch implementation remains on the original open `fa-vdc`.

Regression inputs are synthetic historical frames over real native captures,
with their public digests recomputed. They establish format behavior; historical
algorithm execution requires its own retained environment and execution proof.
The first executed native framing probe at `fb1f522` failed in the helper's
empty-findings assertion: its Benford prototype legitimately returned a finding.
The corrected prototypes use an assertion-drift capture without RegisterEquals
claims and an original-format cutoff capture without a document date. The
empty-findings assertion and all original closure/refusal checks remain.

The corrected `7a7104d` control subsequently compiled and executed on `ovh-a`.
It failed at the intended first historical identity, `aging.inventory@1`, with
FA-REF-150 / exit 8: unexpected extended native inputs. One native test failed,
716 were filtered out, and both remote and outer exits were 101 with completion
acknowledged. This witnesses the old framing refusal; the repaired source's
positive tests and exact-tree proof remain the authority for its behavior.

## 2026-11-04 — fa-d48q read-only preparation was stranded at two surfaces

The native `9435e377` facade library run passed 714 tests and failed
`required_rehearsal_allows_statement_preapproval_but_refuses_unverified_activation`:
statement-definition planning called raw write admission and returned
FA-REF-011 instead of preparing the definition. Preparation now uses the
explicit nonpublishing admission contract; activation checks direct-write
admission before any frontier read and retains its transaction authority
witness. The existing positive, refusal and unchanged-head assertions remain.

The same source's original five-target authorization run passed all 16
operator-token, 53 bank, 392 genesis and 82 journal-policy tests, but the
write-authority matrix passed two tests and failed its required-rehearsal
preview test. The `recover outcomes --dry-run` handler already prepared and
aborted its native transaction, but its launch-bound registry row was missing.
The shared registry now requires Read and SchemaChange for that exact target;
whole-book scope admission still precedes observation. Publication additionally
checks direct-write admission before opening the book. Both preview and
publication enter the existing exact-operation matrix; recovery of projections
remains host-only. Public admissibility now recognizes the same nonpublishing
preview exception as the dispatch confirmation gate.

The repaired `d089882` passed all 546 tests in the original five-target
authorization selection and all 97 complete CLI cases. The expanded run's
643 tests include those same 546; they are not additional independent results.
Its WorldCom walkthrough separately missed the 60,000 ms budget at 151,725 ms.

Fault control `7a7104d` omits only `tb`'s access receipt. The original five-target
selection and test profile, with the exact matrix test filter, compiled on
`ovh-a` and failed one native test at `write_authority.rs:1946`: zero receipts
where exactly one was required. The other four harnesses were filtered out
and supply no passing credit. The remote and outer exits were 101; the source
wrapper acknowledged completion. The full transcript is retained with the
control's verified recovery material.

The admission split is explicit: correct reads retain their mandatory access
event while native Entry payloads and Period rows remain unchanged; a read
that omits that event is rejected even when its head does not advance. These
repairs preserve the global write guard, operation ceilings and class caveats.
The exact `9435e377` Tier-0 PASS proves formatting and compilation only.
Closure follows the final exact-tree repository proof and the original Bead's
complete acceptance inventory.

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

## 2026-11-01 — Merged XBRL profiles disagreed with their retained calculations (fa-yugf.99)

The 6552be55a merge retained both equity writers but changed the historical
`TypeLevelStatements` role to sum parent equity and MinorityInterest. Its
legacy producer still emits posted equity plus a separate unclosed-earnings
fact. StormyLion's f6a631418 sweep reported two failures when those historical
exports were reproduced, an undetected role-removal substitution, and two
SunPower NCI read-backs rejected by the case reader's legacy binding table.

The historical role again sums its original posted-equity and
RetainedEarningsAccumulatedDeficit facts, as in 76049acab. Current attributed
and activity roles keep their parent-equity-plus-NCI calculation unchanged.
The admission split is specific: a legacy export with unclosed income now
foots under its historical role; a one-cent change to its retained-earnings
fact must still fail. Current profile amounts and their negative controls
are unchanged. This is versioned historical reproduction, not a relaxation
of the current equity law or external taxonomy conformance evidence.

Every XBRL producer now verifies its journal content against the retained
coordinate before exporting. Clearing the last account role cannot bypass
that binding. The case reader selects the attributed balance-sheet mapping
used by current exports, while its independent XML reader, exact public-fact
comparisons, contribution witnesses and T/R classifications remain unchanged.
Native qualification is pending; the peer's red report is not this agent's
independent execution, and no golden or acceptance requirement was weakened.

The existing omitted-income negative also selected the historical calculation
role for an attributed instance. The candidate first requires the unmodified
instance to validate under its actual equity profile, retains an explicit
wrong-profile control, and then requires the omitted-income mutation to fail
under that same actual profile. An unrelated profile rejection can no longer
stand in for detecting the incorrect parent-equity amount.

## 2026-11-01 — Solvency's debit-maturity negative retained the old admission contract (fa-0hs4.13)

The forensic solvency workflow still expected general `obligation_maturity`
on a debit leg to fail as historical extension 33 v1. The merged receivable
implementation deliberately selects v2 when a general declaration names a
debit leg. That obsolete expectation blocked the remaining checks in the
test; it was not evidence of an invalid payable entering the journal.

The original credit-only shortfall, changed due date, incomplete schedule,
and exact installment-total checks remain. A new mixed-side history must
produce the same 50.00 shortfall: its authenticated debit schedule is not
another liability. The wrong-side negative now uses the explicit
`receivable_maturity` spelling on a credit leg, which remains forbidden.
Both malformed declarations must leave book information unchanged.

The admission split is intentional: general debit terms now have a positive
workflow check under v2; explicit receivable terms on a credit and an inexact
installment total still refuse. Historical v1 debit rejection remains in
the unchanged model and independent verifier tests. No accounting validator,
amount, procedure threshold, golden or acceptance requirement is weakened.
Native execution of this updated workflow is pending; this test repair is
maintenance of the existing feature, not a newly delivered accounting law.

## 2026-11-01 — WorldCom's restatement lacked four original reporting closures (fa-yugf.42, fa-yugf.99)

The recorded f6a631418 case run refused `case diff --statements` with
FA-REF-161 for FY2001-P02. The native fixture uses a custom quarterly
calendar: only 2001Q1 had a Lock, while the other four periods affected by
R1 were merely Closed and had no StatementIssuance. Close permits audit
adjustments; it is not an originally reported frontier. The refusal was
correct and prevented W-T-03, W-R-02 and the case's disclosure from claiming
retained comparisons that did not exist.

The fixture now executes its four missing planned Locks through the existing
two-person approval workflow before the case. Existing posting step numbers,
published amounts, source documents, expectation types, the runtime budget
and the README are unchanged. These are reconstructed book controls, not
assertions of real filing dates or substitutes for the still-unimplemented
historical issuance workflow in W7. No refusal or accounting law is relaxed.
The existing unreported-coordinate controls remain the negative check; a
redundant full WorldCom run is not added just to test another fixture edit.

Native Linux case execution and the complete renderer acceptance remain
pending. Linux workers initially reported zero slots; capacity recovered
before this candidate's native verification attempt. Portable oracle tests
are being attempted separately on the Windows worker with its
explicit native target and isolated artifact directory; such results cannot
qualify a Linux book workflow or the full project gate.

## 2026-11-01 — Aging-portfolio prose used an uncited proof-class noun (fa-0hs4.13)

The original native `registry-check` target on 1206b023 passed 16 tests and
failed `real_workspace_registries_pass`: README paragraph 97 used “the proof”
without a live FA-ART or FA-INV citation. The paragraph describes independent
runtime verification of a retained portfolio certificate, not a registered
formal proof artifact. It now calls that operation “verification”. Its
account-level checks, distinct `complete` and `reconciled` verdicts, and
explicit limitation about external-subledger agreement remain unchanged.
No unrelated invariant citation, evidence artifact, checker exemption or
accounting requirement is added. The original checker must be rerun on the
repaired tree; the recorded 16/1 run remains a failure.

## 2026-11-01 — Historical-report fixture varied only the credit (fa-715)

The original full Linux qualification at c6b229386 ran the facade library:
679 tests passed and two failed. The historical-cache/authority regression
failed before its first selected report: `post_rent(..., 12_345)` kept the
helper's fixed 150,000-cent debit and supplied only a 12,345-cent credit.
The posting kernel correctly refused FA-REF-001. Its later 700,000-cent
call had the same fixture defect.

The existing citing helper now accepts both explicit amounts, and that
historical test supplies balanced 12,345/12,345 and 700,000/700,000 inputs.
Its expected totals, maintained cursors, tail counts, capability ceiling,
literal fallback and no-repair assertions are unchanged. The original
`post_rent` wrapper still fixes the debit at 150,000; its 149,999-credit
FA-REF-001 negative remains intact. No production auto-balancing or law
change is introduced. The original 679/2 run stays red; the independent
FA-ART-LAB-04 witness mismatch is not repaired by replacing its hashes.
Native re-execution and complete qualification of this repair remain
required.

## 2026-11-01 — Cargo color hid a successful compile from the gate (fa-1qk0)

Original Tier 0 on c6b229386 observed remote exit 0 and Cargo completion
after 15m05, but returned UNRUN: ANSI escapes before `Finished` prevented
its anchored completion predicate from matching. No PASS note or fold was
permitted by that run. A fresh execution on the same tree with supported
plain Cargo output passed and published the exact-tree note before folding.

Both gate drivers now set `CARGO_TERM_COLOR=never` and append that setting
to the existing RCH environment allowlist. No marker, exit-code rule,
budget, test inventory or failure classification changes. The existing
Tier-0 harness gains a forced-color caller regression: its controlled RCH
shim still executes real Cargo, models the remote color default, and
requires the caller's other forwarded input to survive. This is a gate
self-test, not native accounting evidence. The original compiler-error,
transport-refusal, stale-note and missing-note controls remain required;
their rejection and the new positive must execute before qualification.

## 2026-11-01 — Cross-target witness drift isolated to declared model inputs

The original c6b229386 and fresh a68f7f007 cross-target target both fail
the trial-balance certificate pin (1 passed, 1 failed, exit 101). Arithmetic,
fold and report bytes retain their pins; certificate and bundle digests move.
No aarch64 run is available.

Two initial counterfactuals are invalid, not evidence for re-pinning:
current source minus the new classes fails SoD registry validation, and the
old pinned source plus current classes/symbols fails the missing CloseControl
evidence-minimum check. Both failures and unchanged predicates are retained.
Adding that exact new minimum produces a valid control (0d3ba4667), but its
certificates still differ from current and its bundle retains the old pin.
Thus changing the TOML registries alone does not establish the cause.

The decisive counterfactual f698f1739 starts at the unchanged old pin source
f6e9ffbd6 and adds only the declared class/control-kind rows, their required
CloseControl evidence minimum, and CloseTask=62/DEPENDS_ON=38 in the registry
and compiled SymbolTable. Its Rust change is exactly those two symbol rows;
the compatibility checker, original evidence minima, SoD policy, accounting
fixture and every assertion remain unchanged. On the same hz2 worker it
reproduces all eight current a68 digests exactly. Compiled symbols enter the
genesis commitment; they cannot be replaced by editing an unconsumed TOML
file on old code. The original failed controls remain available and are
never merged as product code.

Only the three certificate pins and bundle pin are requalified. The previous
pins remain in the test, all arithmetic/fold/report pins and the planted
target-dependent encoding negative remain unchanged, and full-tree plus
aarch64 qualification are separate requirements. This is maintenance of a
bounded witness after an attributed model addition, not a performance win.

## 2026-11-01 — Existing pre-push guard was disconnected in the shared checkout

The concurrent merge 517c2044d (tree f363d990d) reached main and master;
at 14:03 UTC neither the local Tier-0 notes nor remote notes snapshot
c9f2067b3 held its exact-tree note. `core.hooksPath` was unset and the
default pre-push hook was absent. The tracked guard existed but Git did
not invoke it. No other default hooks were present.

Set the reversible local `core.hooksPath=scripts/hooks` and verified Git
resolves the tracked executable. Direct protocol-admission checks reject
the unqualified tip on main and master, accept an existing Tier-0-qualified
tree in default mode, and reject it in strict mode without a full verdict.
These are hook checks, not actual push attempts. Predicate and strictness
rules are unchanged. Recovery text now names the permanent gate and the
canonical main/master policy; it no longer suggests forbidden train branches
or a Tier-1-only note as a fix for missing Tier 0. Wiring the hook does not
retroactively qualify the published merge. Exact-tree gates remain required.

## 2026-11-01 — Production timer reads discarded the serving context

At 38ed0974, `TimedBook for Book` accepted a serving `Cx` for
`latest_tick` and `corroborated_tick_at` but discarded it. Both calls used
the synchronous book's private context. The async adapter already narrowed
the caller's context, and mutating timer adapters already preserved it.
Thus the production reads checked the wrong cancellation state before
observing retained TimeEvidence. The matched native counterexample below
confirms this context-boundary defect.

The production adapter now calls `Book::latest_tick_with` and
`Book::corroborated_tick_at_with`. Both narrow the supplied context and
reuse the existing async-core query checkpoint and restriction. A direct
production-adapter regression records a real tick, checks live and historical
reads, cancels a separate caller context, requires both reads to return
`BookError::Context`, and verifies that the journal and uncancelled read
remain intact. An earlier timer checkpoint cannot hide the adapter defect
because the test invokes the adapter directly.

The first Tier-0 attempt on 34146634 failed E0061: the newly authored test
omitted the required `BookKeys` constructor argument. Its explicit development
key fixture corrects that error; the production repair and every assertion
remain unchanged. This compile failure does not demonstrate the context defect.

On `ba29f8ad`, the complete native `fad --lib` run passed all 42 tests.
The evidence-only child `a7592cc7` changes only the two adapters back to
their original calls and retains the corrected regression unchanged. Its
complete run passed 41 tests and failed the new regression at the cancelled
`latest_tick` assertion (`timed/tests.rs:93`), after the real tick setup
succeeded. Returning to `ba29f8ad` passed all 42 again. Every run used the
same worker, Cargo command, profile and cap, with zero ignored or filtered
tests. The control remains recovery evidence, never product code to merge.

The original `fa-7uhr` conflict/fresh-tick/checkpoint acceptance and a full
verdict for this source remain separate requirements. The full proof at
`38ed0974` ended RED; it predates this repair and cannot qualify it.

## 2026-11-02 — Expiry-status serialization did not compile

The first native whole-`fad --lib` attempt on `f86a3376` failed E0308 at
`timed.rs:773`: the new expiry-read JSON helper passed an array to `obj`,
which requires a vector. No tests executed. The correction passes the same
six observed kernel fields in `vec![...]`; it changes no accounting effect,
counter value, assertion, gate or dependency. The failed transcript is
retained as `expiry-reads-f86-fad-lib-20261101.log` in the session artifacts.
Runtime and full-tree qualification of the corrected feature remain required.

## 2026-11-02 — Plain aging could not serve a known-at capability

At `26ad42fd2`, plain ledger detail and roll-forward admitted an auditor's
recorded prefix, while `gl aging` still required head reach. Both aging
renderers also loaded the head chart and then filtered its creation dates.
That observation cannot serve a token restricted to an earlier prefix.

Plain aging now uses the existing complete-prefix admission before its fold,
and effective-date and due-date rendering use the capability-checked chart
at the report's own sequence. Certification and reconciliation retain their
whole-head admission. Account, period and effective-date caveats are still
refused; report filters do not become authorization predicates.

The real-binary regression selects the March prefix while April has another
open item. It requires the owner's exact historical answer, one original
5.00 USD item rather than the head's two, one AccessEvent per admitted token
read, unchanged publication state on refusals, no retained certificate,
and current revocation even at the old prefix. It uses an issued Human token
with read, produce, and a known-at bound; it does not issue the Auditor
profile template.

On exact `bdf60c680` (tree `a45648f7`), the four complete CLI targets
`gl_certificates`, `proofs`, `read_scope`, and `robot_schema` passed 69/0
through real RCH at 2026-11-02T18:06:22Z, with no ignored or filtered tests.
The whole `fa-verbs` package passed 21/0. The original Tier 0 passed on that
tree at 18:36:51Z, using its authorized local compile fallback after an
actual remote refusal. No native test ran locally. The first cold CLI
attempt and two remote Tier-0 attempts reached the original compile limit;
their failures remain part of the record.

The evidence-only control `aa02ee77e` changes only the admission condition
back to the old guard. It retains the historical chart repair and the exact
test blob `0adb85ae9bfe5e7f305078700f222d848386325b`. The same four complete
CLI targets finished with 68 passed and one failed, exit 101, at
2026-11-02T19:26:28Z. Only the new positive case failed: its real
`gl aging --as-known-at 7` token read returned FA-REF-011/exit 7 where exit 0
was required. The control first encountered an SSH refusal and then a cold
compile timeout; neither was counted as this counterexample. Its unchanged
retry reused completed dependencies and actually ran all 69 cases. This
control is retained as evidence and must never be published as product code.

These are exact-revision component results, not a full-repository pass.
The return to corrected product `19e14bef0` passed the same four complete
CLI targets, 69/0 with no ignored or filtered cases, at 20:44:43Z. All three
forms again returned one original 5.00 USD item at pin 7 versus two at HEAD.
This is a later combined revision, not a strict same-revision A/B/A claim.
The original full repository run on 19e then recorded a compile-limit
failure; it is not a full PASS. Newer main `e4723f6f` and subsequent changes
need their own qualification. The original read-authorization Bead stays
open for its account-scope, whole-entry, substrate read-counter, and
reference-model requirements. These native results were self-executed;
the subsequent source review is described below.

## 2026-11-02 — Combined custom-case period lookup did not compile

The original Tier 0 on exact combined `665fbc8a` failed with E0425 in
`crates/fa/src/case_statements.rs:109`, in both `fa` and its library-test
target. The newly merged historical custom-statement path called
`fa_journal::rows::period_vid`, which does not exist. The canonical public
helper is `fa_model::period_vid`, already used by the facade's other period
lookups. The call now names that helper directly; its calendar, period code,
recorded frontier, row validation, and effective-date bounds are unchanged.
The superseded CLI and full-proof attempts on `665fbc8a` were deliberately
stopped after this actual compiler failure. Corrected `19e14bef0` subsequently
passed the original all-target Tier 0 remotely at 20:17:34Z; its first cold
attempt had hit the original compile limit. That compile result and the
69-case CLI pass above do not claim full custom-case runtime qualification.

## 2026-11-02 — Effective-date replay renderer missed the historical conversion

StormyLion and a fresh-context reviewer examined `e65cf0322` without
compiling or running it (Agent Mail 6279). They found that the separate
`render_aging` helper used only by effective-date certificate replay still
loaded the HEAD chart and filtered by creation date. The earlier description
of both renderers was therefore too broad. Replay already requires HEAD
authority, and account IDs determine the displayed codes, so the reviewers
found no authorization or output defect from this omission. The conversion
was nevertheless incomplete.

That helper now accepts the caller capability and uses
`accounts_at(aging.known_at, capability)`, with no creation-date filter;
the sole replay caller passes its actual capability. The existing pinned
aging test also checks bare `--certify` refusal. The existing AR/AP role
test now issues a real pinned read/produce token before making the HEAD AR
role ambiguous and removing the HEAD AP role. Both effective-date and
due-date aliases must still return the exact historical 40.00 USD item and
record four admitted reads. All original role and refusal assertions remain.
The shared read-scope runner forwards nonempty stderr without dumping every
successful JSON response; targeted positive witnesses remain.

These aging corrections and added controls subsequently ran on exact
`e9dc06b7750c818bcacd2094d2ee2630af09ab86`: all four pinned AR/AP role reads
and all three plain aging forms passed, including the bare-certification,
current-revocation, exact-amount and AccessEvent assertions. The source
review also confirms that output comparison cannot detect the `accounts_at`
swaps by itself; there is still no substrate read-counter claim.

The corrected source `e9dc06b7750c818bcacd2094d2ee2630af09ab86`, tree
`ac3c0fdbc6620118029d523766b0b7a10f32e878`, subsequently passed original
Tier 0: formatting and remote all-target check on hz3, recorded
2026-11-02 22:10:22 UTC (check 1533 seconds). The original scanner also
passed all 33 roots with zero critical findings. Neither result executes
the aging regression. The fresh six-target CLI run exited 101 on November 3
at 02:46:55 UTC: 253 executed, 251 passed, two failed, none ignored or
filtered. The complete GL-certificate (5), proofs (51), read-scope (11) and
robot-schema (2) targets passed; cli was 156/1 and closing 26/1. Those two
failures are detailed below. These are component results on e9dc, not a
full-repository pass or qualification of the later repaired main.

## 2026-11-03 — equity and custom-trace test integration

StormyLion reported three executed failures on origin `919ecf9b9` plus its
separate changes (Agent Mail 6285). Its changes did not touch the statement
or MCP paths in question. That is peer evidence on its stated source;
local execution against unmodified `e9dc06b77` independently reproduced the
two CLI failures: emitted 273/declared 274 with only
`equity_roll_forward_diff` missing, and the read-only comparison receiving
usage exit 2 for unsupported `--grant`. The separate whole-MCP attempt
reached its original 1800-second compile cap (remote 137 at 02:53:29 UTC)
before any test ran; it is neither a positive result nor a runtime
counterexample. Source inspection confirms these test defects:

- The binary event-coverage test never invoked the newly declared
  `equity_roll_forward_diff` event. It now runs the real comparison against
  an independently specified question and the identical retained source at
  equal frontiers, checking identical source IDs, movements and zero deltas.
  The declared-event set and its equality assertion remain unchanged;
  nonzero comparisons remain covered by the closing test.
- The closing comparison test used `statement --grant read`, although the
  verb does not register `--grant`. Moreover, unbound grants extend implied
  operations; that argument would not prove read-only authority. The test
  now issues an actual Human token holding only `read`, preserves its exact
  original output comparisons, requires precisely one admitted AccessEvent,
  and refuses certification with exit 7 and no further publication. The
  later replay/status/refusal head checks retain that post-read frontier.
  The supported read is exercised; the unregistered flag is not newly
  accepted, and no product authority or selector rule changes.
- The custom-trace MCP test compared its scalar `definition` input directly
  with translated JSON. The registry explicitly makes `--definition`
  repeatable, its schema accepts strings and arrays, and command translation
  deliberately canonicalizes repeatable flags to arrays. The test now
  requires that exact schema and canonical JSON and requires both forms to
  produce identical CLI arguments. Exact definition values, saved/direct
  frontiers, operation sets and host-path refusals remain checked. This
  admits only the already registered representational equivalence; it does
  not accept a different question or silently discard an argument.

These are authored test corrections, not additional product capability or
executed repair evidence. No registry, robot pin, gate, tolerance, test
selection or production implementation was changed to obtain a pass.

Independent source review (StormyLion, Agent Mail 6292; no build or test)
confirmed the event and MCP corrections and caught an omission in my new
token test: an absolute certificate path is forbidden by a token session's
host-file boundary. The token calls now use the actually retained `C:<oid>`
for both original sources; existing owner file-input comparisons remain.
No host-path restriction was relaxed. The access log must identify exactly
one `statement` read under the issued token's commitment, with the
original observed frontier and its precise recording sequence. The refused
certification must name FA-REF-011 and `produce`. The event smoke also
requires one USD unit and all 15 comparison lines, so an empty report cannot
pass its zero-delta assertions. These final review changes still await
native execution; the review is source evidence only.

The original e9dc full run retained its real compile-cap failure (remote 137
at 02:51:05 UTC, unchanged 1800-second limit). Once the local CLI failures
were reproduced and their corrections committed, I stopped the superseded
full driver and cooperatively cancelled only its verified Clippy child,
`rchw-7d933631-afb7-45eb-b85e-395daa9f15d8`. Recovery acknowledged terminal
delivery 143 at 02:57:26 UTC; the earlier daemon 130 remains recorded.
The original proof verifier then exited 0, binding a stable **RED/partial**
bundle with check exit 143 and note
`195fe69e527470161df6125b6715adc5abefb72b`. That proves integrity only; it
does not qualify a full pass or permit resume. No old-source MCP retry,
cap increase, cache manipulation or skipped assertion substitutes for
native execution of the corrected source.

## 2026-11-03 — Oklahoma prepared columns duplicate the intent account map

StormyLion's native probe147 on `dd0f177e5` plus its unrelated changes ran
the complete `legacy_migration` target: 28 passed, one failed (Agent Mail
6302). `oklahoma::public_oklahoma_activity_imports_all_source_legs_and_replays_certified_folds`
failed at actual `migrate import --action prepare`: usage exit 2,
`column_map must not contain a second account_map`. The importer explicitly
requires the intent's account map to be the only mapping. The authoring
helper instead put another identical map in `column_map.toml`.

The helper now emits column declarations only, keeping the existing native
intent mapping and importer refusal intact. The existing complete-package
test decodes the actual prepared TOML with the standard-library parser and
requires exactly its nine declaration fields. Before changing the producer
(blob `90d4cd80b2cf7f0ab1c644618550a82228637682`), the whole 17-test helper
suite exited 1: 16 passed and only that strengthened test failed on the
extra `account_map` table. After the two-line producer correction, all 17
passed with exit 0. No original assertion or test was removed; source bytes,
row-index checks, exact monetary controls, no-overwrite behavior and the
five output artifact names remain unchanged.

The peer result is native evidence on its stated source, and the local
before/after results are helper-unit evidence. Native migration of this
corrected output and the required full gate are still pending. The frozen
`0ee1cb11` compile/MCP runs started before this change and cannot qualify it.
The original `fa-yugf` epic remains open with its dependencies intact; this
integration contribution does not complete or bypass its case-study scope.

## 2026-11-03 — composed equity controls and the migration schema pin

On exact `0ee1cb11e5034e4dea524b5feec6f7899ff9ce47`, the whole MCP package
passed: 113 tests, zero failed/ignored/filtered, remote exit 0 at 03:24:08 UTC.
Its custom-statement trace case exercised the corrected canonical argument
contract. Tier 0's first cold check reached the original limit (remote 137
at 03:31:20); one identical source/worker/profile/all-target retry reused
completed dependencies and passed, fmt 7 seconds/check 16 seconds, exact
tree `4ac5a5149cae59ceb855aa65b96de40193a437fe`, note 03:36:06 UTC.
The first failure remains recorded; neither budget nor gate changed.

The six complete CLI targets on that same source exited 101 at 04:13:54 UTC:
253 executed, 251 passed and two failed, none ignored/filtered. The main CLI
target now passed all 157 cases, including actual equity-comparison event
emission. Closing was 26/1; GL certificates 5/0, proofs 51/0 and read-scope
11/0 passed. Robot schema was 1/1. These are different failures from the
earlier e9dc run, not a reclassification of its failures.

- The equity comparison passed its new token/output/AccessEvent/refusal
  checks and then reached a later invalid control call, `tb --certify`.
  It received usage 2, `no periods selected`. That control needs a valid
  native trial-balance certificate to test rejection of the wrong report
  family. It now explicitly selects the fixture's FY2026-P03; all original
  wrong-family expectations remain. The shared runner also forwards every
  nonempty child stderr, which it previously captured without forwarding;
  successful JSON responses are not dumped. No accounting amount, authority
  rule or expected success/failure code was relaxed.
- The actual byte-pinned schema test failed at byte 220848. The registry
  and native migration producer already include
  `dimensions:[batch_plan_dimension]`, but the saved `legacy_migration_leg`
  shape still had four fields and its old description. The replacement is
  one explicitly authored JSON data record: that description and appended
  dimension field only. A unique literal replacement preserves every other
  byte, event, envelope value and shape. It is not output regeneration or a
  broad source transform. The old fixture remains in reachable 0ee and in
  the actual failing run. Its SHA-256 is
  `68d1240e29a2851ba9329930ee35f1a6e2aaf52c17040ac9aad2c82e60bb27a8`;
  the new value is
  `c66f0c8c97d72728c3572589da26b956fb9afed5c31e1fc306589ba8309f77ee`.
  After authoring, comparison against the retained actual binary output
  confirmed exact byte equality and only that named shape's semantic delta.
  The byte-equality and one-envelope test functions remain unchanged; a
  different field, value, event or envelope still fails them.

Native execution of the explicit trial-balance control and the new saved
pin remains pending on the final source containing the Oklahoma correction.
The earlier component and compile passes do not qualify that later tree,
the full repository or the original broader Beads acceptance.

**Subsequent execution, 05:07 UTC:** frozen
`ac419fca4ab762fa26b295cf8eb60b887f87f369`, tree
`020163f548e5a979a4bb3641d8f0486d0ce8fca9`, passed all seven complete CLI
targets: cli 157, closing 27, legacy_migration 29, GL certificates 5, proofs
51, read_scope 11 and robot_schema 2. All 282 cases passed, with none
failed, ignored or filtered; remote and frontend exit 0. This includes the
actual Oklahoma prepare/import/replay, the explicit wrong-family control,
the schema pin, and historical aging. The first identical attempt reached
the unchanged 1800-second compile limit before executing tests; its 137
receipt remains. The continuation kept the same source, worker, profile,
targets and limits. Exact-tree Tier 0 also passed. The original full proof
on this tree is pending. Concurrent canonical merges and subsequent work
are different sources, and receive none of these qualifications.

## 2026-11-03 — control writes ignore the required-rehearsal caveat (fa-d48q)

The registered live `requires_dry_run` caveat promises a rehearsal before
any requested write commit. Posting and automatic reversal paths check it,
but ordinary shared control admission did not, and approvals, uploads and
bank-match confirmations also bypassed that shared admission. Existing
control previews are not, by themselves, an implemented admission protocol
for this caveat.

The selected repair is the Bead's fail-closed option (a). Shared ordinary
write admission refuses the explicit caveat before observing storage.
Approvals, uploads and bank confirmations invoke the same check on their
separate paths. The posting kernel explicitly retains its existing base
authority checks and verified posting-plan protocol; that entrypoint cannot
exempt a non-Post operation. Nonpublishing source factories retain posting
authority checks without falsely being admitted as control commits. Pure
proof-bundle production uses Read/Produce admission and its existing whole
book reach. Read admission and mandatory access receipts remain separate.
The refusal names `requires_dry_run` and explains the
supported posting-plan path and the unsupported control path.

Six tests in the existing operator-token target exercise issued, holder-bound
authority: flagged close, legal hold, approval, issuance and upload must
refuse without advancing the head, paired unflagged authority succeeds,
and flagged read plus posting rehearsal and verified commit still work.
Issuance is tested through the native Book API; the other requests use the
ordinary CLI handlers. The policy test covers every registered operation's
unrehearsed admission. The existing native bank-match harness also tests a
flagged confirmation over real retained sources, unchanged head on refusal,
and a paired ordinary confirmation with the exact original entry reference.
An additional native Book test produces a real proof bundle under the caveat
without advancing the head.
These are authored tests, not execution evidence;
native execution, any old-code counterexample, and full qualification of
this newer tree remain pending. The original Bead stays in progress.

**Subsequent evidence and review.** The whole policy package on exact
`a6b66f44d2f9d56bf62390db1c18b1855016f410` passed 57 tests (43 unit,
9 registry/property and 5 engine/oracle differential cases), zero failed/ignored/filtered,
remote exit 0 at 05:46:52 UTC. Its first development dispatch on hz3 was
refused before Cargo by namespace initialization status 73/Killed, frontend
103. Ordinary recovery acknowledged that exact preparation's terminal
exit 1. One supported hz4 fallback executed the unchanged command at the
original 1800-second cap. This development result is not Tier 0 or a full
repository verdict, and it does not qualify subsequent source corrections.

Independent read-only review 6333 found substantive gaps; no code was run
by that reviewer. Single and replacement PostPlans still encountered raw
commit admission, so a required-rehearsal capability could plan but could
not commit them. Setting an arbitrary native OID would be wrong: these
plans retain graph certificates and deliberately leave Entry.plan_certificate
empty. The repair instead uses a private verifier token, constructed only
after authenticating the plan and exact capability. It discharges only the
rehearsal prerequisite. Normal authority, policy witnesses, production law,
effect/entry/period/epoch comparison, and atomic certificate/CITES retention
remain required. A real native regression exercises single and replacement
publication, corrupted authentication, unchanged head on refusal, exact
retries and graph retention.

The review also found unmatch and retained findings/certificate/report-artifact
writes bypassing shared intent admission. These now use the same guard;
scenario/draft/close artifact retention refuses before replay at its public
boundary too. Paired native regressions cover unmatch, findings and retained
reports. Draft/scenario creation and discard, and other journaled rehearsal
controls, conservatively refuse the explicit caveat: a draft's journal record
is still a write. Some control previews share this unsupported admission;
they are not claimed available under the caveat. Pure reads, proof export
and supported posting rehearsal remain distinct.

The existing scheduled-admission test had accepted a sweep that blocked
every reversal but still published its cursor under the caveat. Its original
flagged row is now a separate, stronger assertion: FA-REF-011/exit 7, no
reversal and no head advance, including no cursor. Original ceiling/class
rows remain, as do the ordinary sweeps elsewhere in that suite. No test was
removed or ignored and no assertion/tolerance/budget/lint policy was lowered.

The original ac419 full gate passed its complete workspace check (1530
seconds) and then actually failed Clippy on five redundant borrows in the
new equity event test. Removing those borrows preserves every expected
value and assertion. A separate previously reviewed chunks_exact-to-as_chunks
test correction is also applied with the same ignored-remainder semantics;
it is source correction, not a lint exemption. Further obsolete-source tests
were deliberately stopped after the genuine Clippy failure: only the owned
driver and exact fa.lib child were stopped, ordinary cancellation/recovery
acknowledged delivery 143 (the daemon's earlier 130 remains recorded).
The original verifier exits 0 after recovery for stable **RED/partial** note
`82ff122f30cef96bfc0f351ccfac739256ebfeed`. Integrity is not a PASS or resume
authority. Native and full qualification of this newer correction remain
pending; predicted failures from source review are not executed counterexamples.

## 2026-11-03 — Native replay and equity fixtures failed on their actual contracts

The original native run on f6a34cf8 executed all seven selected harnesses:
1,451 passed and four failed, with no ignored or filtered tests. The facade
library contributed 705 passes and four failures. All 15 original fa-d48q
acceptance cases passed; this does not qualify later intake changes or the
whole repository, and the Bead remains open.

The migration-fragment negative still refused, but the newer source-storage
closure message omitted the specific noun its existing assertion required.
The production message now names migration body fragments and migration
source storage; its predicate, code, exit and test assertion are unchanged.

The reopened custom-epoch fixture called synchronous replay with its retained
native history still outside the loaded window. It now invokes the existing
authorized `prepare_report_history` seam, as the report host and the adjacent
historical-context fixture do. Added assertions require the cold window to
become readable without advancing the head. Native history, registry-source
validation and every original exact-output assertion remain required; no
empty-population escape or retained-history exemption is introduced.

The equity zero-interval fixture incorrectly expected an extra `post`
permission to change an original source certificate. That source format
contains accounting inputs; producer capability is a field of the comparison
certificate. The corrected fixture checks source-byte equality and the actual
comparison capability commitment. It preserves both original distinct-source
refusals using a canonical, rehashed source with the same request, native
inputs and statement amounts but omitted movement provenance. Explicit
same-header assertions keep that negative independent of scope mismatch.
No production comparison guard or durable format changes. This admits the
valid deterministic recertification while retaining rejection of different
originals at one recorded frontier, including decode-time rejection.

These are authored repairs, with native re-execution and full qualification
pending. The fourth failure, the FA-ART-LAB-04 witness mismatch, remains red;
its hashes are unchanged while a bounded symbol-addition attribution probe
runs. The original failure and all source boundaries remain retained.

## 2026-11-03 — LAB04 witness drift attributed to three added symbols

The original f6a34cf8 run and the repaired 75a4d58e library run both reached
the unchanged LAB04 pin mismatch. On 75a4, all three other facade repairs
passed: the complete library ran 709 passes and one failure, with no ignored
or filtered tests. Its exact-tree Tier 0 also passed. Those results do not
make the full repository green: its check and Clippy steps did not execute
after worker initialization refusals.

The attribution control starts from clean 7796e910, the old witness source,
and overlays only `fa-model/src/symbols.rs` and `registries/symbols.toml`.
Their entire diff is MigrationRunFragment=63, MigrationSource=64 and
MigrationSourceFragment=65. Cargo manifests, lockfile, toolchain and
foundation pins are unchanged. The original Genesis producer and every
accounting, crash, retry and live-versus-lab assertion are unchanged.
Its automatic RCH source identity ends in overlay fingerprint
489a60f0bd347273da7353d012a825f8164d7e52f316c99c31fb12d71666ed10.

The first attempt hit the original 1,800-second compile cap before execution.
One identical continuation on the same hz4 worker executed the original
36-run campaign and failed its old pin, as intended: zero passed, one failed,
680 filtered. Its structured witness exactly matches f6: the same seed-list
SHA-256, 36 schedules, one explored schedule class and all 36 observed
BLAKE3 values. The counterfactual therefore attributes the changed witness
to those declared symbol inputs, rather than to an accounting change hidden
by replacing expected output.

Only LAB04's observed hash vector and witness-source commit are updated in
its existing manifest and registry row. Seeds, run count, schedule count,
producer command, schema, all assertions and every other artifact stay fixed.
The source is f6a34cf8, which actually produced these fields; that is not a
claim that its whole library or repository passed. The old complete manifest
and registry remain in Git blobs fd05cb4aa40be961e1f4eb6f75cdd1cc3e2d8390 and
6e0d6c5eb95a78ffdde34ed334e1e569cbd3199e, with verified recovery copies retained.
The original red logs are retained too. The updated producing test must
actually pass before the campaign is reported repaired, and final-source
repository qualification remains separate. This is witness maintenance,
with no performance or new product-capability credit.

The actual `registry-check` binary target on e77291cb then ran sixteen
passes and one failure. Its first workspace error was the LAB04 manifest's
enclosing file checksum: ba398bfe updated the attributed vectors and source
but omitted that binding. The registered BLAKE3 still said
70c24c236480b7604b0a03bfb8fdcc4371c4fc68d639960af8fadf37cee3c051;
the unchanged validator read the manifest bytes and computed
c94e2b217c4160129937fb85ca4232355cf0290f0103d9ce07b2f47622c53def.
Only that file binding is corrected. The manifest itself, every campaign
vector, source commit, seed, count and oracle stay fixed. This omission was
mine; the original sixteen-pass/one-failure execution remains retained.
The binding repair does not establish a passing campaign or registry gate:
both still require their actual repaired-source executions. The registry
gate had not reached the later prose-claims checks when it refused here.

## 2026-11-03 — Cash-flow prefix admission needs both dispatch stages

The issued-token regression first ran on clean 2bc74616 plus only its new
test. It failed at its first positive request: a read-only token pinned at
sequence 7 requested that same prefix, but `fa gl cash-flow` refused with
FA-REF-011, exit 7, because the bound command reached the whole-book HEAD
default. Exactly one case executed and failed; eleven were filtered.

The initial handler repair in ff6632ec was incomplete. The complete
read-scope target on 0b9315dd ran eleven passes and one failure, with no
ignored or filtered tests, and the same first positive cash-flow request
was still refused. I had extended the report handler's complete-prefix
admission without extending the earlier verb-registry dispatch rule.

The existing judged-prefix `gl` rule now includes `cash-flow`, matching
the report handler. The earlier certification rule still requires Read
and Produce and whole-head admission. The real binary regression keeps
its original success, exact amount, temporal and non-temporal refusal,
AccessEvent and current revocation assertions. Neither failed execution
is reported as a repaired-source pass; native re-execution and full
repository qualification remain required.

The registry completion in d9bcce3b admitted the first historical explicit
report with its exact 5.00 USD result. The full target still ran eleven
passes and one failure: the next out-of-scope request named a missing
policy, and launch-file containment checked its existence before the
handler could refuse the token's implicit HEAD read. It returned usage 2
instead of FA-REF-011/7. The earlier claim that handler admission preceded
host input therefore did not cover this dispatch-stage filesystem check.

Plain complete-prefix GL reads now admit current authority and their
requested reach before launch-file containment. They use the existing
known-at parser and pure scope checker; the scope check itself does not
resolve an implicit HEAD. A shared predicate keeps that preflight and report
handler aligned. The pending AccessEvent remains for the admitted handler
open, so a refusal records no read and a successful logical read records
once. All original assertions stay, and missing-policy refusals now cover
account, period and effective scopes too. Certification retains its prior
whole-head rule. This further repair still requires native re-execution.

## 2026-11-03 — Strict Clippy rejects a migration fixture's copied slice

The fresh full repository run on 39f088a7 passed its workspace compile
step, then Clippy actually ran and returned 101. Its single error was
`cloned_ref_to_slice_refs` in the migration-source Genesis fixture: a
single original payload was cloned solely to supply an immutable slice.
The call now uses `std::slice::from_ref(&original)`. The package builder,
payload, source-admission refusals, immutable-binding checks and every
test assertion are unchanged. No lint setting or gate changes.

The original failed run is retained and cannot qualify as a passing full
verdict. The earlier complete Genesis target passed 382 cases on e77291cb;
that does not establish repaired-source Clippy or final full acceptance.
The frozen 39f run was later stopped after its queued wrapper was cancelled
and acknowledged. Its checksum-bound result is stable RED/partial, exit143;
it cannot supply passing evidence or resume authority. The correction still
requires its own exact-tree checks.

## 2026-11-03 — Historical symbol fixture retained later labels

The complete model library on 11305bf3 ran 76 passes and one failure. Its
pre-close compatibility fixture removed CloseTask=62 and DEPENDS_ON=38
from today's table, but retained migration labels 63–65. That combination
was never a released table, and the unchanged production checker refused
it. Comparison with the actual registry immediately before 94ef9dae0
confirms 59 labels ending at AssetSchedule=61, the same 60 properties,
and the same 37 earlier relations.

The positive fixture now uses that historical label boundary. Every
existing incompatibility assertion remains, and the formerly misclassified
gapped table is an additional negative. Production compatibility, durable
formats, digests and gates are unchanged. The original 76-pass/one-failure
run is retained; repaired-source native execution and final gates remain
required. This is fixture maintenance, not a new compatibility profile.

The fixture also freezes the actual historical digest
f0701f31f43ebf825e62d202d1aabc9fd64c9987617763e294ce499c6d26c104.
It was computed separately from Git revision 2c6225ced's registry: render
the three namespaces in name order, prepend the existing fa:symbols:v1
domain, then BLAKE3 the resulting bytes. This extra assertion prevents a
future change to today's property or relation table from silently changing
the purported historical fixture. It introduces no product dependency and
does not replace any existing pin. The 77-pass result on b834a15c precedes
this additional assertion; the strengthened fixture still needs execution.

The next complete strict Clippy run reached a second inherited instance
of the copied-slice pattern: the legacy migration approval-group fixture
at approval_groups.rs:164, introduced in f543eae8b. The b834a15c run
returned 101 after 1473290ms; this was its sole emitted error. The group
builder accepts an immutable string slice, so it now borrows the existing
digest with std::slice::from_ref. The encoded input, malformed-member and
size-bound controls, zero-write checks and admitted approval stay unchanged.
No lint setting changes. The workspace pattern search is retained as review
evidence; unrelated custom-type clone sites are not mechanically rewritten.
The actual b834 Tier0 passed and its model library passed 77 tests, but
neither establishes strict-Clippy success for the repaired source.

An unchanged-b834 strict run with --keep-going then completed with 101
after 78308ms. It emitted the approval-group error and two additional
chunks_exact_to_as_chunks errors in closing/functional.rs:326–327,
introduced in e8a20dee1. The closing fixture now iterates typed two-leg
arrays, retains both original dimension assertions, and additionally
requires empty remainders and equal intent/preview pair counts. Thus an
unpaired or unpreviewed leg cannot be silently skipped by the test. The
closing amounts, basis version, replay, verifier and bundle assertions
are unchanged. The diagnostic kept strict warnings and every target;
the original full repository gate is unchanged and still required.

## 2026-11-03 — Long PDF reports silently omitted their trailing rows

The canonical renderer stopped when a table row crossed the first page's
bottom margin. Later accounts and the TOTAL row were omitted even though
the PDF carried the complete IR digest. Raw pipes and line breaks in account
names could also split Markdown rows and shift the amount columns.

The reviewed two-file fix from e533b273b now continues tables on later pages,
repeating their unit line and headers. It retains the first page's object
numbers and the existing one-page byte pins, and escapes Markdown cell data.
New regressions draw all 120 accounts plus TOTAL across three PDF and PDF/A
pages and preserve Markdown column delimiters. The in-tree PDF/A validator
remains the validation boundary; no external PDF/A conformance claim is made.

Both canonical preimages exactly matched that commit's parents before its
patch was applied, and both resulting source blobs match the reviewed commit.
The peer reported old-code failures and 62 repaired-source passes. Those are
peer results; this combined source still requires its own native and full
qualification. The original renderer bead fa-cet is reopened with its original
acceptance and historical cross-machine evidence preserved.

The combined candidate 4887e49e1fc18e48203dcae72777d653c257ba61 subsequently
passed Tier 0 on its exact tree and all 1,693 cases in the six-library,
seven-integration-target native run. The first native attempt reached its
original cap and returned 137; the identical continuation completed with 0.
The complete model library includes the strengthened historical digest
assertion. These results do not qualify the later b2dc173b3 merge or supply
the renderer's original cross-machine acceptance or a full Tier 1 verdict.

## 2026-11-03 — GOLDEN-CHANGE: migration symbols change certificate inputs

The unchanged cross-target target on 39f088a7 actually ran one pass and
one failure. Its fold, report bytes, exact arithmetic, allocation and FX
checks passed; three certificate hashes and the bundle hash differed.
The planted target-dependent encoding negative also passed.

The clean historical baseline a68f7f007 reproduced all eight previously
measured digests. It retained its older expectations and therefore still
returned 101. Sealed counterfactual abcb8dad1158725d388a6b20ac35eb0a67c78858
adds only compiled labels 63–65 and their registry rows to that baseline.
Its unchanged test reproduced all eight 39f digests, again returning 101
against the retained old expectation. Only the three certificate digests
and bundle digest move; the four fold/report-byte digests do not. Original
capped attempts and both complete one-pass/one-failure controls are retained.

The four metadata pins now reflect that attributed input change. Their old
values were 5db0d090…, f58eada5…, 4a13915e… and 1054c7ea…; new values are
82ff1447…, 69fe5d7b…, f5d6a23a… and abb3ff02…, respectively. Full vectors,
source identities and log checksums are retained in the external
cross-symbol-causal-20261103/actual-eight-vector-comparison.json receipt.
No arithmetic, fold/report-byte assertion, planted negative, production
predicate or gate changes. This is metadata-fixture maintenance on x86_64;
the corrected source still needs execution, and aarch64 remains unrun.

## 2026-11-03 — Four new refusal classes were absent from the harness partition

The peer's retained probe152 downstream run reached all existing refusal-fix
cases, then failed the catalog partition at FA-REF-203: one pass, one failure,
remote exit 101. This was a missing partition entry, not a failed application
of a tested fix. Codes 203–206 had been added without either a single-step
case or a documented multi-step reason.

The existing non-single-step list now names these four classes and their
case-disclosure/key-lifecycle fixtures. No previously triggered code is
excluded, no test or assertion is removed, and the unknown-verb and unchanged
refusal controls remain. All catalog entries still must be partitioned.
The admitted set changes only by these four explicit multi-step reasons;
it does not count them as executable fixes. fa-wgsj is reopened for this
reproduced regression, retaining its original acceptance. The corrected harness and referenced native workflows
still require execution on the final source.

## 2026-11-03 — Escrow mutations targeted an unused availability copy

Source inspection confirms fa-escrow's advertised balancing-availability
function had no kernel caller. The kernel used separate capacity formulas;
MUT-032/033 mutated only the unused copy. That copy also returned None on
bounded arithmetic overflow, which the kernel interprets as unbounded.
The live formulas instead return zero for exhausted bounds and clamp only
the final capacity to one representable request.

The live formulas now reside in fa-escrow and serve kernel balancing and
refusal hints. Kernel behavior is preserved; the previously unused public
helper now has the same bounded-overflow semantics. The two existing
mutations target those live formulas, retain their original killed-by test,
and additionally name the kernel's existing capacity test. This retarget is
not a completed mutation campaign: baseline execution and actual kills are
still required. New controls cover both normal signs, exhausted and
unbounded directions, overflow and cancellation. The old byte-length-only
test now calls balancing_request; an additional test decodes signed wire
extremes and refuses every truncated length plus oversized payloads.
The only added dependency edge is test-only access to the existing first-party
fa-time crate for the EntryPayload fixture. The facade's unused direct
fa-escrow dependency is removed; its journal dependency consumes the law.
No timed-hold anchor or plan change is included; the original fa-yysv
remains open.

## 2026-11-03 — CLI fixtures still excluded newly supported report and import modes

The complete CLI target on 4a085aa0 ran 154 passes and four failures. A
dimension fixture still expected usage exit 2 for certified functional
dimension reports, although the registered v13 profile now succeeds. Two
balance-sheet solvency fixtures pinned version 2 after 37f0c685a changed
the actual procedure and registry to version 3 for effective-date selection.
The event fixture omitted functional_dimension_trial_balance,
migration_import_group_staged and migration_import_progress. It observed
no undeclared event. These are observed fixture/contract mismatches, not
authority to weaken a production predicate.

The dimension fixture now exercises the supported profile with exact
84.00 USD, the original hierarchy, certificate linkage and byte-identical
replay from both file and retained ID. Unknown dimensions and unsupported
summary combinations still refuse, including functional plus summary.
The event fixture executes a nonempty tagged functional fold, a group
refused for missing native approvals with zero recorded chunks, and an
approved grouped retry preserving the exact original receipt. Every old
success still requires exit 0, and exact registry/event equality remains.
The two solvency version literals become 3; the deficit, citations, replay,
historical-assertion and unchanged-finding assertions remain intact.

The admitted fixture profile is now the implemented functional dimension
mode; unsupported combinations remain excluded. No monetary amount, gate,
registered procedure or production authority changes. The original failed
run is retained and the repaired complete CLI target still needs execution.
In the same run, cross-target passed 2 and restatement passed 12 cases;
refusal-fix execution passed 2, applying 41 of 154 codes and explicitly
documenting the remaining 113. These passing targets do not turn the
four-target invocation's actual exit 101 into a passing repository verdict.

## 2026-11-03 — A new event-fixture posting invalidated an earlier empty-book policy

The complete four-target packet on d0861d2e2 exited 101: cross-target
2 passed, restatement 12 passed, CLI 157 passed and 1 failed, and refusal
fixes 2 passed, with no ignored or filtered tests. The newly exercised
functional certificate and both solvency version fixtures passed. The
event fixture failed earlier than grouped staging: its new tagged cash
posting preceded existing cash-flow policies with empty assignments.
The direct cash-flow command correctly refused FA-REF-100, exit 2,
because the selected cash leg was unclassified. This was a fixture
ordering error introduced in the repair, not an accounting-law defect.

The same tagged posting and all its nonempty functional-report assertions
now run after the existing book's earlier workflows. The original cash-flow
policies and exit-0 requirements are unchanged, as are the grouped-stage
approval, zero-publication and exact-retry checks. No production predicate,
amount, refusal, gate or registry changes. The reordered complete CLI
target still requires native execution; the prior 157 passes do not
qualify its previously unreached grouped-stage checks.

## 2026-11-03 — The reference clock rejected recovery before its first corroborated tick

Source review of the remaining fa-yysv time-axis concern found that the
reference oracle imposed an extra `observed_utc_ns >= prev_anchor` condition
when calculating corroboration. The kernel permits an honest first baseline
at or before a previously recorded uncorroborated instant. The oracle instead
treated an earlier honest reading as uncorroborated and rejected it against
that future instant, so a differential could disagree about clock recovery.

The oracle now applies the registered forward-skew bound to the saturating
elapsed interval; ordering still compares against the last corroborated tick.
Matching reference and kernel controls exercise earlier and equal first
baselines, reject a repeated trusted instant without publication, and admit
the next honest tick. The kernel test retains the original uncorroborated
record byte-for-byte. No kernel admission, hold-anchor policy, registered
skew limit, original test or gate is weakened. Native execution and the
old-predicate negative control are pending; source agreement is not a pass.

Execution update: the complete fa-reference library at fb6d93f00 passed 34
tests. Restoring only the old predicate in a6c30e915 compiled and produced
33 passes and the intended earlier-baseline failure. These ran on different
x86 workers; they do not qualify the incomplete wider journal campaign or
change the unresolved timed-hold bootstrap policy.

## 2026-11-03 — A late-ready transport result could hide the request deadline

The client checked its absolute deadline before polling the socket operation,
then returned that poll's result directly. Rendering a large request can
consume the remaining budget inside one poll. A subsequent immediately ready
I/O error could therefore win after expiry; the recorded loaded-worker case
returned BrokenPipe instead of SendingRequest timeout. A late success had
the same result-ordering gap.

The same Deadline now checks its existing clock before accepting a Ready
outcome. Newly classified as timeout: completion observed at or after the
unchanged absolute deadline. Within-budget successes and failures retain
their original results. This does not preempt synchronous work within a
poll. The original 3-second peer watchdog, 300-ms backpressure deadline,
32-MiB frame and every existing socket assertion are unchanged.

Deterministic TimerDriver/VirtualClock controls cover both outcome classes,
all three transport phases and observations before, at and after expiry;
an already expired deadline must not poll the operation, and registrations
are released. Native execution and a restored pre-poll-only fault control
remain pending. No gate or timeout limit has been increased.

Execution update: precheck-only control f89a5f51f compiled and the late-ready
test failed with Frame(Truncated) instead of Timeout. The unchanged client
component at b932d46fa then passed its entire 82-test library, including both
new deterministic controls and the original socket/backpressure tests. Its
overall multi-target invocation remained red for three other assertions.

## 2026-11-03 — Migration closure control expected an obsolete diagnostic

The unfiltered native facade library on b932d46fa compiled, then
`migration_fragment_closure_is_exact_and_legacy_prefixes_remain_replayable`
failed at context_tests.rs:381. The forged certificate was refused; the
assertion still required "omits migration body fragments". Production's
source-closure guard now covers canonical Entry storage as well as migration
storage and emits a different, fixed diagnostic. No production validator is
changed to accommodate this fixture.

The control now requires that exact current diagnostic, FA-REF-150, exit 8
and an unchanged book frontier. Its valid-fragment replay, query/snapshot/
duplicate corruption negatives, and original-prefix replay remain. This
admits the intended closure refusal while continuing to reject a different
failure class, diagnostic or publication. The repaired native test still
requires execution; the observed failed invocation is not a passing gate.

## 2026-11-03 — Retire the proved storage-gap refusal after its replacement ran

`schema_valid_bulk_entry_exposes_native_row_capacity_without_partial_publication`
captured fa-fdt's old defect: 512 schema-valid legs encoded to 24,497 canonical
bytes and needed a 27,875-byte row against the unchanged 16,384-byte substrate
limit. It executed twice on 3d1fe2a7e; the complete Genesis target passed 382
tests. That source, native transcript and verified recovery pack are retained.

The repaired Entry representation has now executed its replacement acceptance
on b932d46fa: `large_entry_certificates_bind_fragments_and_replay_offline_after_reopen`
passed within the complete 58-test facade statements target. It posts the 512
legs once, preserves canonical bytes and retry identity, compares maintained,
rebuilt and literal folds, rejects missing/reordered certified fragments,
reopens the disk book and independently verifies the bundle with fa-verify.
The old refusal test's own instruction was to replace it after this acceptance.

Only that obsolete gap test is retired. Newly admitted: schema-valid large
Entries whose immutable fragments fit native rows in one original publication.
Still refused: unbalanced entries, changed-payload key reuse, corrupt or
restored fragments, and noncanonical or incomplete verification closure. The
kernel entry-storage controls remain, including the stronger original-key
conflict check; their final complete Genesis run is still required. No schema,
capsule or row limit, verifier, gate, timeout, amount or publication law changes.
fa-fdt remains open behind its original fa-nd7g dependency; neither the broad
object-layer acceptance nor the full repository gate is claimed complete.

## 2026-11-03 — Retained verification examples used uncited claim-class wording

The unchanged native registry checker on 772e78d60 ran 16 tests successfully
and failed `real_workspace_registries_pass`: the README's new portable-report
paragraph called its retained bundle a "proof" without a live claim citation.
The related BLMIS paragraphs also called their retained execution record
"measured" and their offline verification "proof verification".

These are now a verification example, a retained execution record and offline
verification. The documented inputs, command, verifier-check counts, source
pins, interruption history and tamper refusals are unchanged. No proof-class
artifact or citation is invented, and no linter, gate or requirement is relaxed.
The next native run again completed 16 tests successfully and failed the same
workspace check, now at `docs/blmis_magnify_workload.md` paragraph 56. Review
found the same ambiguity in the related public-ledger and format execution
notes. Those now distinguish accumulator proofs, signed verification bundles
and execution records, and describe recorded durations without claiming a
qualified performance result. Commands, counts, hashes, numeric durations,
source links and limitations remain intact. The claim checker is unchanged.

The corrected source then passed the unchanged complete native registry
target: 17 passed, zero failed, ignored or filtered, remote exit 0 at
23:10:50 UTC. The independent docs-sync command exited 0 with all four checks
passing. These source checks are documentation maintenance; the full
exact-tree repository gate still requires execution.

## 2026-11-03 — GOLDEN-CHANGE: EntryFragment symbol changes certificate inputs

The complete native cross-target executable on b932d46fa ran both original
tests: the planted width/endian negative passed and the eight-vector test
failed at its old trial-balance certificate pin. Its actual output preserved
the register fold and all three canonical report-byte digests; only the three
certificate digests and the evidence-bundle digest changed.

Strict inverse b24313f3ea21456faea9acb590ba96e5186182bf has exactly two changed
files against b932d46fa: remove EntryFragment=66 from the registered namespace
and compiled SymbolTable, keeping the label constant, all storage/runtime code,
fixture inputs and old digest assertions. Its unchanged original executable
then passed both tests, zero ignored or filtered, on vmi1149989/x86_64:
remote and wrapper exit 0, 23:23:30 UTC, 1,324,258 ms. All eight old vectors
were restored. An earlier identical attempt reached the original 1,800-second
compile cap and exited 137 before running any test; that failed attempt remains
separate. Namespace initialization failures likewise supply no test evidence.

Only the four certificate/bundle pins are updated to b932d46fa's actual
output. The fold/report-byte pins, arithmetic/rounding/allocation/FX checks,
repeat-execution comparison, eight assertions and planted encoding negative
remain unchanged. The inverse is diagnostic recovery material, never product
code; its verified recovery pack and both native transcripts are retained.

This maintenance admits the same fixture with its actual symbol-66 namespace
commitment and continues to reject changed canonical digests and the planted
target-dependent encodings. It changes no accounting result or acceptance
threshold. Corrected-source native execution and exact-tree Tier 0/Tier 1
remain required; aarch64 remains unrun and fa-9p1c remains in progress.

## 2026-11-04 — Lifecycle fixture declared a retired assertion-drift version

Commit 6857b70cf upgraded `recon.assertion_drift` and the lifecycle fixture's
capability selector to v2, but left `lifecycle-D-01`'s explicit `version = 1`.
The original oracle test on 3fcd06ad reproduced the defect: one executed test
failed at fixture loading, with `DanglingKey` because
`recon.assertion_drift@1` is not a current registry row. Compilation succeeded;
430 other tests were filtered. Remote/wrapper exit 101 at 23:58:29 UTC,
43,564 ms. This is an actual fixture failure, not a compiler or zero-run result.

Only that explicit version becomes 2, agreeing with the existing selector and
registry. The 20,000-minor-unit expectation, scale, Critical severity, account,
attestation and period citations remain unchanged. The strict loader and all
original tests remain intact. A read-only search of 21 fixture files and 19
procedure/version rows found no further selector mismatch; that search supplies
no native procedure qualification. The corrected oracle and CLI case consumers
still require execution.

The earlier full 3fcd run was deliberately interrupted after formatting and
143 Python unit tests passed. Its exact RCH check child was cooperatively
cancelled and acknowledged with exit 143 before the driver was terminated.
The capture then failed independent verification because it never reached
`QUALITY GATE RED`; the wrapper exited 2. Its raw logs are retained, with no
published valid verdict or resume credit. The separate original Tier 0 reached
its unchanged 1,800-second compile cap: remote 137 after 1,804,185 ms, format
PASS/check FAIL, wrapper 1. Neither result authorizes a fold, push or closure.

## 2026-11-04 — Reconciliation exposed authorization-order and coverage defects

The unlanded 953b25b candidate reconciled 05090127 with owner 7ebfffc2.
Its original unfiltered journal/CLI authorization packet compiled and completed
with exit 101: operator tokens 15 passed/1 failed, write authority 1/2,
bank matches 53/0, Genesis 391/1, and journal policy 81/1. The remote run
finished at 01:17:09 UTC after 1,396,260 ms. All five failures are retained;
the candidate was not merged, published or used to close a Bead.

Two original armed outside-scope controls failed with `entry class mirror:
None`: class-aware metadata admission inspected that mirror even for tokens
without a class caveat. It now reads the class mirror only when that caveat
requires it. Account and period guards retain their original behavior, a
class-scoped request still requires the actual valid class mirror, and an
unscoped consumer still detects the deliberately unreadable entry payload.
Neither armed control is edited.

`tb --certify` correctly refused a required-rehearsal token, but only after
the bound read's AccessEvent moved the head from 6 to 7. Certifying report
admission now rejects the unsupported publication before opening the book.
The original unchanged-head assertion remains; a certificate-file twin also
requires no output file. Ordinary reads and read-only proof bundles keep their
separate access-receipt contract.

The new class-scoped CLI fixture issued a close-only token although the actual
period route requires read and close, so a missing-read refusal masked the
class boundary. Its controller now holds both required operations; the exact
class-refusal, matching-class success and unscoped success assertions remain.
The write matrix also lacked the existing CloseRun start, step and run routes.
They now have rows, including the step-preview operation set; no writing route
is exempted, and the original coverage checker remains unchanged.

The separate 953b25b compile gate and policy/CLI packet reached their original
1,800-second caps with exit 137 before tests executed. They provide no compile
PASS or test credit. Corrected-source native execution, exact-tree Tier 0 and
the complete Tier 1 proof remain required.

The corrected 6b76ebdb candidate passed the exact-tree format/all-target compile
gate. Its complete authority packet still exited 101: operator tokens 15/1,
write authority 2/1, bank matches 53/0, Genesis 392/0 and journal policy 82/0.
Both original armed scope controls and the missing matrix coverage passed.
The CLI library separately passed 82/0; policy passed 45/1 because the added
Agent fixture tried to construct a forbidden Close capability. That fixture
now uses an allowed Post capability and keeps the Agent-on-trunk refusal.

The remaining class failure was a front-door whole-book judgment over an
unknown class, before the period handler's actual PeriodControl check.
Both bound-admission callers now supply that known payload class only for
period transition commands. Every other whole-book coordinate check remains;
the registry's scope rules are not exempted or broadened.

The remaining preview assertion incorrectly forbade the mandatory AccessEvent
required by plan §9.7 and the existing operator-token plan-delivery controls.
Its admission split is explicit: an ordinary read or period-plan delivery may
publish exactly its one access receipt, with the original principal, capability,
command and observed/recorded sequence. The complete Entry identities and
payloads and all period rows must remain unchanged. Missing, wrong or extra
receipts and accounting changes remain failures. The recovery preview keeps
its original no-publication requirement. A planted missing-receipt execution
and corrected native/full-gate execution are required before this test repair
can be treated as qualified; no missing receipt is a passing read.

## 2026-11-04 — Per-crate input hashes fabricated execution verdicts (fa-xrl)

On frozen commit `9bc4c99a27c1b30e9342e2f6b3e8923658e1aa8c`, the native
`fa-formats` test job exited 101. A separate invocation of
`scripts/crate_verdicts.py` with a new empty store nevertheless exited zero
and emitted `PASS` for all 33 crates, including `fa-formats`, plus ten
workspace steps that it never ran. Both fresh statuses and default step
statuses were hard-coded; a stored `PASS` needed no execution provenance.
The wrapper could publish that output as a Git note. No such note was
published by this probe. This violated doctrine 12 and the gate verdict
contract; hashing source inputs is not execution evidence.

The repair keeps candidate input fingerprints, reports every unexecuted
status as `UNRUN`, exits 2, and refuses verdict-note publication. It removes
the unauthenticated store interface and preserves existing stores and notes.
The report format is version 2 and output creation refuses an existing file.
The old producer's retained manifest and store remain negative evidence.
The admission split is entirely restrictive: the 33 unbound crate `PASS`
claims and ten invented workspace `PASS` claims are no longer admitted;
no authenticated execution result is removed, because this producer never
consumed one. The ordinary full repository proof remains authoritative.

The existing selftest preserves leaf-change, deterministic fingerprint,
registry-invalidation and external-input checks without calling them
execution or reuse. Added controls refuse false verdicts for broken Rust,
forged stores, unproved note publication and report overwrites. All nine
metadata/refusal controls and their integration into the existing local-proof
selftest passed in the external review copy. They are tooling tests, not a
native accounting test run. Original bead `fa-xrl` is reopened; real executed
per-crate reuse and cold-run equivalence remain unmet acceptance criteria.
Publication combined with selftest is refused before any child starts, in
both flag orders. A retained instrumented-child control observes an early
exec directly without recursively invoking the suite on regression.

## 2026-11-04 — Role oracle treated an undirected pair as ordered

The native Lantern target on `9bc4c99a27c1b30e9342e2f6b3e8923658e1aa8c`
ran 106 passing and two failing tests. In the role-renaming failure,
`jet.unusual_accounts` version 2 retained the same two account members,
citations, occurrence count and population. Only the pair's narrative order
changed after account renaming changed the native vertex-ID order. The
registered version-2 definition explicitly makes this pair undirected;
the algorithm serializes its members in native-ID order. The comparison
already normalized citation order but omitted this unordered narrative value.

The oracle repair maps accounts back to their original identities, then sorts
only this version-2 procedure's declared pair text. Every member, remaining
word, statistic, severity, citation, procedure identity and version remains
in the compared outcome. Both complete corpus comparisons remain in place.
The admission change accepts only equivalent ordering of this undirected
value. Added controls use an actual native procedure result: swapping only
the two displayed members is equivalent, while changing a member, value,
scale, population, severity, citations, version, narrative suffix, statistic
name or procedure ID must still differ. Native execution of these prepared
controls is required; formatting alone does not qualify the repair.
The semantic mutants start from an already canonical pair presentation,
so changing the procedure or version cannot differ merely by disabling
the pair-order normalization.
Production algorithms, registry versions and certificate bytes are unchanged.

The other failure expected 22 date-aware procedures. Comparing the registry
at the assertion's introducing revision `ea9ba4f71` with this tree identifies
exactly one addition: `recon.attested_register_compare` became date-aware in
version 2 (`748173064`). Its code consumes the optional cutoff in both claim
and instrument comparisons. The expected inventory is now exactly 23; every
undeclared procedure still undergoes the original strict date-invariance
comparison, and the corpus must still exercise a declared date-sensitive run.

## 2026-11-04 — Native reapplication shipped ahead of its reference model

The original generated-history differential on
`9bc4c99a27c1b30e9342e2f6b3e8923658e1aa8c` failed at seed
`0xe220a8397b1dcdaf`, step 232: the kernel committed a native reversal
that revived an application, while the reference model returned
`FA-REF-102` from its obsolete unsupported-reapplication guard. The target
ran 54 passing tests and this one failure. I extended the production law
without extending and qualifying the independent oracle first, contrary
to doctrine 11. The full repository gate caught the omission before
publication; its failing proof remains evidence and cannot authorize closure.

The repair derives prospective restored applications from the model's own
immutable reversal lineage and literal live-entry fold, using its independent
limb arithmetic. Each restored application requires a currently live target
and sufficient remaining capacity. No production applied mirror, delta map
or compare-and-swap implementation is reused. Refusal precedes journal
mutation; foreign-valued application profiles remain unsupported.

The exact differential comparison and original seed corpus remain unchanged.
A model test adds both receipt and payment orientations, four reversal
levels, cumulative capacity competition across two application legs,
successful retry of the same refused key after
capacity is released, and refusal when the source was reversed. Each refusal
must preserve journal length, monetary fold and open-item fold. These
prepared changes still require native model execution and the entire
original generated-history differential on the final candidate.

## 2026-11-04 — CLI fixture omitted live events and expected an old refusal reason

The general CLI integration target on frozen `9bc4c99a27c1b30e9342e2f6b3e8923658e1aa8c`
ran 156 passing and two failing tests. Exhaustive event coverage was missing
exactly `dimension_constraint_recorded` and `dimension_constraints`:
the handlers and schemas already existed, but the fixture never called them.
The repair records a real cost-center allowlist on account 6000, reads it
back, and checks its one row and exact allowed value before the existing
tagged posting. The final complete emitted-versus-declared set equality
remains unchanged. No event is removed or exempted.

The recovery test already required a read-only issued token to be refused.
Its exit 7 and `FA-REF-011` assertions passed; only its old blanket
launch-surface message assertion failed. The actual path names the missing
`schema_change` operation before recovery observes book contents. The test
now requires that specific missing-operation reason and immediately checks
that the refusal published no sequence. The existing confirmation refusal,
final unchanged-head assertion, successful authorized previews, stale-basis
refusal and covered-book no-op assertions remain.

This admission change accepts the precise earlier authorization refusal in
place of the old blanket refusal text; it admits no successful reader-token
recovery. Production authority and recovery behavior are unchanged. Both
original test names and the complete CLI target still require native
qualification on the assembled candidate.

## 2026-11-04 — Dimension refusal omitted from executable fix coverage

The original refusal-fix target ran one passing and one failing test on
`9bc4c99a27c1b30e9342e2f6b3e8923658e1aa8c`. After executing its existing
cases, the exhaustive catalog assertion found `FA-REF-207` absent from
both real triggers and the documented non-single-step exceptions.

The repair adds two native CLI cases: a declared value outside an account's
allowlist, and an explicitly forbidden value with no allowlist. Each
restriction is isolated, so ignoring either policy rule makes its own case
fail. Each must return `FA-REF-207` and execute the existing structured
`fa dimension constraints cost_center` hint under the harness's read-only
operation check. This is policy inspection; classification remains the
preparer's decision, and the refused posting is not resubmitted or silently
changed. The renderer already extracts this command from the refusal.
No production change, catalog exemption or coverage-assertion reduction is
needed. The full original target still requires native qualification.

## 2026-11-04 — Schema branches diverged in shape ordering

The native robot-schema target ran one passing and one failing test.
The retained binary output and published version-1 pin are both 355,126
bytes. Structural comparison found identical envelopes, events and all
284 named shapes, including every field, type and documentation string.
Only `plan_application` and `plan_application_difference` were in different
array positions: their registry declarations followed `plan_leg`, while
the published pin appends them after `asset_register_row`.

An initial external candidate moved the two unchanged declarations to match
that local pin. Before applying it, the canonical remote advanced to
`b14cd555d`. Comparison with the shared `17aa0fba` base established that
the local fixture had moved those two shapes, while the canonical remote
retained their original order and matched the automatically merged registry.
The final integration preserves that canonical order; the earlier external
declaration move is superseded and never applied to product source.

The schema merge starts with the canonical remote's exact bytes. It carries
over only the two local daemon event objects (`fad_serving`, `fad_status`)
and the separately attributed `tb_served` documentation correction below.
This retains the remote's new bank-reconciliation fields, item shape and
bundle documentation. Structural comparison with the shared base proves
the two branches' declared deltas before composition; all 285 shapes and
284 events then match the combined registry's exact names, order, fields,
types and documentation. No binary fixture regeneration occurs. The
356,766-byte combined fixture is a prepared merge, not native schema or
registry qualification; both remain required.

## 2026-11-04 — Retained-cut conformance pinned an obsolete current procedure version

The native substrate-conformance target ran 14 passing and one failing
test. Its call to the current `PonziNetInvestment::new()` returned version
5, while the test still expected 4. Registry commit `cbc90a645` and the live
implementation both declare version 5, adding explicitly classified posted
principal transfers. This fixture contains cash subscriptions and payments,
with no such transfer. Version-4 distribution procedures remain cash-only.

The repair pins that current constructor to exactly 5 and updates the
test's corresponding evidence label. The exact per-investor values
`[10000, 20000]`, distribution values `[3000, 6000]`, all other financial
vectors, the four other procedure-version pins, retained input and finding
digests across later postings, and the changed-head non-vacuity checks
remain unchanged. This tests version 5 at a retained cut; it does not claim
cross-version replay of a historical version-4 certificate. The original
test and complete conformance crate still require native qualification.

## 2026-11-04 — Historical serving invalidated the served-read test's literal oracle

The native served-read target failed both tests, with zero passing tests.
Its helper assumed that a numeric `--as-known-at` selector forces a literal
fold with `served: null`. Commit `804f02225` deliberately added authorized
historical reads from pinned maintained state, and updated the README and
other CLI tests accordingly. The first failure returned a literal serving
description rather than null; later maintained reads would also invalidate
the helper. Adding an unrelated head entry would not restore independence.

The repair uses `tb --as-known-at <the original cut> --certify` as the
comparison oracle. The certificate path directly calls the literal
`fa_registers` fold over journal payloads. The test runner requires exactly
two schema-valid frames for this command, a trial balance naming a
certificate followed by a report certificate. Ordinary calls still require
exactly one frame. The original exact selected frontier, null serving
metadata for the certified fold, rows and unit totals remain required.
All head serving-mode and tail-count assertions, the maximum-amount
overflow refusal, unchanged frontier after refusal, and register
verification checks remain intact. No product read path changes.

The registry's `tb_served` documentation also retained the obsolete claim
that historical reads always fold the journal. Only this documentation
string is corrected in the registry and in the existing published robot
fixture: historical cells, checkpoints and tails use the selected recorded
frontier; certified, as-of and summary reads retain their literal behavior.
Every other fixture byte segment, shape field, type and event is preserved.
The initial standalone prepared fixture was 355,252 bytes. The subsequent
canonical-remote merge described above retains the remote's original shape
ordering and new declarations, the local daemon fields, and this same one
documentation edit. It changes no financial golden or type expectation.
Full native served-read and robot-schema execution remains required before
acceptance.

## 2026-11-04 — Bank facade replay preceded the raw-publication rehearsal gate

Source review of the newly published bank and subledger features found an
existing admission gap in the facade. `confirm_bank_statement_match` and
`reconcile_bank_statement` called `authorize_bank`, which observes the
recorded current-authority point, and then could reopen governed bank
evidence before reaching the native publication boundary's
`admit_direct_write` refusal. The native boundary already blocked an
unverified rehearsal-required publication; that did not prevent the
facade's earlier observations. The new outstanding-item reconciliation
variant inherited the same ordering.

The repair performs the same pure `admit_direct_write` check at the start
of the two facade publication implementations, before `authorize_bank`.
The exact-close convenience method delegates to the checked outstanding
implementation. The native gate remains in place, and current authority,
Human profile, source replay, exact cash bridge and publication witnesses
remain independently enforced. Read-only bank matching and continuity
continue to use their existing preparation admission.

Two new real-MemVfs tests cover all three public write entry points with
ordinary and expired rehearsal-required capabilities. They require the
specific FA-REF-011 rehearsal refusal without changing the book frontier.
An expired capability without the rehearsal caveat must instead reach the
real current-authority check and return FA-REF-014. A separate positive
test imports a real bank statement and matches its retained source using
a rehearsal-required capability. These checks distinguish publication
admission from permitted preparation; they do not weaken an old check or
claim that denied native commits previously succeeded. This is a
source-observed defect with a prepared repair; native qualification of
both new tests and the existing bank paths is still required.

## 2026-11-04 — Canonical parser tests required Debug on private usage errors

After integrating the four canonical bank/subledger commits, the complete
native verifier build exited 101 before running tests. Two E0277 diagnostics
came from the nested `parse(...).unwrap()` and `request(...).unwrap()` in
the positive recipient-question parser test: its private `Usage` error type
does not implement Debug. Exact-tree Tier 0
also failed at the new bank-selector test's `selected(...).unwrap()`, which
required Debug on the private CLI `Fail` type.

The repair uses explicit test panic messages on parsing failure, retaining
the same successful values and every assertion. The recipient test still
requires the spaced subledger code, maximum control ID, negative civil
cutoff and maximum recorded selector. The bank test still checks both
sorted leg references and rejects duplicates, changed digests, bad ordinals
and caller-supplied amounts. No production parser, error type, Debug
implementation, refusal expectation or input bound changes. Both native
verifier execution and exact-tree Tier 0 must be rerun on this repair.

On the preceding integrated source, the independent reference package
executed 38 tests and the unchanged register differential executed all 55
tests, including its original nine-seed generated-history comparison.
Both exited zero with no failures, ignored or filtered tests. These scoped
results validate the native application-fold repair on that source; they
are not a complete repository verdict for the subsequent parser-test fix.

## 2026-11-04 — Refusal fixture setup omitted robot mode

Candidate `a954f5ea0` passed exact-tree Tier 0 and the complete independent
verifier package: 925 tests passed, with none failed, ignored or filtered.
Its focused CLI packet then exited 101 with 307 passing tests and one
failure. The library, bank, general CLI, robot schema, served-read and
subledger targets passed, including portable native AR/AP verification.
The refusal-fix harness failed before its new FA-REF-207 cases: five new
dimension setup commands omitted `--json`, so its existing strict robot
schema check correctly rejected human output from `dimension add`.

The repair adds `--json` to those five setup commands. Both independent
allowlist-only and forbid-only cases, their expected FA-REF-207 refusals,
the actual suggested read commands, the catalog coverage requirement and
strict schema validation remain intact. No production admission rule or
robot output contract changes. The corrected complete target must execute
successfully before it supplies passing evidence.

The same source's facade and formats/Lantern/conformance builds reached
the ordinary 1800-second compilation limit and exited 137 without running
tests. A queued strict Clippy command exited 103 before remote execution.
These are not passing results. The three focused commands placed profile
options before the Cargo subcommand; the CLI transcript unexpectedly says
`unoptimized + debuginfo`, whereas the repository's original command form
places these options after `test` and reports `unoptimized`. Local config
inspection resolves the leading options correctly, so the remote cause is
unestablished. Subsequent qualification uses the repository's original
argument order. No compiler optimization, assertion, time limit, worker
capacity or gate criterion is relaxed. All owned source leases were
terminal and acknowledged before applying the fixture correction.

## 2026-11-04 — Conformance mutation omitted qualified tests and failures

The complete c363 model packet executed 374 passing tests and one failure:
formats passed 148, Lantern passed 212, and substrate conformance passed
14 with one failure. No test was ignored or filtered. The role-oracle
membership/value/citation mutants and the original date and solvency
controls passed. The next conformance assertion expected cash-flow version
2, but its current constructor and registry declare version 4. Commit
37f0c685a moved cash-flow and balance-sheet evaluation to effective-date
semantics at version 3; 718013ad9 advanced cash-flow to version 4 for net
overdraft liquidity. Source inspection also found the later, unreached
balance-sheet pin still expected 2 instead of 3.

The test selects current constructors and then replays a retained sequence
after a head mutation. Its corrected explicit pins are cash-flow 4 and
balance-sheet 3. Every amount, narrative component, input/findings digest
comparison and head non-vacuity assertion remains. This fixture has no
later settlement, overdraft or valuation extension to change its exact
financial vectors. It does not prove archived version-2 evaluation across
an algorithm upgrade. No production algorithm or golden output is changed.

Comparing the actual 15 native substrate test names with the mutation
script's original awk discovered only 13. Both the forensic method test
and register-capacity test are nested and omitted. The flat-name failure
parser also drops the actual qualified forensic failure. An initial
diagnostic assertion incorrectly expected 14 discovered names; the
corrected read-only comparison proves 13 of 15 and preserves that mistake.
The repair, tracked by fa-yuc4, discovers the compiled harness inventory,
requires a complete passing baseline, and inverts every listed test while
checking that exactly it fails and all others pass. Native commands use
explicit remote execution, the parent job/profile settings and a forwarded
runtime inversion variable.

Admission split: previously unexamined qualified tests now require their
own negative run; red baselines, hidden second failures, omissions,
duplicates, ignored tests, vacuous inversions, delivery errors and missing
completion evidence cannot pass. The existing checker is tightened, with
no new exception, timeout or reduced financial predicate. Fifteen bounded
classifier/argv fixtures passed in the existing check-classify selftest;
these fake transcripts are not native conformance evidence. The actual
positive 15-test baseline and all 15 native inversions remain required.

The c363 corrected CLI packet independently completed 308 passing tests,
and the complete journal bank-match target passed 64, with no failures,
ignored or filtered tests. The facade and MCP builds instead reached the
ordinary compilation cap without executing tests. Strict Clippy found an
unnecessary reference and nested duplicate-declaration condition in the
portable verifier; their direct fixes preserve the comparison and
short-circuit mutation/refusal. All owned source leases were terminal and
acknowledged before this combined correction. No full repository verdict
or closure follows from the bounded positives above.

## 2026-11-04 — Checkpoint refusal precedence and bound MCP access receipts

On the frozen correction batch over c363, the complete facade library
executed 734 passing tests and one failure, with none ignored or filtered.
Both new bank rehearsal-admission controls passed. The portable native
subledger authority test expected FA-REF-126 for a checkpoint older than
the report, but got migration-specific FA-REF-133. The shared producer
called report::run_bodies before the assembler's covering-prefix check;
migration input lookup therefore rejected the report frontier even though
the fixture has no migration. The repair adds that coverage refusal in
the report-specific helper, using its existing FA-REF-126 constructor.
The original exact refusal assertion, authority ordering, complete-prefix
requirement and independent assembler check remain unchanged.

The MCP package then executed 99 passing tests and one failure before its
ordinary 1800-second command cap ended the remaining campaign. Its library
passed 63, denial controls 2, stdio integration 31 with one failure, and
external-subledger integration 3. The new stdio subledger test completed
historical export and independent exact gross/pending verification for
retained and inline certificates. Its final assertion incorrectly expected
the head to remain 14; four admitted deliveries had journaled their
mandatory AccessEvents, advancing it to 18. Existing access_record policy
and access_receipts_since checker establish that bound reads, including
refused accounting questions, owe these receipts. The test now requires
exactly four ordered `bundle produce` receipts by `mcp-agent`, with no
other publication allowed. Every original financial, recipient-question,
certificate, receipt and byte-equality assertion remains. This admits
only required access evidence, not monetary or metadata mutations.
The capped command is not a complete MCP passing result.

The repaired mutation runner compiled and listed all 15 tests, but its
worker then refused the baseline and inversions for capacity. No native
baseline or inversion passed. A control-flow error in the new runner let
it continue after gate_verdict returned for that unrun baseline; it now
exits immediately, and the existing classifier selftest checks that both
red and unrun baselines stop after listing and baseline. Source review
also found the formerly omitted register test's switch used an unqualified
name; its constant now matches its compiled qualified name, preserving
every race, capacity and atomicity assertion. Native discrimination still
requires all 15 inversions to execute successfully.

Fresh complete fa-verify passed 925 tests after the two production lint
fixes, with no failures, ignored or filtered tests. Strict keep-going
Clippy found two additional constant-pair decoder lints in CLI and MCP
test helpers; typed two-byte chunks replace the iterator form while their
existing even-length assertions and exact decoders remain. No suppression,
accounting predicate, watchdog or worker guard changed. Every owned parent
and remote source lease was terminal and acknowledged before applying
this batch. All changed targets and the original full repository proof
remain required; earlier scoped results do not qualify the new tree.

The corrected batch subsequently completed the full facade library (735
passed), the complete MCP package (119 passed), and strict workspace and
all-target Clippy (exit 0). Neither native package ignored or filtered
tests. The unchanged exact FA-REF-126 checkpoint assertion and both bank
admission controls passed; MCP's four-receipt bound passed alongside all
original recipient, amount and certificate checks. Two intervening facade
builds and the first mutation listing reached their ordinary compilation
caps without running tests; those attempts retain their UNRUN evidence.

The real mutation continuation then executed the compiled 15-test
inventory, a complete 15-pass baseline and all 15 separate inversions.
Each inversion failed exactly its intended test and passed the other 14,
with none ignored or filtered. The formerly omitted qualified forensic and
register-capacity tests both discriminated. Its gate exited 0 with 16 PASS,
zero FAIL and zero UNRUN verdicts. All 16 classifier/argv controls also
passed, but remain synthetic controls rather than native execution proof.
These are source-bounded diagnostics over the correction batch, not a
complete repository verdict, authenticated crate-cache reuse, a measured
performance win or authority to close a bead. Canonical changes integrated
after these runs require a fresh exact-tree full repository proof.

## 2026-11-05 — Document presentation must not overstate certificate scope (fa-qh60, fa-cet)

Canonical `28f7d018` allowed PDF rendering without `--certify`, while the
PDF content always called itself `FrankenAccounting Certified Statement`.
During rounded-document integration, review also found that the first
unpublished draft put its display-only/exact-certificate notice solely in
`ir.markdown`; HTML, SVG and PDF consume the common table rows instead.
These are source-observed scope defects, not evidence of an issued rounded
accounting proof or a conclusion about any underlying transaction.

The repair uses a neutral statement title and collision-safe common rows
declaring the display units, registered rounding law and `Display only;
cert exact` scope. Exact statement amounts and accounting certificates are
unchanged. Regressions require the scope notice in actual content in all
five formats, including PDF text operators, plus unchanged exact certificate
bytes, explicit residuals, no-overwrite and clock/selector refusals.

The title-only change deliberately updates two byte-exact pins: PDF becomes
4,341 rather than 4,351 bytes and PDF/A becomes 4,378 rather than 4,388.
The first native run correctly failed the old two pins; HTML, SVG and
Markdown pins were identical. Only the two reviewed title-dependent hashes
and lengths change, with explicit assertions rejecting the unsupported
certification title. No fixture-wide regeneration or relaxed comparison is
used. Corrected final native execution remains pending at this record's
creation; the earlier source-bound 63-test pass and 31-pass/1-failure CLI
diagnostic are retained separately and supply no full repository verdict.

The later fixed-source runs on `fb0acc362` plus this implementation pass all
63 `fa-statements` library tests and all 32 CLI tests across `statements`,
`rendered_reports`, `migration_proofs` and `robot_schema`, with no ignored or
filtered tests. The PDF/PDF-A pins and actual rendered scope/numeric content
pass. These are scoped native results; full exact-tree repository
qualification and the broad `fa-qh60`/`fa-cet` acceptance remain pending.

### 2026-11-05 — native PDF/A output fails an external conformance check (`fa-cet`)

The retained native CLI fixture `rounded-pdfa-0` from the completed 05:07
rendered-reports run is 30,650 bytes, SHA-256
`e88fcbef044631f1febe026b7e6658959e6b3f52c25efd0da3c3590bbb9a8da1`.
An independent `pdffonts` invocation exits 0 and finds only Type 1 Courier,
with embedding, subsetting and Unicode mapping all absent. The existing
renderer emits that unembedded font and an undeclared `fa:irDigest` XMP
property; its local metadata/OutputIntent checks do not establish PDF/A
conformance.

The same unchanged native PDF was checked offline with the official veraPDF
CLI image pinned to
`ghcr.io/verapdf/cli@sha256:de5843855864e20b2ffffe8aab9336810725468eecf06dccdc15df7a43527ef2`.
This is the development-series apps 1.31.212, core 1.31.53 and validation-model
1.31.213. The explicit command is `--format xml --flavour 2b /data/input.pdf`,
with the fixture mounted read-only and container networking disabled. The
command exits 1; parsing finishes normally, and the PDF/A-2b report states
`isCompliant="false"`: 141 rules and 5,258 checks pass, while three rules and
three checks fail. ISO 19005-2:2011 rule 6.2.11.4.1 test 1 rejects the missing
font program. Rule 6.6.2.3.1 tests 1 and 2 reject `fa:irDigest` because its XMP
extension schema and value type are not declared. No parse, encryption,
out-of-memory or validator-exception failure is reported.

The report is retained at
`/home/ubuntu/.codex/artifacts/fa-gap-work-20261031.lM8xfA/native-rounded-pdfa-verapdf-20261105.xml`,
SHA-256 `747545cbc625a453004feb143736c141415dc5793671fd3cecaf397803dc2c3a`,
alongside the original stderr and exit code. The container and input remain
retained. This is an executed negative result on that historical native
fixture, not qualification of the later combined tree. `fa-cet` remains in
progress under its original first-party-renderer, external-validation and
cross-machine acceptance. No validator, output pin, font requirement or
acceptance condition was weakened to admit this PDF.

### 2026-11-05 — CLI preflight prevents admitted Post-only draft workflows (`fa-txgy.7`)

The combined `abb6fec2217d119bcd14fb593a967a34495474c2` tree passes exact
Tier 0, but the real unfiltered `fa-cli --test authority_cli` execution exits
101: 10 pass, four fail, with no ignored or filtered cases. All four
`source_draft_tests` fail at `draft new`, before their FX, external-subledger,
disposal-review or no-read checks execute. The generic bound-command registry
marks draft creation as whole-book reach and rejects the capability's named
draft branch as trunk-incompatible. The native draft lifecycle already judges
that logical branch and current issuance; its surface was disconnected. The
native log and exit remain in
`/home/ubuntu/.codex/artifacts/fa-gap-work-20261031.lM8xfA/specificid-authority-abb6fec2-vmi1152480-20261105.log`
and its adjacent exit file. Remote exit 101 is an executed failure, not an
offloader refusal, and the new disposal test has not yet exercised its factory.

The repair delegates only `draft new|plan|discard` and `post|batch --draft`
to native scope admission. Draft listing, showing and promotion keep their
whole-book front-door policy. Disposal review gets a separate Post-only
registry row and an Agent review exception; the handler still requires either
ordinary Read/Post or the current explicitly confined owner-draft source
admission. Ordinary disposal retains Read/Post and Agent trunk restrictions.
No accounting admission or test expectation is removed. The positive disposal
test additionally checks the MCP preflight, and general draft listing/showing
join the no-read negatives. Corrected native execution is pending; these edits
are not evidence that the four workflows pass or that the broad bead is done.

Independent source review caught an additional ordering issue before corrected
execution: lifecycle handlers eagerly derive `control_date` from book metadata,
even when a date flag is present. New and discard now use `open_admitted` to
judge conjunctive named-draft Post reach and current issuance before that
lookup; native lifecycle and transaction checks remain. Wrong-name lifecycle
requests with an invalid date are added as negatives: branch refusal must
precede date parsing, reveal no coordinate and leave the head unchanged.

On repaired `8177cafa`, the unchanged complete authority target ran again:
12 passed and three failed, with no ignored or filtered cases. All three
writing-authority matrix tests passed in the same native command, whose
remote/outer exit remains 101. The new conjunctive-scope and no-read controls
pass; the positive workflows now reach their factories. Later failures expose
three invalid test prerequisites: reversal JSON supplies `E:<vid>` instead of
the documented raw 32-hex field, canonical external detail is retained without
its declared MIME, and disposal review incorrectly expects no journal-head
advance despite the required bound-command AccessEvent.

The correction supplies contract-valid reversal and MIME inputs. It does not
change the source-purpose guard or expected unreviewed-evidence refusal.
For disposal review, incorrect head equality is replaced by an exact one-receipt check of
command, principal, capability, argument digest, observed/recorded sequence
and final head, together with byte-exact equality of all native Entry/payload
rows and an empty draft before append. This admits only the mandated audit
receipt, never an accounting write. A new wrong-MIME test retains the source
refusal and verifies that a planted private balance is not disclosed. Detail
guidance now names the required document-add MIME. Corrected full native
execution remains pending; these source/test edits do not erase either loss.

Review caught two mistakes in the first unexecuted correction: request digests
use canonical positional/sorted-flag/sorted-switch order, and current draft-plan
refusals do not select the disposal review-delivery AccessEvent. The receipt
check now uses an explicit independent canonical argument vector; unreviewed
and wrong-MIME draft-plan refusals retain unchanged head, no access records
and unchanged full accounting payloads. Production audit selection is unchanged.
This correction was made before another native run, not presented as a test pass.

### 2026-11-05 — ordinary FX draft reversal rejected by batch composition

Native `authority_cli` on `1cf18d0e` ran all 16 cases: 15 passed and the
FX draft case failed; all 3 `write_authority` cases passed. The original
purchase planned successfully, but reversing that retained draft entry returned
exit 5 from `PreparedPost::into_member`. The exact side-swap had passed posting
validation; batch composition rejected its aggregate-sensitive classification.
Raw evidence is `fa-gap-work-20261031.lM8xfA/draft-authority-1cf18d0e-hz3-20261105.log`
and `.exit` (outer and remote 101, 678867 ms). No unchanged assertion retry
or passing credit is attributed to this result.

The repair admits only ordinary SpotClose reversals in admitted draft protocols,
with no application legs or extensions. It leaves `requires_aggregate_basis`,
valuation ancestry, exact side-swap validation and the batch publication frontier
guard intact. The original positive regression remains and now also asserts
literal 100.00 EUR / 110.00 USD values and retained reversal effects. Qualification
of this repair is pending; other FX laws and source-derived reversal families
receive no new admission from this change.

The later `dd2e7485` run passed the existing 16 authority cases and all 3
writing cases, but both newly added payable tests failed before application
planning: their fixtures read `data.entry` from an ordinary posting result,
whose canonical identity field is `data.vid`. Those two reads were corrected;
the draft result's `entry` field and every economic/refusal assertion remain.
The failed run (outer/remote 101, 8611 ms) is retained, with no passing credit
for the two new cases. Its unfiltered genesis request separately did not run:
source initialization returned 73 before a source/execution grant, outer 103.

With those fixture IDs corrected, `2d57d69d` passed 17 authority cases,
including current-trunk promotion refusal, and all 3 writing cases. The payable
case passed planning and exact amount checks, then its read-denial probe used
`fa entry <vid>` instead of the registered `fa entry show <vid>` and received
usage exit 2. The probe was corrected to reach the permission check; its
expected exit 7 / FA-REF-011 and exact promotion assertions were preserved.
Raw outer/remote 101 (8601 ms) remains; this is another fixture error, not a
product-law failure or a pass for the full suite. The second unfiltered genesis
request again did not execute (initializer 73 / outer 103).

### 2026-11-05 — complete journal suite exposes two safety defects and a fixture error

The unfiltered genesis run on `cd8311d0` executed all 450 cases: 447 passed,
3 failed, none ignored or filtered; outer/remote 101, 79378 ms. Evidence is
`fa-gap-work-20261031.lM8xfA/genesis-cd8311d0-hz3-request3-20261105.log` and `.exit`.

`compound_carrying_keeps_full_history_tamper_refusals` returned carrying data
after unrelated retained-entry damage. Earlier revaluation-input replay did
not verify immutability through the selected current prefix. The repair runs
the existing complete entry-history verifier at that prefix before auditing
allocations. All delete, relabel, rewrite, restore, literal/compound parity and
intact historical-coordinate controls remain unchanged (`fa-pvt7`).

`closed_reversal_sweep_requires_system_authority_even_for_an_agent_operator`
failed at the real System caller's Closed-period assertion, not the Human
profile refusal. Execution substituted the caller's extra `post_closed` for
the schedule's recorded `post`. The repair requires both the recorded operation
and the executor's actual authority; SoftClosed execution and all original
profile/period assertions remain (`fa-61i4`).

The draft rehearsal negative constructed an Agent-profile capability, for which
`with_requires_dry_run` deliberately emits no redundant tag 12. Its expected
explicit control restriction was absent. The fixture now uses a Human base
with an Agent operator, the same draft confinement and actual tag 12, and
asserts that the flag is present. The original refusal and unchanged-head
assertions remain. Production capability formats and lifecycle admission are
unchanged (`fa-d48q`).

On `55a2797b` / tree `0a60b739`, the complete genesis suite then passed all
450 cases, with none failed, ignored or filtered. The complete authority and
writing targets passed 18 and 3 cases respectively. Strict workspace/all-target
Clippy completed with `-D warnings`. Each remote command returned 0, followed
by outer RCH exit 1 during retirement/finalization. Official recovery and a
separate lease read observed acknowledgment and source/tree/pair retirement;
they do not repair those original exit codes. The original full repository
gate and exact Tier 0 remain unqualified. Two broader workspace test requests
were refused with exit 120 before Cargo started because normal disk admission
could not cover the original 40 GiB growth reservation, 10 GiB protected floor
and active reservations. Neither request supplies test evidence; no disk
budget, reservation ledger, gate or daemon guard was changed.

The remaining `fa-txgy.7` carrying-settlement factory still demanded whole-book
Read even after its caller admitted an owned draft. Its new purpose-bound
path returns only derived EntryPayload effects; it never returns the existing
PreparedFxSettlementGroup's CarryingOpenItem balances. Direct factories keep
Read admission, the draft path uses governed Rate-source reads, and both use
the same exact carrying derivation and publication checks. New positive CLI
coverage requires a retained 100 EUR / 110 USD payable to draft a 120 USD
settlement with an explicit 10 USD loss and exact independent promotion;
wrong-branch and ordinary entry/document reads must still refuse. Native
execution and complete qualification of this additional slice are pending.
