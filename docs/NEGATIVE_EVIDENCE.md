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
  review found that `activate_policy` validates then seals a caller's
  control proposal without passing through the monetary posting guard.
  The shared payload validator now rejects `base_totals` on any entry with
  no legs, including control entries and reservation releases. The model
  test preserves valid round trips; the policy regression checks a typed
  structural refusal without advancing the head or policy epoch. Valid
  encoded bytes and their digest golden vectors are unchanged. Previously
  accepted malformed no-leg valuations fail validation and decoding.

Runtime verification of the two aggregate-admission repairs remains pending;
the exact before/after results and combined landing gate are tracked on
`fa-p7r`. Their source review is not a passing test or full FX-law coverage.
