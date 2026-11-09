# Approved cash-flow classification policies

`cash-policy` retains reusable cash-flow classifications in the journal. A
preparer reviews a named version against a specific chart; two independent
Human approvers approve that exact proposal; activation records the complete
definition, approvals and effective date atomically. Later reports can select
the same approved version at an explicit recorded prefix.

## Prepare and activate a version

Create a rule-policy JSON file using account codes from the book's chart:

```json
{
  "name": "company-cash",
  "cash_accounts": ["1000", "1100"],
  "account_rules": [
    {"account": "3000", "activity": "financing"},
    {"account": "4000", "activity": "operating"},
    {"account": "6000", "activity": "operating"}
  ]
}
```

Cash accounts must be asset or overdraft liability leaves. Counterpart rules
must name non-cash monetary leaves and classify them as `operating`,
`investing`, `financing` or `exchange_effect`. Internal transfers are derived
from the selected cash accounts. An activated definition cannot contain
per-entry overrides. Names contain 1–64 ASCII letters, digits, underscores or
hyphens; versions are positive integers.

The preparer's capability requires whole-book `rule_change` authority and
admission to `PolicyControl`. Preparation is read-only and returns canonical
review bytes and their `proposal_digest`:

```bash
fa cash-policy define --file policy.json --version 1 --from 2026-01-01 \
  --key company-cash-v1 --plan-out policy.plan \
  --token preparer.token --book ./book --json
```

Give the exact saved review and its independently retained digest to the two
reviewers. Each must be a distinct Human, separate from the preparer, with
whole-book approval authority. If a reviewer has a registered key, the
approval must use that key:

```bash
fa approve --proposal <proposal_digest> \
  --token controller-a.token --sign-key controller-a.key --book ./book --json

fa approve --proposal <proposal_digest> \
  --token controller-b.token --sign-key controller-b.key --book ./book --json
```

The preparer activates the saved review with both returned approval IDs:

```bash
fa cash-policy activate --plan policy.plan --digest <proposal_digest> \
  --approval <controller-a-approval-vid> --approval <controller-b-approval-vid> \
  --yes --token preparer.token --book ./book --json
```

Activation rechecks current authority, the approved bytes, reviewer
independence and the chart basis inside the native transaction. Changing the
chart requires a fresh review and approvals. Recording approvals or ordinary
monetary entries does not invalidate an unchanged chart. An exact retry with
the same plan and approval list returns the original activation and sequence;
reusing its key with different content or approvals is refused.

## Select the approved classification in reports

Inspect the version that applies to a complete inclusive interval:

```bash
fa cash-policy show --name company-cash --from 2026-03-01 --to 2026-03-31 \
  --book ./book --json
```

Use the same name for a direct cash-flow report. The account selection must
exactly match the approved cash account set:

```bash
fa gl cash-flow --policy-name company-cash --account 1000,1100 --unit USD \
  --from 2026-03-01 --to 2026-03-31 --certify --book ./book --json
```

For an indirect report, include `--indirect --income-period <period-code>`.
An optional `--policy adjustments.json` supplies only `name` and `adjustments`:

```json
{"adjustments": []}
```

Omitting that file selects an empty adjustment set. The native report still
requires complete income coverage and exact reconciliation to operating cash
flow. Named indirect mode refuses rule, account, split or override fields in
that file; named direct mode refuses `--policy` entirely. Existing ad-hoc
`gl cash-flow --policy ...` workflows remain available.

## Historical selection and evidence

Every later version of a name must have a greater version number and a later
effective date. `--as-known-at <seq>` pins both policy selection and report
history to the same recorded prefix; activations recorded after that prefix
cannot affect the result. Selection refuses an interval that crosses a policy
version change. Request separate intervals when a classification changes.

`cash_flow_policy_selected` identifies the selected version, definition digest,
activation, chart basis, effective date and recorded sequence. Existing report
certificates retain their complete original policy inputs and arithmetic, so
replay remains stable after later activations and postings. The activation
citation supplies native approval provenance separately: a math certificate
does not itself establish historical approval authority or accounting judgment.

The portable verifier recognizes the typed activation entry and independently
checks its canonical definition, digest, identity and framing. Native
`verify registers` also checks activation history and its common intent-outcome
claim. A missing claim, malformed definition or unsupported future entry
version fails verification.

Library callers use `CashFlowPolicyDefinition`, `CashFlowPolicyPlan` and the
`Book` methods `admit_cash_flow_policy`, `plan_cash_flow_policy`,
`activate_cash_flow_policy` and `active_cash_flow_policy`. `AsyncBook` exposes
the equivalent operations with explicit purpose contexts. MCP exposes
`cash_policy` inspection and named `gl` reporting; definition and activation
remain host workflows with explicit review, independent approvals and
confirmation.
