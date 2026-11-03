# Lossless normalized bank-feed intake

The saved `plaid-sync` bank importer and the supervised `fwc` connector path
share the same source decoder. It accepts the normalized `fwc.robot.v1`
envelope in the [retained fixture](../crates/fa-formats/corpora/fwc_plaid_transactions_sync_fixture.json).
This envelope contains one account's statement balances and a complete ordered
transaction array. Raw Plaid API responses, pagination and `added`/`modified`/
`removed` change streams require an explicit normalization step; this reader
does not silently ignore those populations.

## Preserve the meaning of source text

The previous adapter searched for the next quote and closing brace in the raw
response. An ordinary JSON value such as `"Acme \"Holdings\" Corp"` could
therefore become the counterparty `Acme \`, while its amounts and statement
balance still reconciled. A brace inside a valid description could also end a
transaction prematurely. References participate in bank-line identities, so
their interpretation must be exact as well.

The adapter now decodes the complete JSON structure once and reads each field
from its declared object. Escaped quotes, backslashes, Unicode and surrogate
pairs retain their decoded text. Braces and brackets inside strings remain text.
These rules follow [RFC 8259, section 7](https://www.rfc-editor.org/rfc/rfc8259.html#section-7).
Malformed escapes, duplicate decoded keys, trailing input and wrong field types
are refused before bank intake can publish a statement.

## Supported source contract

Every field below is required. Undeclared fields are refused rather than
discarded. The declared version is deliberately bounded: a broader connector
response needs an explicit adapter update and its own source assertions.

| Envelope field | Admitted representation |
|---|---|
| `robot_schema_version` | String `fwc.robot.v1` |
| `connector` | String `plaid` |
| `operation` | String `transactions_sync` |
| `receipt_hash` | A string encoding exactly 32 hexadecimal bytes |
| `account_id` | The source account identifier as a string |
| `sequence_number` | A string parsed as an unsigned 64-bit integer |
| `currency` | A registered unit code |
| `statement_date` | An ISO civil-date string |
| `opening_balance`, `closing_balance` | Exact decimal strings at the registered unit's scale |
| `transactions` | An array of transaction objects |

Each transaction has exactly `transaction_id`, `booking_date`, `value_date`,
`direction`, `amount`, `counterparty` and `reference`, all strings. Transaction
IDs must be nonempty and unique within this supplied feed. Direction is
`credit` or `debit`; each amount is a strictly positive exact magnitude, with
direction carrying its sign. Opening balance plus signed activity must equal
the stated closing balance. The native importer also enforces its existing
date, size and account-admission constraints.

The parser visits every array member in order. A null, scalar, nested array or
incomplete transaction cannot disappear during extraction. A legitimate
offsetting payment pair remains two source observations and two bank lines,
even though it leaves the closing balance unchanged. Monetary JSON numbers,
including integers and scientific notation, remain refused: money travels as
exact decimal strings, with no floating-point conversion or automatic rounding.

The original response bytes remain the content-addressed source document, and
every admitted bank line retains its `DERIVED_FROM` link. Two JSON encodings of
the same decoded values can have identical bank-line interpretations while
retaining different raw-source document identities. The declared receipt hash
is preserved; parsing it does not authenticate an external service or prove
that an upstream feed omitted nothing.

## Import a saved normalized response

Use an existing book with the intended cash account and accounting periods:

```bash
fa bank import normalized-feed.json --bank-format plaid-sync \
  --account 1010 --book acme.fabook --json
```

The native bank-intake path remains responsible for source retention, canonical
bank-line storage, exact retry and reconciliation. No connector installation or
network access is needed to import a saved response. The committed two-payment
fixture is a constructed format regression, not a customer's live bank feed.

Warehouse export responses use the same structural decoder. Their normalized
root object has exactly `robot_schema_version`, `connector` and `receipt_hash`.
Nested or shadowed connector/receipt fields cannot stand in for those root
fields, and the raw response remains the receipt's source commitment.

## Verification and reproduction

The decoder implementation is shared through `fa_model::json`; the existing
`fa_verbs::json` API re-exports it. This preserves one integer-only decoder
without an upward dependency from formats into the surface layer or a new
third-party parser. All 11 existing JSON/TOON compatibility tests remain at
their original consumer test paths. Nine additional FWC tests cover source
text, structural ambiguity, array population, exact monetary refusal and
warehouse receipts; all three prior FWC tests remain.

The [public-data native workflow](../.github/workflows/public-ledger.yml) runs
the shared-codec tests, all 12 FWC parser tests, saved-feed CLI intake/readback,
and the existing supervised connector and warehouse regressions. It retains
their logs alongside the corpus results. Its commands include:

```bash
cargo +nightly-2026-08-31 test --locked -Z bindeps -Z git=shallow-deps \
  -p fa-verbs --lib json::tests:: --jobs 1
cargo +nightly-2026-08-31 test --locked -Z bindeps -Z git=shallow-deps \
  -p fa-formats --lib fwc::tests:: --jobs 1
cargo +nightly-2026-08-31 test --locked -Z bindeps -Z git=shallow-deps \
  -p fa-cli --test bank plaid_ --jobs 1
cargo +nightly-2026-08-31 test --locked -Z bindeps -Z git=shallow-deps \
  -p fa-cli --test bank fwc --jobs 1
```

Local validation of this repair passed the affected crates' all-target compile
checks, the targeted native bank-test compile check, and an explicitly scoped
Rust harness running the exact shared-codec implementation and all 11 retained
compatibility tests. Full FWC package and native CLI runtime execution remains
pending a build of this change: the local Cargo test attempt was stopped when
it reached the dependency code generation that had repeatedly exceeded the
available execution resources. The dedicated runtime commands are included in
the hosted workflow for this revision. Neither a compile check nor the isolated
codec tests establish full bank-import runtime acceptance or a live connector
integration result.

The [measured validation record](../evidence/formats/fwc-json-validation-2026-11-03.json)
retains the exact source pins, commands, log hashes, successful checks and
unexecuted runtime boundaries. An older repaired-engine build does not validate
this later parser change.
