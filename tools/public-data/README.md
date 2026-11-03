# Complete public expenditure extracts through FrankenAccounting

This development helper acquires complete, pinned public transaction files and
constructs an explicitly declared expenditure model for the native import
pipeline. It preserves every original record, including duplicate and zero
records. It does not turn a transparency extract into an original general
ledger or claim that the resulting book reconstructs a department's accounts.

Python 3.11 or newer is required. All helper code uses the standard library.
Network access occurs only when explicitly preparing a dataset without a local
`--source`. Tests and bundle reconstruction are offline.

## Executed native coverage

The complete HMRC March 2025 extract passed the actual native workflow on
2026-11-03: **1,430 original records, 127 migration entries, 2,860 monetary legs,
588 native calls and 402.144 seconds**. The retained
[execution result](../../evidence/public_spend/hmrc-2025-03-native-2026-11-03.json)
records all 18 completed checks, original-source and executable hashes, native
document identities, certificate/checkpoint identities, and the verified bundle
hash. The process exited zero; a separately corrupted bundle exited eight.

Both complete datasets also passed actual HTTPS acquisition and deterministic
source preparation. A native DWP completion is not established until its own
complete execution produces a retained `PASS`; preparation and a partially
staged run do not establish that result. Execution timings are diagnostic dev
build observations on a shared host, not release throughput benchmarks.

The complete HMRC control body is 65,422 bytes and the DWP body is 49,105 bytes,
both above the substrate's 16 KiB vertex ceiling. Native migration storage now
uses the existing authenticated object-fragment mechanism for large bodies,
preserving their canonical source bytes and Open commitments. Reassembly
validates fragment identity, original birth and immutable history at the
selected prefix. Historical inline bodies remain supported. Native storage,
certificate closure, offline verification and >16 KiB durable/replay/corruption
regressions were exercised alongside these corpus runs.

## Run the native workflow

First [prepare the complete sources](#prepare-the-complete-source). Build the
repository's real `fa` and `fa-verify` binaries with the pinned Rust toolchain:

```bash
cargo build --locked -p fa-cli --bin fa -p fa-verify --bin fa-verify -p fad --bin fad
```

Then run, using `target/debug/fa` and `target/debug/fa-verify` from that build:

```bash
python3 tools/public-data/run_live.py \
  --prepared /tmp/fa-public-hmrc --dataset hmrc-2025-03 \
  --out /tmp/fa-public-hmrc-live \
  --fa /absolute/path/to/fa --fa-verify /absolute/path/to/fa-verify

python3 tools/public-data/run_live.py \
  --prepared /tmp/fa-public-dwp --dataset dwp-2025-01 \
  --out /tmp/fa-public-dwp-live \
  --fa /absolute/path/to/fa --fa-verify /absolute/path/to/fa-verify \
  --fad /absolute/path/to/fad
```

`--out` must name a new directory. `--timeout 300` sets the timeout for each
native command; it is not a total run-time limit. The runner retains command
arguments, return codes, stdout/stderr transcripts, native export, report
certificate/checkpoint/bundle and a final `result.json`. It emits `PASS` only
after all required native observations succeed. A failed run preserves the
completed command evidence and identifies the first failed step.

Before the first book mutation, the runner rebuilds every prepared file from
the pinned original and requires byte-for-byte agreement. It then drives native
FullDetail migration, package/chunk retries, staging invisibility, approval and
finalization, historical reads, exact gross and net trial-balance totals,
register verification, every exported dated leg and source memo, certified
replay and independent `fa-verify` report verification. Export comparisons also
check each leg's source journal, ordinal, description and native Migration
class, so moving balanced amounts between journals cannot pass. All six retained
source/control documents are read back and compared byte-for-byte, preserving
evidence for zero rows and fields that do not become journal legs. A deliberately
modified report bundle must be refused. Separate CLI invocations reopen the
durable book between operations.

For a larger extract, optional `--fad` uses the existing native daemon only
during the bulk staging loop. It avoids thousands of repeated file-store
recoveries; every stage still invokes the native importer and posting kernel.
The runner issues two restricted reviewer tokens through the native capability
API, so each daemon approval is bound to its own fixture principal. It stops the
daemon after staging, verifies that a direct reopen has the same recorded
frontier, and performs finalization, export, certification and outsider
verification through direct invocations. Source-document readback and preparation
also use direct reopens. The retained result records which transport was used
and the SHA-256 of every executable. Daemon logs and limited fixture token files
remain in the new execution directory alongside the book.

Two named **fixture reviewer roles** exercise approval separation. These are
test identities controlled by the same harness, not independent human review
or historical approvals by departmental employees. Uploaded source documents
use the real command's custody. The runner records explicit native Reviewed
attestations under a fixture principal distinct from the uploader, including
the normalized source and each computed period control that the Migration
entry cites. This exercises the evidence admission rule without relabeling
AgentUpload or Generated documents as human uploads. It does not claim an
audit-grade, independent human review, or third-party signature.

The model's sole source month remains explicit throughout the run. To satisfy
the native FullDetail historical-span rule, the runner carries that month's
modeled balances through empty scoped months to a January 1 go-live in the next
year. Those empty months mean **no additional activity was supplied to this
model**. They make no assertion that the department had no later activity or
that the model equals its actual later closing balances. No source-month data
is sampled or omitted to make the native run pass.

## Prepare the complete source

From the repository root:

```bash
python3 tools/public-data/public_spend.py list
python3 tools/public-data/public_spend.py prepare \
  --dataset hmrc-2025-03 --out /tmp/fa-public-hmrc
python3 tools/public-data/public_spend.py prepare \
  --dataset dwp-2025-01 --out /tmp/fa-public-dwp
```

To use an already downloaded original file, retain the source's original bytes:

```bash
python3 tools/public-data/public_spend.py prepare \
  --dataset hmrc-2025-03 \
  --source /path/to/HMRC_spending_over_25000_for_March_2025.csv \
  --out /tmp/fa-public-hmrc
```

The offline path applies the same byte-count, SHA-256, encoding, header, date,
and control-total checks. Re-saving the CSV in a spreadsheet changes the bytes
and is refused. Existing matching outputs allow an exact retry; different
existing outputs are never overwritten. No sampling flag is provided: every
source record is processed by default.

Fetches use HTTPS, a 30-second socket timeout, the manifest's byte bound and the
project User-Agent. Redirects must remain HTTPS. Source bytes are verified
before an output directory is created. A changed upstream publication requires
an independently reviewed new pin and its new controls; the helper never
updates a checksum automatically.

## Sources and their genuine complexity

The complete files below were retrieved and inspected on 2026-11-02. Locked
controls in [sources.toml](sources.toml) were computed separately from the
adapter using `csv.DictReader` and `decimal.Decimal` on the original files.
They are source-file arithmetic controls, not independently published audited
trial balances.

| Source | Rows | Negative / zero rows | Distinct payment references | Largest reference group | Exact sum of published values |
|---|---:|---:|---:|---:|---:|
| HMRC March 2025 | 1,430 | 125 / 0 | 1,321 | 12 rows | £285,744,584.15 |
| DWP January 2025 | 13,099 | 283 / 134 | 578 | 1,204 rows | £307,764,094 |

HMRC has 134 expense categories, 42 expense areas and 160 supplier strings;
DWP has 83 account descriptions, 1,830 cost centres and 187 supplier strings.
HMRC contains one exact duplicate row beyond its first occurrence; DWP contains
31. These repeated records are preserved. A payment reference is not a unique
row identifier, and equal records do not establish accidental duplication.

### HM Revenue & Customs, March 2025

- [Official publication](https://www.gov.uk/government/publications/hmrc-spending-over-25000-march-2025)
- [Original CSV](https://assets.publishing.service.gov.uk/media/680fdb56b0d43971b07f5c76/HMRC_spending_over_25000_for_March_2025.csv)
- [Official field explanations](https://www.gov.uk/government/collections/hmrc-spending-over-25000)
- [Dataset licence declaration](https://www.data.gov.uk/dataset/008d307b-5434-4218-9b62-2eabdef48778/financial-transactions-data-hmrc)

Original length: **213,348 bytes**. SHA-256:

```text
eca3d42b3c8f6c8e1b4746fcd3614b6b65311fbd4a7900a96b3b269dc3006a2a
```

HMRC describes positive amounts as invoices and negative amounts as credit
notes or memos. Its values include VAT; its dates are payment dates. An invoice
can be split among several expense types and expense areas, so individual rows
can fall below the publication threshold. The downloaded source contains
Windows-1252 text and two-decimal pound values.

### Department for Work and Pensions, January 2025

- [Official publication](https://www.gov.uk/government/publications/dwp-spending-over-25000-january-2025)
- [Original CSV](https://assets.publishing.service.gov.uk/media/68b84d92d723ba6f74dba95a/dwp-spending-over-25000-january-2025.csv)
- [Official explanatory notes](https://www.gov.uk/government/publications/dwp-monthly-payments-explanatory-notes/dwp-monthly-payments-explanatory-notes)

Original length: **1,935,610 bytes**. SHA-256:

```text
b6477bc3ea1afeac5d97caa581369b78c2c473360c2fe4a7493a26da847583b1
```

DWP excludes staff salaries and excludes recoverable VAT from the displayed
amounts. Payments can contain many component rows under one payment reference.
The source publishes whole-pound values, with a pound sign and thousands
separators, including negative and zero values. The adapter represents those
published whole pounds exactly in pence; it does not reconstruct undisclosed
original pence or infer a rounding-error bound. A total is exact for the
published values, not necessarily for an unpublished underlying ledger.

## Declared source-to-book mapping

| Source concept | HMRC field | DWP field | Preserved/modelled use |
|---|---|---|---|
| Date | `Date` | `Invoice Paid Date` | Validated DD/MM/YYYY, modeled effective date |
| Amount | `Amount` | `Transparency Invoice Amount` | Exact signed integer pence |
| Expense category | `Expense type` | `Invoice Account Description` | One stable modeled Expense leaf account per exact category string |
| Area | `Expense area` | `Invoice Cost Centre Description` | Preserved source dimension and independent dimension totals |
| Supplier | `Supplier` | `Supplier Name` | Preserved source string; no inferred party-identity merge |
| Reference | `Transaction number` | `Payment Number` | Preserved cross-row payment link; never treated as unique row id |
| Other fields | Department, entity, description, postcode | All original columns | Original field dictionary in normalized records and provenance |

Each source row is identified by the **full source SHA-256 and its one-based
CSV record ordinal**, excluding the header. This remains unambiguous when raw
records are identical. A separate canonical field-dictionary digest binds each
decoded record. `raw.csv` retains the original source bytes unchanged.

Positive values debit the modeled Expense category and credit the
`published-payment-offset` account. Negative values reverse those sides. The
offset is explicitly an **Equity** account with no cash role. It asserts neither
an original bank account nor an original counterpart entry. Expense categories
are also modeled accounts, not claimed original chart-of-accounts codes. Source
capital-purchase labels remain intact even though this simple expenditure
model places every category under Expense; it does not produce a GAAP
classification of assets or expenses.

Nonzero records are grouped by effective date into modeled journal entries of
at most **12 source rows / 24 legs**. This deliberately bounds native proposal
size. The grouping is unrelated to source payment-group boundaries, which can
contain 1,204 rows. Every generated leg has a memo linking to its original row;
the full source fields remain in provenance rather than being truncated into a
bounded memo. No original posting timestamp, entered-by identity, approval,
invoice date or original journal grouping is invented.

Zero records carry the explicit disposition `unposted_zero`, with no entry or
leg ordinal. They remain counted in source controls and dimension totals and
are retained in the source/provenance records. Negative rows are never netted
away with positive rows before import.

## Deterministic output contract

One output directory represents one complete dataset:

| File | Contents |
|---|---|
| `raw.csv` | Exact original, hash-pinned source bytes |
| `records.jsonl` | Every decoded source row, exact amount, dimensions, raw fields and stable row id |
| `provenance.jsonl` | Every row's original fields and mapping to generated entry and leg ordinals, or explicit zero disposition |
| `chart.json` | Native `fa chart import` accounts: category Expense leaves and modeled Equity offset |
| `account_map.json` | Explicit identity map for all generated native account codes |
| `legacy.csv` | UTF-8 generic legacy GL with paired, signed-direction postings |
| `columns.toml` | Native legacy CSV column declaration, GBP unit and dataset-specific source-system identifier |
| `expected_tb.json` | Independent raw-source Decimal fold by account, gross debit/credit movement, signed/net sided balances, counts and source-row groups |
| `dimensions.json` | Independent source sums and counts by expense category, area, supplier, reference and date |
| `receipt.json` | Source/publication/licence links, limits, all source controls and SHA-256/byte bindings for the other files |

All monetary fields in JSON are **decimal strings containing integer pence**.
`expected_tb.json` uses `signed_minor = debit_minor - credit_minor`. Its
`debit_minor` and `credit_minor` are gross movements;
`balance_debit_minor` and `balance_credit_minor` are the net sided balance.
Use `signed_minor` for native migration trial-balance amounts.

The pure API `load_sources()` returns the pinned dataset declarations;
`build_bundle(spec, raw)` returns a mapping of filename to deterministic bytes.
A live runner can reconstruct this entire mapping from the pinned original CSV
and compare every file before touching a book. Checking only mutable hashes in
`receipt.json` would be insufficient: an attacker could alter both the
generated files and their receipt.

## Verification and limits

Run the offline helper tests:

```bash
python3 -m unittest discover -s tools/public-data/tests -p 'test_public_spend.py' -v
```

The unit fixtures are explicitly synthetic. They test malformed amounts,
invalid dates, header drift, encoding failures, mutated source bytes, changed
control totals, duplicate preservation, signed accounting, source-to-leg
mapping, zero disposition, bounded grouping, deterministic outputs and
non-destructive retries. Preparing each pinned full dataset exercises the
real-source parser and source-control checks. Native import, durable reopen,
trial-balance reads and outsider verification belong to the live runner; a
successful preparation alone makes no claim that those ran.

These extracts omit original double-entry counterpart accounts, opening
balances and other departmental activity. The model does not reconstruct tax
accounting, original accrual timing, bank reconciliation, full financial
statements, audited balances or fraud. A matching generated trial balance
validates this declared transformation and the native pipeline; it is not an
independent opinion on either department's accounts. The source-file controls
and alternative arithmetic implementation reduce shared parser/sign errors but
are not external audited trial-balance evidence.

The project's [forensic case-study plan](../../docs/FORENSIC_CASE_STUDIES_PLAN.md)
separately describes sourced reconstructions of WorldCom, Enron, Lehman and
other cases. Those reconstructions have different evidence and claim types.
This corpus adds whole-file public transaction processing without labeling it
as one of those companies' unavailable complete ledgers.

## Attribution

Contains public sector information licensed under the
[Open Government Licence v3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/).
Source: HM Revenue & Customs and Department for Work and Pensions. The original
source links and per-file attribution are included in each preparation receipt.
