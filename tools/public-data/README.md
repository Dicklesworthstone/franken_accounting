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

The complete HMRC March 2025 extract passed a fresh grouped native workflow on
2026-11-03: **1,430 original records, 127 migration entries, 2,860 monetary legs,
463 native calls and 113.172 seconds**. The process exited zero using frozen
binaries from `93714f772a6279c0ea233841d1d51dbe096d9ff1`, direct CLI transport,
and two initial staging groups of at most 64 independently approved chunks,
plus an exact first-group retry. The
[new execution evidence](../../evidence/public_spend/hmrc-2025-03-grouped-confirmation-2026-11-03.json)
retains the exact 20 completed checks, source/helper/executable identities,
report/export/transcript hashes, native custody and finalization coordinates.
It records 462 successful native calls and the expected exit eight when the
standalone verifier rejected a deliberately modified report bundle.

That run checked every dated exported leg and memo, exact gross and net account
totals, retained source byte identity, staged and historical invisibility,
original retry identities, certified replay and independent report verification.
The earlier complete [native execution result](../../evidence/public_spend/hmrc-2025-03-native-2026-11-03.json)
remains unchanged: 588 calls, 402.144 seconds and 18 completed checks. These are
separate development-host observations, not a controlled speed comparison.

A subsequent complete run enabled only `--batch-approvals`, retaining direct
CLI transport and 64-chunk staging groups: **219 native calls, 65.599 seconds
and all 22 checks passed**, with process exit zero on frozen
`f543eae8b535fc0b37936bc5094a459add26c5a3` binaries. Its six native approval-group
calls include the exact first-group retry by both issued reviewer principals;
two finalization approvals and all 127 evidence attachments remain separate.
The [approval-batch execution evidence](../../evidence/public_spend/hmrc-2025-03-batch-approvals-native-2026-11-03.json)
retains source/helper/native hashes, every earlier source/proof check, 256 fresh
approval receipts and 128 exact retry receipts. The source remains all 1,430
rows, 127 entries and 2,860 legs. The comparison with 463 calls and 113.172
seconds is diagnostic evidence from separate shared-host executions; both
earlier records remain unchanged.

The native report covers the explicitly modeled GBP expenditure and offset
accounts. Supplier, area, reference and other original fields remain in retained
source/provenance evidence and source-side controls; this runner does not claim
that all those fields are native queryable dimension tags. The extract supplies
no complete original general ledger, opening stocks or original double-entry
counterparts. The independent verifier checks the resulting analysis book under
its own trusted checkpoint key, not a department-signed or audited set of accounts.

The complete DWP January 2025 extract also passed its full native workflow on
2026-11-03: **13,099 original records, 1,091 migration entries, 25,930 monetary
legs, 3,375 native calls and 5,896.770 seconds**, with process exit zero and all
20 checks completed. Its 18 initial staging groups used at most 64 independently
approved chunks; approval and evidence commands remained separate. The
[DWP execution evidence](../../evidence/public_spend/dwp-2025-01-grouped-native-2026-11-03.json)
retains the pinned complete source, frozen `93714f77` executable/helper identities,
all transcript and exported-artifact hashes, 19 source/control uploads and
fixture review attestations, and six exact source-document readbacks. Every
dated exported leg and memo was checked, all 84 account registers matched the
native fold, finalization published at one commit, and the independent verifier
accepted the authentic 8,868,413-byte report and refused its modified copy.
This completed baseline predates explicit native source-population binding:
its portable report has major 1/minor 0, and it must not be described as a
source-bound run. All 283 negative rows, 134 zero observations and 31 additional
exact duplicate rows remain accounted for in the source controls and evidence.

Both complete datasets passed actual HTTPS acquisition and deterministic source
preparation. The execution timings above are diagnostic development-build
observations on a shared host, not release throughput benchmarks.

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

The runner records the initial SHA-256 identities of `fa`, `fa-verify` and,
when used, `fad` before its first native command. It checks filesystem identity,
size and timestamps before and after each invocation and checks all executable
paths again before accepting `PASS`. A detected replacement, rebuild or missing
executable makes the run fail, and `result.json` retains the original hashes.
Keep the supplied binaries unchanged for the entire run; a separate copy of a
completed build lets development continue elsewhere. These checks detect
ordinary concurrent changes, not hostile filesystem races.

Each forwarded stdin request is retained verbatim as a transcript `.stdin.bin`
file. Its path, byte length and SHA-256 appear in the corresponding `started`
record in `commands.jsonl`; the `completed` record is written only after the
process returns. If a command times out, its available partial stdout and
stderr are retained too.

The runner stages up to 64 independently approved chunks per request by default.
`--stage-group-size 1..4096` changes that bound. Each request authenticates the
complete retained source, mapping, proposals and required trial-balance
documents once, then submits each selected chunk to the native posting kernel
with its own approval pair. The saved `stage-*.json` files contain the exact
requests; their bytes are forwarded through stdin so the daemon needs no host
filesystem grant. The result records the group size and number of staging
requests, and the harness checks every receipt against the prepared source
proposal, including retry sequences.

### Approve a staging group without reopening the book for every proposal

For direct CLI runs, add `--batch-approvals` to use the native
[`approve --proposals` command](../../docs/approval_groups.md). This mode is
explicit: an older binary that does not support it refuses the run. The runner
does not silently fall back or change authority after a refusal.

```bash
python3 tools/public-data/run_live.py \
  --prepared /tmp/fa-public-hmrc --dataset hmrc-2025-03 \
  --out /tmp/fa-public-hmrc-batched \
  --fa /absolute/path/to/fa --fa-verify /absolute/path/to/fa-verify \
  --stage-group-size 64 --batch-approvals
```

Each staging group needs two native approval calls: one per separately issued
reviewer token. Both receive the identical ordered digest array through stdin;
each retains its exact bytes and native response in the transcript. The runner
requires a complete ordered receipt list, the expected book and reviewer,
distinct native approval identities, positive publication sequences and the
correct security-policy/retry fields before constructing each chunk's pair of
approvals. It explicitly retries both reviewers for the first group, requiring
the original IDs and sequences and an unchanged book frontier. Cached receipts
are only comparison evidence; every retry still reaches native authority checks.

Approval publication remains per proposal. If either reviewer returns a
committed prefix followed by a refusal, the run fails with that actual prefix
retained. It does not stage the incomplete group, manufacture approvals, reissue
tokens or use owner authority to continue. Separate finalization approval and
activation are unchanged. `result.json` records the chosen mode and the actual
number of approval-group requests, including the explicit first-group retry.
The ordinary per-proposal path remains the default and supports existing
binaries. Batch approval also works with `--fad` through the same bounded stdin
contract, where the execution environment permits native daemon sockets.

### Attach complete source evidence in bounded native groups

Add `--batch-evidence` to attach the original CSV, transformation receipt,
row provenance and complete normalized records to each staged entry through
[`document attach --entries`](../../docs/evidence_groups.md). It works
independently of approval batching; enable both for a large direct CLI run:

```bash
python3 tools/public-data/run_live.py \
  --prepared /tmp/fa-public-dwp --dataset dwp-2025-01 \
  --out /tmp/fa-public-dwp-batched \
  --fa /absolute/path/to/fa --fa-verify /absolute/path/to/fa-verify \
  --stage-group-size 64 --batch-approvals --batch-evidence
```

One bounded request holds the book open while each target receives its ordinary
native supplemental-evidence transaction. Current authority and target read
scope are rechecked for every member. The complete request is limited to
4,096 distinct targets, 1 MiB of target JSON and 16,384 target/citation pairs,
which bounds both processing and the repeated document details in the response.
The runner forwards the ordered entry array through retained stdin bytes and
checks every returned entry, source document OID, original document commitment
and evidence role. Every supplement must have a distinct native identity and a
publication sequence later than the complete staged group. The runner uses
the fixture book owner for attachments, including tokenless owner requests via
`fad`. It retries the first group and requires the original supplement IDs, body/entry commitments and sequences,
with no movement in the book frontier.

Each supplement remains individually durable. A refused later attachment leaves
its actual completed prefix in the transcript and the workload at `FAIL`.
`result.json` records the chosen mode and attachment-group request count. The
default individual attachment mode remains available for existing binaries;
there is no automatic authority change or fallback on a grouped refusal.
Grouping appends the same source-evidence records and leaves finalization,
source-to-export comparisons and independent proof verification in the workflow.

### Require the complete retained source population in native activation and proofs

Add `--bind-source` to use native
[`migrate import --action prepare --bind-source`](../../docs/migration_source_completeness.md).
This is an explicit compatibility choice: the default still prepares an
unbound legacy run, and requesting binding against an older binary fails.
For a complete large extract, all three options can be combined:

```bash
python3 tools/public-data/run_live.py \
  --prepared /tmp/fa-public-dwp --dataset dwp-2025-01 \
  --out /tmp/fa-public-dwp-source-bound \
  --fa /absolute/path/to/fa --fa-verify /absolute/path/to/fa-verify \
  --stage-group-size 64 --batch-approvals --batch-evidence --bind-source
```

Preparation first retains the native package, then binds its complete ordered
entry identities and proposal digests to the empty Open run. These are two
separate native publications. The runner checks both original receipt
coordinates and retries the same preparation before staging and after
finalization, requiring the original package, binding control and sequences
without publishing duplicates. The operation uses current migration authority;
all independent chunk approvals and finalization approvals remain required.
There is no fallback to an unbound run if binding fails.

The bound document is the complete normalized `legacy.csv`, whose original
bytes are read back before preparation. Its declared `source_rows` therefore
counts monetary ledger legs: **2,860 for HMRC and 25,930 for DWP**. It is not the
raw observation count of 1,430 or 13,099, respectively. The runner separately
retains and reconstructs the complete original government CSV, including the
134 zero-amount DWP observations, and checks every dated exported leg and memo.
The binding cannot establish transactions absent from the published source or
replace those independent transformation checks.

Before staging, every prepared member must appear in the native missing-member
list. Before activation, the same manifest must report every expected member
recorded, no missing or unexpected entries, and complete coverage. Native
finalization enforces this independently of the Python harness. An omitted
transaction and its offsetting reversal cannot pass merely because the net
trial balance still agrees.

The report must then use the source-aware minor version and carry exactly the
expected source manifest for this fresh single-run book. A bounded container
inspection compares the complete witness bytes, including the original
package order, against the checked native preparation and document commitments.
It does not decode or authenticate ledger records or signatures. The existing
standalone `fa-verify report` call must independently accept the actual bundle,
checkpoint, certificate and receipt; the tampered-bundle control must still
be refused. `result.json` retains the manifest identities, complete native
coverage, original binding receipt and observed report format. Runs executed
without this flag remain explicitly unbound evidence.

The same native interface can resume an interrupted import:

```json
{
  "chunks": [
    {"index": 0, "approvals": ["<reviewer-one-approval-vid>", "<reviewer-two-approval-vid>"]},
    {"index": 1, "approvals": ["<different-first-approval-vid>", "<different-second-approval-vid>"]}
  ]
}
```

```bash
fa migrate import --action stage --package D:<retained-package-oid> --intent stage-selection.json
# With a daemon and no filesystem grant, forward the same saved bytes:
fa --via fad migrate import --action stage --package D:<retained-package-oid> \
  --intent - < stage-selection.json
```

Chunk publications are individually durable. A group is not an atomic batch:
if a later chunk is refused, `migration_import_progress` records completed
receipts before the original error event and exit code. Retry the same package
and selection with valid proposal-bound approvals; already committed chunks
return their original sequences. Staged money remains invisible until the
separately approved native finalization activates the complete run. Malformed,
duplicate or out-of-range selections are rejected before any chunk is posted.

A `started` command without a completed receipt may still have committed one
or more chunks. After an interruption, inspect the retained package with
`--action show`, then retry its exact saved selection with valid approvals.
Do not infer the durable count from acknowledged receipts alone. The runner
keeps an incomplete execution at `FAIL`; recovering staged entries does not
establish that the remaining finalization, reports and verification checks
passed. It always requires a new `--out` directory; native commands provide the
recovery path for an existing retained book.

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
