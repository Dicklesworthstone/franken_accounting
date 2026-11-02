# Replaying an authentic public general ledger

The public-ledger driver provides a native replay workflow for complete agency
selections from Oklahoma's published general-ledger data. It is designed to check
every monthly account balance against an independent integer fold of the source,
exercises migration staging and retries, and asks the standalone `fa-verify`
binary to verify an exported ADS package. It also corrupts a copy of that export
and requires the verifier to reject it.

This work extends plan §§5.8, 8.6, 9 and 16 and the `fa-yugf` public-record case
workstream. Existing WorldCom, Enron and Lehman cases remain useful bounded
reconstructions. This dataset adds actual published ledger activity, with an
automated download, preserved original records and a repeatable source-to-report
workflow.

## Validation status of this change (2026-11-02)

**Source acquisition, full-distribution profiling, normalization, and the 35
Python tests passed. Native end-to-end execution has not been completed.**

The original 113,856,733-byte distribution was downloaded and verified, all
373,357 rows were profiled, and `prepare` succeeded for all three complete
agency selections. The Python suite exercises the acquisition and normalization
code, independent source totals, strict refusal cases, and native-output
assertion helpers. Its constructed native-shaped test payloads are not evidence
that the accounting engine executed the workflow.

Rust formatting passed, and the standalone `fa-verify` binary built and ran its
help command. Three attempts to compile the native CLI or prerequisite test
dependencies were killed while compiling `asupersync` in an environment with
an 8 GiB memory limit. Consequently, the new Rust regression tests did not
execute and no agency has a native replay `PASS` report from this session.
A subsequent Tier0 attempt passed formatting but failed at check; full disk
prevented its diagnostic and summary files from being written. Tier0 did not
pass. Repository gate requirements and dependency pins were not changed.

The next acceptance step is to build on a sufficiently provisioned machine,
run the three commands below, and inspect each native `report.json` and
`commands.jsonl`. See
[the recorded validation status](../evidence/public_ledger/validation-2026-11-02.json)
for the exact separation of completed and unexecuted checks.

## What the publisher actually provides

The [State of Oklahoma General Ledger catalog](https://catalog.data.gov/dataset/general-ledger)
is published by the Office of Management and Enterprise Services (OMES). This
driver pins the [FY2024 Q4 CSV](https://data.ok.gov/dataset/dd1ecf41-4abc-4886-ab0f-b84d7662d8d4/resource/0c2a7e42-610e-4f1d-826f-f6b267fba68a/download/ledger_fy24_qtr4.csv):

| Property | Pinned value |
|---|---|
| Original byte count | 113,856,733 |
| SHA-256 | `141e2d5524f6aa9d25c7331bc56f623f43da9a1f00cdfee42b7c5f3ccf6fc0fe` |
| Encoding | Windows-1252; treating the original as UTF-8 fails |
| Data records | 373,357 |
| Source columns | 36 |
| Agencies / distinct account codes | 170 / 908 |
| Published fiscal periods | 10, 11 and 12 of FY2024 |

These are **monthly posted-activity aggregates by ChartField**, as the amount
column `SUM(L.POSTED_TOTAL_AMT)` and the source's grouping columns demonstrate.
The file does not contain original journal IDs, individual transaction dates,
approval identities or agency opening stocks. It is not a recovered complete
general ledger for Enron, WorldCom or Lehman, nor a complete transaction-level
history for an Oklahoma agency. The driver preserves all of the detail that this
publication actually contains.

The [OMES Statewide Accounting Manual](https://oklahoma.gov/content/dam/ok/en/omes/documents/statewide-accounting-manual-UA.pdf),
chapter 3, describes business units, funds, class funding, departments, account
codes and the other ChartFields. Chapter 4 describes the July 1–June 30 fiscal
year. Thus source periods 10–12 represent April–June 2024. The
[OMES contracts/revenue manual](https://oklahoma.gov/content/dam/ok/en/omes/documents/COR440.pdf),
printed pages 22 and 24, describes credits as negative general-ledger amounts.
The adapter consequently maps positive amounts to debit and negative amounts to
credit without passing through floating point.

The catalog identifies the dataset's license as
[Creative Commons Attribution](http://www.opendefinition.org/licenses/cc-by).
**Attribution: State of Oklahoma, Office of Management and Enterprise Services,
General Ledger, FY2024 Q4.** The committed CSVs are exact agency selections from
that distribution; their JSON sidecars identify the selection and every original
record position. Generated normalized files are transformations by this project.
The accounting manuals have their own notices; this repository links to them
and does not redistribute them under the CSV's license.

## The complete selections included for offline testing

All records for each named agency in the pinned quarter are included. The
fixtures are not random samples or balanced subsets chosen from within an
agency. Every selected agency's natural `(fiscal year, period, ledger, fund,
class funding)` group balances exactly in the original source.

| Business unit | Published entity | Original rows | Accounts | Natural groups | Debit activity, quarter |
|---|---|---:|---:|---:|---:|
| `31500` | Firefighters Pension & Retirement System | 137 | 51 | 12 | $262,659,554.11 |
| `66000` | Southeastern Oklahoma State University | 1,055 | 223 | 27 | $66,085,688.26 |
| `20400` | J. M. Davis museum | 125 | 43 | 19 | $260,793.80 |

Quarter debit activity is the sum of positive source rows, not revenue, expense,
net assets, or an agency financial-statement total. Credits match these debit
totals in each selected source group. The pension fixture includes the
alphanumeric class code `8315A`; identifiers remain strings throughout.

Fixtures live in `crates/fa-oracles/fixtures/public_ledger/`. Each `.json` sidecar
records both full-distribution and selected-file hashes, original logical-record
ordinals and physical line positions, per-period account totals, and distinct
values across all 36 fields. Fixture bytes and sidecars are checked together;
a modified input is refused before a native book is created.

## Run it

The [Public ledger native replay workflow](../.github/workflows/public-ledger.yml)
runs the Python source checks, builds the native binaries with the pinned
toolchain, executes the Rust CSV regressions, and replays all three agencies.
It uses committed source fixtures, records the exact tested commit and runner
resources, and retains reports and command transcripts as workflow artifacts.
Each agency still runs when another agency fails, provided the native build
succeeded. Read the workflow result and the individual replay reports for
execution evidence; configuration alone is not a successful native run.

Use the repository's pinned Rust toolchain and normal build lane:

```bash
cargo build -p fa-cli --bin fa -p fa-verify --bin fa-verify

# Fast complete-agency workflow, using the committed authentic pension data.
python3 scripts/public_ledger.py run --agency 31500 --out artifacts/omes-pension

# Larger complete-agency workflow, including all 1,055 published university rows.
python3 scripts/public_ledger.py run --agency 66000 --out artifacts/omes-university

# Another complete entity with small native entries.
python3 scripts/public_ledger.py run --agency 20400 --out artifacts/omes-museum
```

Where `rch` is configured, prefix the Cargo command with `rch exec --`, as
described in `AGENTS.md`. `--fa /path/to/fa --fa-verify /path/to/fa-verify` selects
already-built binaries. Python 3.11 or later is sufficient; these helpers have
no third-party Python dependencies.

The output directory must be new. A run never points at or modifies an existing
production book. Every native call uses the actual on-disk book, launches a
separate process, and records its arguments, exit status, stdout and stderr in
`commands.jsonl`. Environment `FA_BOOK` and `FA_TOKEN` settings are removed from
the child process so an unrelated configured book or credential cannot redirect
the exercise.

To fetch and inspect the **entire** statewide distribution:

```bash
python3 scripts/public_ledger.py fetch --out artifacts/ledger_fy24_qtr4.csv
python3 scripts/public_ledger.py profile \
  --source artifacts/ledger_fy24_qtr4.csv --out artifacts/omes-statewide-profile.json

# Select the same complete agency from the verified original download.
python3 scripts/public_ledger.py run --agency 66000 \
  --source artifacts/ledger_fy24_qtr4.csv --out artifacts/omes-university-from-original
```

The downloader identifies itself as this project, bounds the response size,
checks the exact byte count and SHA-256, and publishes only a verified complete
file. An existing matching download is reused. Different existing bytes or a
changed upstream resource cause an explicit failure; hashes are never silently
regenerated to make a changed source pass.

For an inspection without creating an accounting book:

```bash
python3 scripts/public_ledger.py prepare --agency 66000 --out artifacts/omes-prepared
python3 -m unittest discover -s scripts/tests -p 'test_public_ledger*.py' -v
cargo test -p fa-formats --lib legacy::tests::
```

`prepare` produces source and mapping material only. Its `PREPARED` status is
not an end-to-end test result. The native runner writes `report.json` with
`status: PASS` only after every required native operation and verification has
returned the expected outcome. A failed run exits nonzero, retains its command
transcript and writes `failure.json`; it never emits a partial success report.

## How the conversion preserves the source

1. **Verify the original bytes.** Admit the pinned statewide distribution or a
   checked-in complete-agency selection with its committed hash and record map.
   Decode Windows-1252 explicitly and require the full 36-column schema.
2. **Select the complete agency.** Parse all rows, preserve every identifier and
   ChartField string, and independently profile each natural source group.
   Refuse the entire selection if any group is unbalanced or any amount has
   subcent precision. Do not discard a troublesome group to make it balance.
3. **Create explicit aggregate entries.** A deterministic entry ID identifies
   each actual fund/class/month group. The date is its declared period-end
   convention. Each nonzero source monetary row becomes exactly one native leg
   with the original account code and exact signed amount. No counterpart is
   invented, no monetary row is split, and no opposing rows are netted away.
4. **Retain zero rows and dimensions.** A zero row has no native monetary leg,
   but remains in the original retained CSV and the manifest's explicit zero-row
   list. All 36 original fields also appear in each normalized nonzero row with
   `original_` column prefixes. The manifest binds each source ordinal to its
   aggregate entry, leg ordinal, account and cents. Original and normalized
   sources are not confused: their hashes are separate.
5. **Use native migration semantics.** A fresh activity-only book has a July
   fiscal year and a 2024-07-01 go-live. Each actual fund/class gets one
   `FullDetail` run with three contiguous historical periods and no opening
   stock. This is a scoped activity ledger starting with the publication, not
   an assertion that the real agency had zero assets before April. Source-
   derived cumulative account controls are retained as documents and declared
   before import preparation. The native kernel computes its own tie-outs.
6. **Retain approvals and evidence.** The native importer retains sealed
   proposals. Two distinct local test principals approve each chunk and each
   finalization. Original selected bytes and the transformation manifest are
   attached as supplemental evidence to the staged entries. The harness checks
   staging before activation and exact retry identities after finalization.
7. **Compare and verify.** Compare every monthly account cell and cumulative
   account cell to a separate integer-cent fold of the original source fields.
   Read the earlier recorded prefix again, advance and verify native registers,
   produce ADS with proofs, verify it using the independent `fa-verify` binary,
   and require exit 8 for a corrupted copy of the extract.

The account-type crosswalk follows the manual's prefixes 1 assets, 2 liabilities,
3 fund balance, 4 revenues and 5 expenditures. Source account `631100`,
*Appropriated Transfers In*, belongs to other financing sources/uses. It has an
explicit `Equity` classification for this mechanical activity book; unknown
prefix-6 accounts are refused until someone supplies an explicit crosswalk.
This classification is not an interpretation of GASB reporting requirements.

Native source and control documents preserve provenance, but the controls are
**derived from the published source**. They are independent of the native
parser and ledger fold, not independent audited agency statements. Similarly,
the two test principal labels exercise the native separation-of-duties rule;
they do not prove that two independent humans authenticated an approval.

## What the complete statewide profile reveals

The exact pinned distribution has these source properties:

| Measurement | Value |
|---|---:|
| Positive rows | 324,013 |
| Negative rows | 36,761 |
| Zero rows | 12,583 |
| Positive amount total | $36,627,212,778.158 |
| Negative amount total | −$36,704,739,814.998 |
| Signed net | −$77,527,036.840 |
| Agency/period groups | 504 |
| Agency/period groups with nonzero net | 342 |
| Rows with subcent precision | 20 |

The profiler keeps integer thousandths to report the original fractional-cent
values exactly. All 20 occur in agency `22000`, fiscal period 11. A USD-cent
import refuses them; it does not round, truncate or silently register a different
meaning for USD. The nonzero statewide net is a property of this publication,
not a finding of misconduct or an explanation of why its scope does not balance.
The profile reports the affected groups and source ordinals for investigation.

## Verification boundaries and remaining work

- A successful native run would establish the tested source-to-accounting-to-
  extract checks for its complete published selection. Native execution is
  still unverified as recorded above. Even a successful run would not establish
  completeness of the publisher's internal system or original transaction history.
- All chartfields remain available in retained evidence. Only original account
  codes are projected into the native chart by this adapter. It does not claim
  that departments, projects and fund dimensions are native queryable dimensions.
- Run boundaries follow real fund/class boundaries to keep native control
  payloads bounded. Each migration activates atomically; finalizing the entire
  agency across several runs is not one atomic publication. The preactivation
  historical check uses the prefix before the first finalization.
- The larger selection still has bounded group sizes. It does not settle
  `fa-fdt`/`fa-zddh` large-entry and million-line bulk-migration acceptance.
  Unsupported native sizes must be reported, never addressed by inventing
  transactions or weakening limits.
- The offline verifier receives the trusted public key of the freshly created
  local test book from the caller. It does not learn its trust anchor from an
  untrusted incoming bundle, and this exercise does not authenticate an external
  agency's signing key.
- Proof verification checks the export's agreement with native journal history.
  Source-row preservation and the accounting crosswalk are separately checked
  by the pinned-source manifest and the original-source oracle. A native proof
  alone cannot establish that an upstream publication was complete or correct.

For a run's actual execution evidence, inspect its `report.json` and
`commands.jsonl`. The source/profile tests, targeted Rust tests and repository
gates remain separate claims; none substitutes for another.
