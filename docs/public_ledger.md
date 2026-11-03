# Replaying an authentic public general ledger

The public-ledger driver provides a native replay workflow for complete agency
selections from Oklahoma's published general-ledger data. It is designed to check
every monthly account balance against an independent integer fold of the source,
including department account balances and their gross debit/credit activity.
It exercises migration staging and retries, checks every exported CSV and ADS
leg against its original source row, and asks the standalone `fa-verify` binary
to authenticate the ADS monetary fields and native dimension identities. Two
separate copies change one cent and one department identity respectively; both
must be rejected, including the case where every monetary amount is unchanged.

This work extends plan §§5.8, 8.6, 9 and 16 and the `fa-yugf` public-record case
workstream. Existing WorldCom, Enron and Lehman cases remain useful bounded
reconstructions. This dataset adds actual published ledger activity, with an
automated download, preserved original records and a repeatable source-to-report
workflow.

The [BLMIS Glantz transaction workload](blmis_glantz_workload.md) complements
these monthly public-sector aggregates with every dated transaction and printed
running principal balance of one published bankruptcy-case account. It preserves
the distinction between statement transfer amounts and trustee-credited principal.
Its acquisition, extraction, source controls and native replay have separate
validation records; a successful source check does not establish a native pass.

## Native replay validation (2026-11-03)

**Earlier account-level native replays passed for all three complete agency
fixtures, including independent proof verification and rejection of a one-cent
corrupted extract.** The current grouped-staging and department/export extensions
require their own native replay; the measurements below do not validate them.
The actual `fa` and `fa-verify` binaries executed 608 commands against fresh
on-disk books. Every monthly account cell, cumulative account cell, and gross
debit/credit account cell agreed with the original-source oracle.

| Agency | Original rows | Native monetary legs | Migration entries | Native commands | Observed seconds |
|---|---:|---:|---:|---:|---:|
| `20400` — museum | 125 | 121 | 15 | 191 | 26.479 |
| `31500` — pension system | 137 | 131 | 6 | 101 | 13.530 |
| `66000` — university | 1,055 | 1,051 | 27 | 316 | 132.771 |

The 14 zero-valued source rows remain in the original evidence and explicit
manifest dispositions. All 1,303 nonzero source rows became individual monetary
legs without netting opposing rows or inventing counterparts. Each run also
checked preparation and finalized-stage retries, preactivation invisibility,
historical reads, native registers, projection integrity, and a signed
accumulator checkpoint. All 73 helper-uploaded source/control documents retained
native self-sourced `AgentUpload` custody and received separate native `Reviewed`
attestations from a distinct fixture principal. A final native inventory check
confirmed that each document's original grade, commitment, and birth sequence
remained unchanged. Durations are observations under concurrent diagnostic
workloads, not performance benchmarks.

Actual execution found and fixed two driver defects: document intake requires
a MIME value without spaces, and June 30 must be routed explicitly to the
source's normal fiscal period because it also belongs to year-end adjustment
and closing periods. The driver now preserves the Windows-1252 declaration as
`text/csv;charset=windows-1252` and supplies `entry_periods` for every source
aggregate. The native refusal rules and reconciliation assertions were retained.

Review also found an incorrect `HumanUpload` assertion in the original driver.
That assertion was removed, and all three agencies were rerun from fresh books
with native automatic-upload custody and explicit fixture review attestations.
The results above are from those corrected runs. The document reviewer and
approval principals are operated by this same harness: their native records
exercise the review and separation-of-duties laws, and do not constitute
independent human review or an audit.

The [execution record](../evidence/public_ledger/validation-2026-11-03.json)
contains per-agency results, checks, source and binary hashes, original report
and command-transcript hashes, reproduction commands, the two initial native
failures, and the superseded runs with incorrect asserted custody. Full
generated books and private keys are not committed. The earlier
[unverified validation record](../evidence/public_ledger/validation-2026-11-02.json)
remains as a record of the previous build failures; it is superseded for these
three native replays.

Source acquisition and profiling had already verified the original
113,856,733-byte distribution and all 373,357 rows. The 36 Python checks passed
again after the driver repairs. Those helper checks, the separately executed
705 targeted Rust tests, and these real-corpus runs are distinct evidence.
None substitutes for Tier0 on the final exact committed tree, or establishes
that the entire statewide publication is admissible as one balanced USD-cent
ledger. **These native measurements precede grouped staging, department
projection and the source/export dimension checks described below. They do not
establish execution of those additional checks.**

### Grouped staging and department extension validation boundary

The department extension arrived concurrently with the native account-level
validation. All 61 integrated public-ledger Python checks pass, covering
source/export department negatives, grouped staging receipts, source custody and
document review. Development Finance Authority helper validation is recorded
separately. These helper checks do not establish a native grouped-staging or
department PASS.

The Development Finance Authority helper's 18 offline tests include the native
column-map contract: generated TOML contains only the declared columns, while
the native intent supplies the account mapping once. The earlier native attempt
exposed a duplicate `account_map`; the corrected workflow needs its own native
rerun before it can be recorded as a PASS.

The official 113,856,733-byte resource was downloaded through its actual HTTPS
redirect and verified against the fixed SHA-256. The complete 373,357-row file
and the committed museum, pension and university selections produce identical
original CSVs, charts, column maps and normalized run CSVs with the department
projection enabled. Complete manifests differ only in their declared input
kind and input hash; source-row mappings, department inventories, monthly
department/account net and gross controls, and every other field agree.

The Python tests independently fold the original source fields and build CSV
and ADS assertion fixtures directly from the original records for all three
complete agencies. Neither normalized run files nor the manifest supply those
fixtures' monetary amounts or department codes. Negatives change only a
department while preserving every monetary amount. They also check leading
zeros, blank values, missing dimension tags, wrong native identities,
zero-net/nonzero-gross activity, scope, export row coverage and order, declared
dimension coverage, grouped stage receipts and exact report-replay comparisons.
Constructed native-shaped payloads and exports in those tests are not evidence
that the accounting engine or its real exporter ran.

The [first hosted replay](https://github.com/Dicklesworthstone/franken_accounting/actions/runs/41544280544)
at commit `14dc993adc6f63d8a77c41080c186a39af62731d` built both native binaries
and passed all 11 legacy-format Rust tests present at that commit. All three
agency replays then failed during original-source intake: Docket refused a
space in `text/csv; charset=windows-1252`. The driver now sends the admitted
`text/csv;charset=windows-1252` token while retaining the exact original bytes
and encoding. The regression checks both native token restrictions and MIME
charset semantics. That earlier build does not validate subsequent Rust or
runner changes, and it did not reach migration, reports, or proof verification.

The upload path now also records its actual `AgentUpload` provenance and requires
a native `Reviewed` attestation by a distinct local fixture principal before
using each source or helper document. Misgraded receipts, reviews of a different
document, and refused reviews fail the run. The earlier account-level native
PASS is not attributed to the grouped-staging and department extensions. Their
acceptance requires running the workflows below and inspecting the actual
`report.json` and `commands.jsonl`; no repository-wide gate PASS is claimed here.

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

Within each migration run, the driver obtains a separate approval pair for
every source chunk and sends one retained selection to `migrate import --action
stage --intent`. Complete source authentication is shared across the request;
each chunk still has its own native publication and immutable receipt. The
driver checks every approved identity and publication sequence, including a
grouped retry after finalization. A later refusal does not undo earlier staged
chunks, and no staged balance is activated before native finalization.

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
   aggregate entry, leg ordinal, account, department and cents. Nonblank
   `DEPTID` values are registered as native departments, and the explicit
   `column_map.toml` maps `original_DEPTID` to each corresponding native leg.
   Original and normalized sources have separate hashes.
5. **Use native migration semantics.** A fresh activity-only book has a July
   fiscal year and a 2024-07-01 go-live. Each actual fund/class gets one
   `FullDetail` run with three contiguous historical periods and no opening
   stock. This is a scoped activity ledger starting with the publication, not
   an assertion that the real agency had zero assets before April. Source-
   derived cumulative account controls are retained as documents and declared
   before import preparation. Each source aggregate is explicitly routed to its
   published normal fiscal period, including June 30 where year-end periods
   overlap. The native kernel computes its own tie-outs.
6. **Retain custody, reviews, approvals and evidence.** Automatically acquired
   or generated documents retain self-sourced `AgentUpload` provenance under a
   named uploader; the driver checks each native receipt's grade and identity.
   A distinct fixture principal records a native `Reviewed` attestation with
   `approve` authority, without
   changing the original document's custody. The native importer retains sealed
   proposals. Two local fixture principals approve each chunk and finalization.
   All these roles are operated by the same harness, not independent human
   reviewers. Original selected bytes and the transformation manifest are
   attached as supplemental evidence to staged entries. The harness checks
   staging before activation, exact retries after finalization, and unchanged
   original document grades, commitments and birth sequences.
7. **Compare and verify.** Compare every monthly account cell and cumulative
   account cell to a separate integer-cent fold of the original source fields.
   Compare each department's monthly and cumulative account cells, including
   both gross sides; retain and replay each department's final-quarter report.
   Read the earlier recorded prefix again, advance and verify native registers,
   and produce canonical CSV and ADS. Re-read both native coordinate
   certificates and compare every exported leg's account, side, amount, date
   and dimension set against the source manifest and actual native identities.
   Verify ADS with proofs using the independent `fa-verify` binary, require
   dimension coverage for every monetary row, and require exit 8 for each of
   the money-only and dimension-only corrupted copies.

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
The source-review principal has the same local-test scope. A helper-created
workpaper does not claim the receipt-derived `Generated` grade: ordinary document
upload cannot supply that grade's required generation receipt. Its actual upload
and subsequent review remain explicit in the native evidence history.

## Query the original departments

The import projects the source `DEPTID` into the native `department` dimension.
It registers the source code and description before preparing migration
proposals, then checks every prepared leg's native dimension identity against
its original record. The pension's `0100001` remains the string `0100001`;
it is never converted to the distinct identifier `100001`.

For the pension book produced by the commands above:

```bash
fa --book artifacts/omes-pension/book tb --period FY2024-P10 \
  --dimension department=0100001 --activity --json

fa --book artifacts/omes-pension/book tb --period FY2024-P12 \
  --dimension department=0100001 --certify --json
```

The second command returns the cumulative department trial balance followed by
its retained report certificate. `fa replay C:<certificate-oid>` reproduces
that report at its original recorded prefix. The driver checks this replay for
every registered department, as well as the empty preactivation views and all
three months of departmental net and gross activity. A wrong department tag
must fail even when every whole-agency account balance remains unchanged.

Department slices may be unbalanced: a cash or fund leg can have a blank
department while its counterpart names a department. Blank and whitespace-only
source values remain **untagged**. They are retained under the empty key in the
manifest's `department_activity` oracle, not assigned to an invented native
value. No department is forced to balance. Nonblank codes with surrounding
whitespace, invalid native code characters, or conflicting source descriptions
are refused explicitly. All original fields remain available in retained
evidence; a missing description uses the explicit label `OMES department <code>`.

This import checks registered department identities and agreement with the
published historical attribution. Native migration retains that attribution
without applying today's required-dimension or value-effectivity policy to old
records. Fund, class funding, project and other chartfields remain in evidence;
this adapter does not yet project them into native dimensions.

## Import existing parties and legal entities from generic CSV

The generic CSV importer also accepts `party` and `legal_entity` in
`[dimension_columns]`, alongside ordinary dimensions such as department,
fund and project. This is useful when a legacy ledger already identifies the
customer, vendor, investor or subsidiary on each source posting.

These columns contain **existing native codes**. Declare the legal entities
when creating the book and register each party with `fa party add` before
staging. The importer resolves the codes to their native dimension values; it
does not create parties or entities, infer a counterparty from an account name,
or transfer a raw dimension VID from another book.

For example, the following column map preserves all three source fields:

```toml
[columns]
source_system = "legacy-csv"
entry_id_column = "Journal"
effective_date_column = "Date"
account_column = "Account"
signed_amount_column = "Amount"

[dimension_columns]
party = "InvestorID"
legal_entity = "Company"
department = "DepartmentID"
```

A four-row source can contain two independently balanced entities:

```csv
Journal,Date,Account,Amount,InvestorID,Company,DepartmentID
A,2025-12-20,1000,100.00,Case-001,Entity-A,0100001
A,2025-12-20,3000,-100.00,,Entity-A,
B,2025-12-29,1000,25.50,case-001,Entity-B,0100001
B,2025-12-29,3000,-25.50,,Entity-B,
```

This example assumes the accounts, the department, both legal entities and
both counterparties are already declared. `Case-001` and `case-001` are
different parties. The blank equity-leg party and department cells remain
absent. No placeholder party is invented to make a dimension slice balance.

| Source mapping | Native dimension ID | Native posting requirement |
| --- | ---: | --- |
| `legal_entity` | 1 | Names one of the book's declared entities. Every leg must name an entity in a multi-entity book, and each entry balances independently per entity and unit. |
| `department` | 3 | Names an existing registered department value. A historical Migration preserves its original attribution. |
| `party` | 12 | Names an existing Party's dimension value. A blank source party stays absent unless the account's native posting law requires one. |

Party codes are bounded by the native 64-byte UTF-8 contract; legal entity
codes by the native 32-byte contract. Nonblank values retain their exact case,
Unicode and surrounding spaces. Whitespace-only cells mean absence. Ordinary
dimension codes retain their stricter printable-ASCII identifier contract.
The importer never trims a nonblank code to make it match a different object.

Preparation retains the exact source, column map and sealed leg proposals.
Changing only a party or entity changes the source attribution attestation;
changing only a retained proposal's dimensions fails source replay even when
every account total still agrees. The native staging transaction checks value
existence and per-entity balance. Missing parties, undeclared entities,
missing mandatory entity tags and entries that balance only across entities
refuse without posting a partial chunk.

Staging remains invisible until finalization, and exact retries retain the
same dimension identities. Existing CSV, ADS, SAF-T and other dimension-aware
exports carry these IDs through the same `fa-dimension-ids-v1` contract.
These IDs prove identity within the exporting book; the source crosswalk
remains necessary to explain what each code means.

This generic mapping does not infer investor or legal-entity meaning for OMES
chartfields. The public OMES adapter still projects only the fields described
above.

**Validation boundary:** new format and persisted CLI regressions cover the
simultaneous entity/department/party mapping, case-distinct counterparties,
retained-package substitution, activation/retry and dimension-preserving CSV
and ADS certificates. They also exercise missing references and a globally
balanced entry that violates per-entity balance. Those new Rust tests are
**UNRUN** in this authoring session: the prerequisite native build was
unavailable and the executor subsequently disconnected.

## Preserve attribution through CSV, ADS and offline proof verification

The native format journal carries every leg's complete dimension set, including
an empty set for an untagged leg. Canonical CSV adds `dimension_set_v1` and ADS
adds `FA_Dimension_Set_V1` when at least one exported leg has a tag. The extra
column then appears on **every** monetary row, including an empty field for an
untagged row. CSV's coordinate header and `ADS_Coordinate_Certificate.toml`
declare `dimension_encoding = "fa-dimension-ids-v1"` using their respective
metadata syntax. Historical exports without this extension keep their
13-column representation.

The encoding is an ordered, unique list of native kind IDs and 128-bit native
value VIDs, for example:

```text
3:0000000000000000000000000000000a;7:0000000000000000000000000000000b
```

The decimal kind IDs and 32-digit lowercase hexadecimal value VIDs are exact
identities. This field does not embed a department code, display name or a
dictionary proving what a source code means. The driver obtains native
identities from its actual department registrations and independently binds
them to the retained original `DEPTID` values. It also binds the original
aggregate entry IDs to the actual prepared native proposals. Both CSV and ADS
are checked against that source mapping, rather than against each other.
Losing, inventing, substituting or reordering a source leg fails the run;
changing its department fails even when the whole-agency trial balance agrees.

The independent verifier compares each exported dimension set directly with
the corresponding leg in its authenticated native proposal. Its JSON
`ads_extract` check reports `detail.dimension_rows`: a number when the declared
extension covers every row, or `null` for a historical 13-column extract. The
public-ledger run requires the number to equal the complete agency's monetary
row count before it can produce `PASS`; monetary verification alone does not
satisfy that condition.

The output retains the accepted `gl.csv` and `ads/` package, plus two independent
negative controls. `ads-tampered/` changes one cent.
`ads-dimension-tampered/` changes one native value VID in a tagged row, preserving
all 13 monetary and text fields, every other dimension, and the original line
ending. The actual `fa-verify ads` process must reject each with exit 8.
`report.json` records the source comparisons, explicit dimension coverage,
exact tamper mutations and verifier responses. The dimension proof establishes
agreement with native journal history; the separate source oracle establishes
agreement with this published source's attribution.

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

- The three successful native runs establish the tested source-to-accounting-
  to-extract checks for their complete published selections. They do not
  establish completeness of the publisher's internal system or original
  transaction history.
- All chartfields remain available in retained evidence. Original account codes
  and nonblank departments are projected into the native chart and dimension
  values. Other chartfields are not yet native queryable dimensions.
- Run boundaries follow real fund/class boundaries to keep native control
  payloads bounded. Each migration activates atomically; finalizing the entire
  agency across several runs is not one atomic publication. The preactivation
  historical check uses the prefix before the first finalization.
- Import preparation supports an explicit `--bind-source` opt-in before
  staging. Its immutable native manifest retains source/package commitments
  and the complete ordered proposal inventory. For a bound run, staging admits
  only its exact members and finalization requires the complete population as
  well as the declared trial balances: omitting an increase and its exact
  reversal refuses even when every net balance agrees. Default preparation
  remains unbound; already staged or terminal unbound runs cannot acquire a
  retrospective binding. The historical execution evidence above is unchanged.
- [Source-bound migration completeness](migration_source_completeness.md)
  establishes membership against the retained prepared package. It does not
  independently replay the CSV transformation or establish the source's
  economic truth or completeness outside that package. The replay drivers
  still check every source chunk and gross activity against the original
  source. Portable proof coverage states whether the manifest was supplied
  and verified; an arbitrary Workpaper or a CLI count cannot establish it.
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
