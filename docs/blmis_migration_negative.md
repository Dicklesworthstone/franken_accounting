# BLMIS monetary finalization control

`scripts/blmis_migration_negative.py` checks the native monetary finalization
law with the complete seven-account population from the
[published-principal migration](blmis_migration.md). It complements that
workflow's source-bound preparation, omission, repair and activation checks.
The additional boundary is a balanced monetary alteration that reaches the
native finalization planner with every selected observation present.

## Original evidence and exact control

Every run re-extracts both pinned original filings. It retains all 379 Glantz
and 2,364 Magnify source observations, then selects the seven accounts whose
printed principal cells foot exactly under the disclosed interpretation:
Glantz `1T0026`, `1ZA192`, `1ZB010`, `1ZB143` and Magnify `1FN025`, `1FN097`,
`1FR051`. Their **393 observations** include **371 monetary observations** and
22 zero-principal observations. The source CSV contains 742 monetary legs.
The original PDFs, raw literal tables, source metadata and all **217 monthly
printed controls**, December 1990 through December 2008, remain unchanged.
See the [Glantz](blmis_glantz_workload.md) and
[Magnify](blmis_magnify_workload.md) source documentation for provenance and
the retained discrepant accounts.

This is the same explicit analysis model as the positive migration: a
credit-normal principal account and the constructed
`BLMIS-MIGRATION-OFFSET` counterpart. It is not a recovered BLMIS general
ledger, and reproducing trustee-credited transfers is not an independent
legal net-equity conclusion.

The target is one actual Glantz observation:

| Source field | Value |
| --- | --- |
| Row identifier | `SRC-BLM-001:1T0026:p27:l16` |
| Published date and description | November 19, 1992, `CHECK WIRE` |
| Original published deposit | USD 2,800,000.00 |
| Positive principal / counterpart legs | −USD 2,800,000.00 / +USD 2,800,000.00 |
| Negative principal / counterpart legs | −USD 2,800,001.00 / +USD 2,800,001.00 |

The two native chunk intents differ only in these two amount literals. Dates,
source identity, descriptions, source citations, evidence and account
identities are identical. A separate retained Workpaper labels the deliberate
counterfactual; the original source row is never edited.

## Matched native books

The runner creates a new, explicitly **unbound** `FullDetail` run, retaining
the original printed controls and `sole_opening_source` rule. It uses the
native CSV importer to prepare all 371 original entries and checks each
proposal against the source. It then obtains native approvals and stages the
370 unchanged observations through native grouped staging.

After the embedded native processes have closed, it copies this complete
unactivated book prefix to a new positive-control directory and verifies
every file's length and SHA-256 before and after the copy. This is a controlled
filesystem copy, not a claimed native branching feature. There is no resident
daemon. Both books start at the same native frontier, with the same 370
original receipts, source documents, account identities and review tokens.

The same manual adapter then plans, obtains two native fixture approvals for,
and stages the remaining observation in each book. The positive control uses
the original amount; the negative uses the balanced one-dollar alteration.
Each book must contain all 371 entries, with exactly the unchanged 370-member
prefix plus its individually approved target. Native `entry show` checks the
target's publication receipt, proposal digest, dates, description, citations,
amounts and two approvals. The altered amount must change the approved native
proposal digest.

The positive twin must tie to every printed control and successfully produce
a native finalization **plan**. The negative twin must identify exactly 388
monetary mismatches: principal −100 cents and counterpart +100 cents in each
of the 194 controls from `FY1992-P11` through `FY2008-P12`. The preceding 23
controls remain unaffected. Both raw `migrate show` observations and the
finalize refusal must name the exact period, account, unit, printed amount and
folded amount; recognizing a refusal code alone is insufficient.

The expected matrix is independently derived with `Decimal` from the raw
published amount and balance literals. Its compact canonical JSON SHA-256 is
`061314cd52aa21432bc0cfb3aa450478356a83f76b420093874f5439653acc4f`.
The focused source test compares all 217 original printed-control vectors and
all 388 expected mismatch objects, without deriving its expectations from
native results or normalized movement fields.

The negative planner must return **exit 3 / `FA-REF-131`** with the monetary
tie-out message and leave no finalization plan. In both twins, planning must
leave the publication frontier unchanged, the run `Open`, and ordinary trial
balances empty. The runner deliberately does **not activate either twin**.
Positive planning acceptance is not reported as finalization or activation.

## Why this control is unbound

The ordinary migration remains source-bound. Its package-integrity and
completeness checks correctly prevent changes to retained source proposals.
This separate experiment intentionally opens a new unbound run so the single
altered manual chunk reaches the native monetary tie-out law. It does not
change an existing bound run or weaken its checks.

After the manual target is staged, the runner uses `migrate show` and
`migrate finalize` directly. Even an unbound retained import package continues
to enforce the identities of its original proposal members; the manual
target does not claim retained-package membership. The matched positive twin
establishes that the complete population and manual adapter work with the
original amount before the negative is interpreted as a monetary-law check.

## Run it

```sh
python3 -B scripts/blmis_migration_negative.py \
  --pdf /path/to/pinned-glantz.pdf \
  --magnify-pdf /path/to/pinned-magnify-affidavit.pdf \
  --out /path/to/new-monetary-control \
  --fa /path/to/fa \
  --fa-verify /path/to/fa-verify
```

Omit either PDF argument to fetch its pinned original. `pdftotext` is required.
The destination must be new; existing books and evidence are preserved.
Matching native executables are required by the shared runner. This control
invokes `fa`; it does not invoke `fa-verify` or independently verify a report
bundle. The source-bound migration and full replay workloads exercise those
separate verification paths.

The output retains both books, the hash-checked common-prefix manifest,
original source preparation, two manual intents and approved plans, native
run observations, complete command transcripts and either `report.json` or
`failure.json`. Missing native executables return `UNRUN` / exit 4 before
creating output. A source, accounting or comparator failure returns `FAIL`;
it cannot become the expected native monetary refusal.

Focused regression tests run with:

```sh
FA_BLMIS_GLANTZ_PDF=/path/to/pinned-glantz.pdf \
FA_BLMIS_MAGNIFY_PDF=/path/to/pinned-magnify-affidavit.pdf \
python3 -B -m unittest discover -s scripts/tests \
  -p test_blmis_migration_negative.py -v
```

The tests distinguish fabricated comparator envelopes from actual native
execution. They reject altered target identity, unsupported deltas, missing
or substituted chunk receipts, extra or changed mismatch cells, a refusal for
a different law, and unsafe reuse of an existing or symlinked copy destination.
Without both pinned PDFs, the original-literal oracle is explicitly skipped.

## Recorded native execution

The complete control **passed on November 3, 2026**, using the verified native
CI artifact built from Rust source commit
`88286f8c41f3943fde51e76334b33db758422c95`. The checked execution summary is
[seven-account-monetary-twin-native-2026-11-03.json](../evidence/blmis/seven-account-monetary-twin-native-2026-11-03.json).
It records the original source identities, exact driver/helper hashes,
compiler and lock identity, workflow/artifact provenance, executable hashes,
native receipts, report/transcript hashes and exact control results.

The run made **108 actual `fa` calls** in **43.074 seconds**; the outer process
returned exit 0 in 43.202 seconds. Native exits were 107 successes and the one
required monetary refusal. All 108 stdout hashes, 108 stderr hashes and 24
retained stdin hashes were checked against the complete command transcript.
The focused test suite also passed all 12 tests with both original PDFs
present, including the independently constructed full mismatch oracle.

The common 370-member prefix contained 10,246 files and 68,637,043 bytes. The
copy check verified identical bytes at native frontier 1535. Each twin then
recorded two fresh fixture approvals and its own final chunk at frontier
1538. The original amount passed native finalization planning. The altered
amount failed that same planner with precisely the 388 expected monetary
differences. Both books stayed at frontier **1538**, remained **Open**, and
returned zero visible ordinary trial-balance rows after planning.

The observed endpoint cells were:

| Period and account | Declared printed control | Altered native fold |
| --- | ---: | ---: |
| FY1992-P11, BLMIS-1T0026 | −USD 5,100,000.00 | −USD 5,100,001.00 |
| FY1992-P11, counterpart | USD 4,612,161.00 | USD 4,612,162.00 |
| FY2008-P12, BLMIS-1T0026 | USD 7,374,165.00 | USD 7,374,164.00 |
| FY2008-P12, counterpart | −USD 51,081,015.00 | −USD 51,081,014.00 |

The run used 15 `AgentUpload` evidence documents with native `Reviewed`
attestations from a distinct local fixture principal. Its reviewer capabilities
exercise automated role separation; they are not independent human or court
review. No standalone report verification was invoked in this specific
control, no twin was activated, and no bead closure is claimed. Current
whole-workspace cargo, clippy, tier0 and tier1 gates remain **UNRUN** in this
execution summary.
