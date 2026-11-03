# BLMIS published principal through native CSV migration

`scripts/blmis_migrate.py` exercises the actual generic CSV importer, retained
package, source binding, independent fixture approvals, grouped staging,
FullDetail finalization, certified balances and standalone report verifier.
It complements the direct-posting workflow in
[blmis_glantz_workload.md](blmis_glantz_workload.md). It implements a runnable
Glantz subset of the migration variant described by the
[case plan's M-T-03](FORENSIC_CASE_STUDIES_PLAN.md#93-claims).

## Published population and declared accounting model

Every invocation verifies the size and SHA-256 of the original public Glantz
complaint, extracts all fourteen Exhibit B pages, and retains all **379
observations across six accounts**. The original PDF, actual extraction text,
row literals, metadata, footnotes and discrepancy results remain available in
the output's `source/` directory. There is no generated-fixture fallback.

The exact migration population is:

| Account | Exhibit | Published observations | Printed-control treatment |
| --- | --- | ---: | --- |
| 1T0026 | B-1 | 117 | Exact credited-principal footing |
| 1ZA192 | B-2 | 75 | Exact credited-principal footing |
| 1ZB010 | B-3 | 61 | Exact under the disclosed `same_day_display_reorder` rule |
| 1ZB143 | B-4 | 51 | Exact credited-principal footing |
| 1ZR010 | B-5 | 57 | Retained discrepancy account, excluded from exact migration |
| 1ZR176 | B-6 | 18 | Retained discrepancy account, excluded from exact migration |

The first four accounts contain **304 observations**, including seven
zero-principal observations. The **297 monetary observations** become 297
balanced analysis entries and **594 CSV leg rows**. No original observation is
split across entries. Zero-principal observations remain in the source and
manifest; no zero monetary posting is invented.

For each monetary observation, the investor account receives the negative of
the published principal movement; one explicitly constructed account,
`BLMIS-MIGRATION-OFFSET`, receives its opposite. This combines cash and
trustee-credited transfers into the case plan's single counterpart model.
These are analysis accounts, not recovered BLMIS chart accounts or original
double-entry journal records. Credited transfer amounts are named trustee
oracle inputs. Reproducing them is not an independent legal net-equity finding.

The two excluded accounts' source differences are retained explicitly. The
driver neither rounds them away nor substitutes calculated balances for printed
cells to make an exact migration pass. Their direct-source replay remains
available in the six-account workload.

## Independent printed controls

The driver declares every monthly period from **November 1992 through December
2008**, a contiguous chain of **194 controls**, with a January 1, 2009 opening
date. For each account and month, it selects the last printed principal balance
on or before month end, naming the exact source row and source date. The
counterpart is the negated sum of those printed account cells. Zero lines are
omitted and the remaining lines are sorted by account code.

The control builder does not read movement columns or normalized entries.
Consequently the importer compares two separately constructed inputs:

- CSV entry amounts come from the published movement columns.
- Declared cumulative trial balances come from printed balance cells.

Quiet months carry the last published balance in this scoped model. A December
control can be anchored to an October source row; it does not assert the
existence of a printed December statement or undisclosed activity. Before an
account's first published observation there is no cited balance, so that
account is omitted. The from-inception baseline is an explicit scope choice.

One retained `printed-controls.json` Workpaper contains the complete set of
dated controls and their source anchors. Each native period declaration cites
that document and carries its own exact lines. FullDetail uses
`sole_opening_source`, with no separate opening-balance posting or detail base,
so finalization cannot double-count the imported history.

## Run it

The preparation-only command produces reviewable source, CSV, chart, mapping,
control and manifest files without requiring native executables:

```sh
python3 -B scripts/blmis_migrate.py prepare \
  --pdf /path/to/pinned-glantz.pdf \
  --out /path/to/new-migration-inputs
```

The execution command performs fresh preparation and then runs the complete
native workflow:

```sh
python3 -B scripts/blmis_migrate.py run \
  --pdf /path/to/pinned-glantz.pdf \
  --out /path/to/new-native-migration \
  --fa /path/to/fa \
  --fa-verify /path/to/fa-verify
```

Omit `--pdf` to fetch the pinned original. `pdftotext` is required for extraction.
The optional `--fad /path/to/fad` keeps the book open during grouped staging;
every entry still enters the native migration admission path. The default
group size is 64, configurable with `--stage-group-size`. A group preserves
separate native publications for its entries and is not reported as atomic.
Only finalization activates the entire migration in one publication.

Outputs must be new directories. Existing evidence is never overwritten. A
missing executable returns `UNRUN` with exit code 4 before creating output;
source, accounting or verification failures produce `FAIL` and retain the
completed evidence. `PASS` is written only after every requested native check
and independent verification has actually completed.

## What execution checks

The runner uses `fa migrate import --action prepare --bind-source`, verifies
every prepared entry's account, side, amount, date, period and unique identity
against the published rows, and checks the resulting native source manifest.
The native `source_rows` count is **594 normalized CSV legs**, distinct from the
304 included observations and 379 retained source observations. The
[source-binding contract](migration_source_completeness.md) authenticates that
prepared population; the acquisition and transformation checks independently
connect it to the published original.

Before successful preparation, the driver changes one monetary observation by
exactly $1 and changes its constructed counterpart by the opposite amount.
The pair remains balanced while the printed controls remain unchanged. The
native importer must refuse this twin at **prepare, exit 2**, with the exact
trial-balance mismatch diagnosis. The book frontier and empty run must remain
unchanged: no package, source binding or chunk can have been published. This
is the M-T-03 preparation negative, not a claimed finalize-time FA-REF-131.

The driver also tests source completeness with a **genuine offsetting pair**:
the $25,000 STOP PAYMENT and $25,000 CHECK printed for 1ZB010 on October 17,
2006. It initially stages the other **295 of 297** original package members.
The native run's monetary tie-out must still match all 194 monthly controls,
while its source binding must identify exactly the two missing entries.
`fa migrate finalize --dry-run` must then refuse in the actual native
transition planner with **exit 3, FA-REF-131**, reporting `295 of 297` exact
source chunks, `2 missing` and `0 unexpected`. Its frontier must be unchanged
and its state must remain Open. The driver then stages those same two retained
approved members and finalizes successfully. No source or proposal is
regenerated, and the negative does not require a fabricated transaction.

That omission check proves why a matching trial balance alone cannot establish
complete import: a transaction and its offset can both disappear without
changing any monthly net. It is distinct from the plan's additional monetary
native-chunk tie-out twin, which this driver does not claim to execute.

Source and helper documents are explicitly `AgentUpload`; a separate local
fixture principal records native Reviewed attestations. Two separately issued
Human fixture capabilities approve each retained proposal. These automated
roles exercise the evidence and segregation rules without claiming an
independent human examination.

Grouped staging and preparation retries must preserve original identities and
publication sequences. Staged entries must remain invisible in ordinary
balances, and an old prefix must remain empty after activation. Finalization
must activate the complete run in exactly one native publication. A terminal
preparation retry and a repeated staging selection must append no new history.

After activation the driver:

- Checks cumulative net balances against printed controls and final gross
  debit/credit totals against source movements.
- Exports the entire migration, runs native export verification, and checks
  every dated leg, exact description, citation memo, recorded sequence and
  `migrated_from` source identifier against the original observations.
- Certifies and byte-replays all 194 monthly trial balances; advances and
  verifies each period's registers; verifies projections.
- Produces a source-aware report bundle for every monthly certificate and
  invokes the actual standalone `fa-verify report` with a retained signed
  checkpoint, receipt and expected certificate identity.
- Checks that each bundle's source witness contains every expected prepared
  member, then confirms that changing a report bundle byte causes independent
  verification to fail with exit 8.

The checkpoint key is explicitly trusted for this fresh local analysis book;
it is not represented as a court or trustee signing key. The output preserves
binary identities, individual command stdout/stderr, exact requests, source
custody and approvals, reports, proof bundles and the terminal result.

Source dates and citation identities are retained. The named same-day
computation-order interpretation for B-3 is carried in the manifest. The
migration claims monthly control equality and exact dated entry coverage; it
does not manufacture a source time of day or original recorded sequence. The
deliberate omission-and-repair control publishes the withheld pair last; this
actual native publication order is preserved and is not described as the
exhibit's original sequence.

## Verification scope

Run the focused source and comparator tests with:

```sh
FA_BLMIS_GLANTZ_PDF=/path/to/pinned-glantz.pdf \
  python3 -B -m unittest discover -s scripts/tests -p test_blmis_migrate.py -v
```

The tests independently parse published amount literals with `Decimal` and
exercise changed dates, lost legs, duplicated identities, text and lineage
loss, and a balanced changed entry. Native-shaped unit inputs are explicitly
comparator fixtures; they are never evidence that the accounting engine ran.
The real PDF test covers the full 304-observation selection and 194 controls.

This driver is a standalone execution workload. It does not claim completion
of the case framework's entire M-T-03 bead, its separate native-chunk tie-out
twin, or migration of the other complaints' accounts. Native execution status
is recorded by each actual run's `report.json` or `failure.json`.
