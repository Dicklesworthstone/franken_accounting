# Ledger movements and open-item aging

The local workspace now has **General ledger** and **Open-item aging** links in
its sidebar. Both views use the same private loopback server, fixed local book,
native CLI authority and exact-integer transport as the overview. No new package
installation, frontend build, Rust dependency or posting endpoint is required.

From the repository root:

```sh
python3 tools/dashboard/serve.py --book ./books/myco --fa ./target/release/fa --open
```

For a clearly labeled synthetic preview without a native executable or a book:

```sh
python3 tools/dashboard/serve.py --demo --open
```

Open the private launch URL, then select either report in the sidebar. The new
report page reuses the token already held in this browser tab's session storage.
A copied bare report URL in another tab is not an authenticated launch URL.

## General ledger: opening to closing

Choose one account, one native unit, an **inclusive from/to date range**, and
HEAD or an exact recorded commit sequence. The adapter calls the existing
`fa gl detail` command. The native report supplies opening stock, each posted
movement, its complete entry digest and leg ordinal, its running balance, and
closing stock. The dashboard checks those columns agree before rendering them;
it neither repairs a mismatch nor substitutes a zero for a missing cell.

The chart shows **daily closing balances at the selected recorded snapshot**,
with the opening and final closing values. Hover or keyboard-focus a point for
its exact value; select it to filter the movement table to that date. The table
keeps the native effective-date/recorded-sequence/digest/leg ordering and running
balances of the *full* report even when the table is filtered. Pending
reservations are not posted movements, and reversing movements remain visible.

Daily closings do not expose every intraday extreme. Large charts use a bounded
first/minimum/maximum/last envelope over daily points; the caption says when this
happens. No movement rows are dropped from the searchable, paginated table or its
filtered CSV export. Chart dimensions are normalized from exact integer
*differences*, so a cent change above JavaScript's safe-integer range is not lost.
A flat nonzero balance remains distinct from an absent account/unit cell.

All ledger amounts use the native **debit-minus-credit** convention, including
credit-normal accounts. This is not a classified cash-flow statement or a claim
about the balance actually known on each movement's recorded day. Full entry
digests are available in the movement table; they are not treated as 32-hex
entry vertex handles or converted into invented drilldown links.

## Open-item aging: no implied overdue status

Choose one explicit account, an inclusive effective cutoff, a recorded snapshot,
a display unit, and 1–12 increasing whole-day upper bucket bounds. The default
`30,60,90` creates **0–30, 31–60, 61–90, and 91+ days**. Ages are measured from each
item's effective date, not from a contractual due date. They do not establish
that an invoice is overdue or that an account is a receivable or payable.

The adapter first runs `fa gl aging`, then runs its native `--reconcile` variant
at the **same resolved commit sequence** and with the same account, date, and
buckets. A refused second read prevents a partial success display. A returned
red reconciliation remains red, including an account-wide failure in a unit
other than the one currently displayed. An absent unit reconciliation row is
labeled **unreported**, not a verified zero.

Separate debit and credit cards and bars preserve gross open amounts; opposite
sides are never silently netted. Selecting a band filters the item table. Filter
by side or entry/date, sort oldest first or by exact open amount, and inspect
original, applied-in, applied-out, and remaining amounts. Filtered table totals
do not relabel the full-scope summary cards.

Select an item's entry handle to inspect its current entry, resolved legs, and
evidence commitments. Those existing APIs are current-state reads: their entry
and evidence observation sequences are shown separately from the historical
aging snapshot. No document content is fetched, and no later review is presented
as if it were known at the earlier report coordinate.

The synthetic sample deliberately contains no settlement links. Its debit and
credit legs remain separate open items, even when a description mentions a
payment. The preview must not manufacture settlement history to look realistic.

## Selection integrity and export

Changing an account, unit, date, snapshot, or bucket selector clears the previous
result and disables its export. Late replies cannot restore an old report under
new selectors. A new request must complete before another result is shown.

CSV exports retain the original report's live/demo mode, book identity, account,
native unit, recorded sequence, effective range, and exact native amount strings.
Search and chart filters affect the exported rows, not their running balances.
Formula-leading text is neutralized for spreadsheet import. Demo warnings remain
visible when printing, including after switching to dark mode. Downloads contain
financial data and remain the operator's responsibility to protect.

This is still a **read-only owner-local presentation companion**, not a native
`fa dashboard` subcommand, remote service, signed report, independent proof,
settlement tool, or automatic repair facility. Account suggestions are a
convenience from the initial overview; historical or other valid account codes
can be entered explicitly. Native read limits and missing history can refuse a
selection. Consult the main dashboard README for launch and security boundaries.

## Regression commands and evidence classes

Standard-library adapter and model tests:

```sh
python3 -m unittest discover -s tools/dashboard/tests -v
node --test tools/dashboard/tests/amounts.test.mjs tools/dashboard/tests/report-model.test.mjs
```

The new report tests exercise a **real Python HTTP listener** for private routes,
headers, static asset MIME types, denied methods, unknown inputs and exact integer
transport. Native CLI calls in the contract tests are controlled fixtures, not a
Rust accounting-kernel integration run. The pure JavaScript model tests cover
large exact amounts, ordering, scope rejection, date handling, sampling,
application balances, reconciliation, exports and stale-response invalidation.

An optional **offline Chromium DOM fixture** test exercises the actual report
HTML, CSS and JavaScript with explicitly synthetic in-memory responses:

```sh
# Requires Playwright already installed as a test tool, not a dashboard dependency.
python3 tools/dashboard/tests/browser_reports.py --chromium /path/to/chromium
# Optional screenshots of the synthetic render:
python3 tools/dashboard/tests/browser_reports.py --chromium /path/to/chromium --screenshots ./report-previews
```

That test makes no browser network requests. It tests rendered interaction,
keyboard chart filters, refusal handling, stale-result invalidation, entry
inspection, export scope, theme, mobile width and print warnings. It is **not**
evidence that the browser HTTP/CSP/module-bootstrap path or a real native book
was exercised. Validate those separately with the ordinary local launcher and a
trusted development book before relying on the native integration.
