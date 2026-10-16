# The ledger workbench

The default local dashboard is now one coordinated workspace for balances,
recorded-time comparisons, general-ledger movement, effective-date aging, and
source-reference graphs. The original native accounting APIs remain authoritative;
no live accounting fold, posting API, new runtime dependency, or altered writer
lease is introduced.

```sh
# Existing native book and executable
python3 tools/dashboard/serve.py --book ./books/myco --fa ./target/release/fa --open

# Explicit synthetic preview; no native executable or book required
python3 tools/dashboard/serve.py --demo --open
```

The existing private launch URL and tab-scoped token mechanism are unchanged.
Python 3.10+ and a modern browser suffice for the companion. No npm, pip, CDN,
external fonts, analytics, or frontend build are required. Launch-time book,
principal, executable, and key selection remain outside browser control. This is
an owner-local read-only companion, not an Internet or multi-user service.

## A visual system, not separate report pages

The mineral/forest palette, lime navigation accent, consistent spacing, larger
numeric hierarchy, clear semantic icons, unified selection strip, and linked
inspectors apply across all views. Light and dark modes, narrow-screen layouts,
print-safe synthetic warnings, visible keyboard focus and reduced-motion support
are included. Cmd/Ctrl-K opens the command menu; mobile has a search button.

Account spotlight shows actual daily closing values from the native ledger, not
an invented trend. The adjacent evidence preview derives its nodes and counts
from the selected account's native period contributions. Account, entry, evidence,
and lineage inspection share the same side panel. The existing classic reports
remain available via `/reports.html#ledger` and `/reports.html#aging`; no old
application assets were deleted.

## Time lens: hold effective time fixed

Select one period, an explicit recorded snapshot A, and snapshot B (an exact
sequence or HEAD). `/api/compare` resolves B once, then reads A through the same
native stock-report API. It refuses mismatched books, periods, effective cutoffs,
modes or sequences. A failed second read cannot become a partial result. Equal
snapshots reuse the one native response rather than fabricating an empty report.

The view aligns account-code/native-unit rows and exposes exact **B minus A**
debit-minus-credit differences, gross debits and credits, pending columns, and
name/type changes. Net-neutral gross movement stays visible. Newly reported,
absent, metadata-only and unchanged rows are distinct; an absent row is never
labeled as a native verified zero. The displayed difference alone treats absence
as zero, and the table/export explicitly preserve presence flags.

This is a report-row comparison, not causal attribution, proof of identity
continuity across account codes, a signed restatement, or a counterfactual branch.
Native balance verdicts are preserved, including red results. CSV includes the
original book, mode, period, effective cutoff, both recorded sequences, native
unit, presence flags and exact differences.

## Evidence graph: explore actual references

An account graph joins returned contribution entries to their account and cited
document OIDs/commitments. Pending, posted and released columns remain distinct.
A current entry graph joins resolved leg accounts, its principal, document
metadata and supersession references. No source text becomes markup. A leg's
presence does not claim that it posted. Commitments identify documents; they do
not establish economic truth or authenticity.

The graph uses a deterministic initial layout with spring, repulsion and card
collision forces. These are **visual coordinates only**, never money. Dragging
pins nodes visually; dragging empty canvas pans. Zoom, fit, reset, search,
object-type filters, neighbor highlighting, a linked object inspector, and a
keyboard-accessible list view are available. Selecting an entry opens the native
current entry/evidence inspector; its two observation sequences are shown
separately from any earlier account snapshot.

Account graphs show up to 32 contributing entries, with omitted counts. Entry
graphs bound leg/document/lineage objects; all graphs refuse above 220 nodes or
600 relationships. These limits bound layout work, not the underlying native
query's work. No relationship is inferred from matching amounts or descriptions,
and distance, edge length, or node position has no accounting meaning. This is
not a funds-flow attribution or full-book graph-completeness claim.

## Stay oriented and exact

Each result has an explicit **View scope** inspector. Editing source controls
clears the old result and removes its export action immediately. Late replies
cannot restore old numbers under changed controls. Refresh to latest is explicit;
there is no background polling or automatic repair.

The existing general-ledger and aging models still check native running balances,
application arithmetic, age bands and reconciliation before display. Amounts and
recorded sequences stay as decimal strings and BigInt. Only normalized chart and
graph geometry becomes floating point. Different units are never combined.
Current calendar metadata and current entry/evidence observations are labeled
separately; period movement is not cumulative stock, and effective-date age is
not contractual overdue status.

## Test evidence

New standard-library tests:

```sh
python3 -m unittest discover -s tools/dashboard/tests -p 'test_compare.py' -v
python3 -m unittest discover -s tools/dashboard/tests -p 'test_workbench_assets.py' -v
node --test tools/dashboard/tests/workbench-model.test.mjs
```

These cover the native-response adapter contract, exact u64/i128 presentation,
net-neutral and metadata changes, row absence, source-reference joins,
commitment conflicts, bounded deterministic layout, visual pinning and real
loopback HTTP asset/session/origin contracts. Native-response fixtures are not
accounting-kernel oracles.

Optional rendered interaction tests, with Playwright already installed as a test
tool and an available Chromium:

```sh
python3 tools/dashboard/tests/browser_workbench.py --chromium /path/to/chromium
# Capture the actual synthetic render after the interface settles:
python3 tools/dashboard/tests/browser_workbench.py --chromium /path/to/chromium --screenshots ./workbench-previews
```

The browser test loads the actual HTML, CSS and module implementation bodies into
an **offline DOM fixture** with explicit synthetic API responses. It exercises
comparisons, invalidated late responses, failures, graph drag/zoom/list/inspection,
ledger and aging filters, exports, keyboard search, themes, mobile sizing,
reduced motion and print warnings. It makes no browser network request. It is
not evidence of native-book integration, ordinary HTTP/CSP/module bootstrap, a
cross-browser matrix, or formal accessibility conformance. Validate the ordinary
launcher against a trusted native development book separately.
