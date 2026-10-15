# FrankenAccounting · Local workspace

A local browser dashboard for exploring a book without posting to it. The
accounting engine stays in `fa`/`fad`; this companion calls the existing versioned
robot API. It does not interpret database files, introduce another writer, or
replace the kernel with a web backend.

## Launch

From the repository root, with Python 3.10+ and an existing `fa` executable:

```sh
python3 tools/dashboard/serve.py --book ./books/myco --open
```

Supply the executable explicitly when it is not on PATH:

```sh
python3 tools/dashboard/serve.py --book ./books/myco --fa ./target/release/fa --open
```

Preview the complete interface without a binary or a book:

```sh
python3 tools/dashboard/serve.py --demo --open
```

Demo mode contains deterministic **synthetic** transactions. Its banner and
export metadata identify the data as synthetic; it is never a fallback after a
native error. Demo integrity results are interface examples, not native checks.

The launcher binds **only `127.0.0.1`**, selects an unused port, and prints a private
URL. `--open` opens that URL in the default browser. Otherwise paste it into a
local browser. Keep the URL private. Ctrl-C stops the server. Restarting it
creates a new token; use the newly printed URL, not an old bookmark.

No pip installation, npm install, frontend build, CDN, external font, cloud
account, or telemetry is required. JavaScript modules, BigInt, SVG, and native
HTML dialogs are required in the browser. A modern desktop browser is the target;
mobile-width layouts are supported, but the server does not accept LAN traffic.

Optional launch settings:

```sh
python3 tools/dashboard/serve.py \
  --book ./books/myco --fa ./target/release/fa \
  --keys ./private/myco.keys --as operator \
  --title "My company" --port 8088 --timeout 60 --open
```

`--title` is a display label, not a change to the book. Book, key-file path,
principal, executable, port and timeout are fixed by the local launcher, never by
browser request arguments. Omit `--keys` to use the native default. The normal
CLI/daemon writer-lease routing remains in effect; the companion does not force
`--via direct` or bypass a running daemon.

## Explore

**Overview.** Asset/liability stock, revenue/expense period activity, a signed
account landscape, an account-type composition chart, and a balance table. Select
a bar or account to inspect the actual contributing entries. The unit selector
never combines currencies or quantities. Cards identify their type and sign
formula; they are not classified financial statements or a cash-flow statement.

**Accounts.** Search by code or name, filter by account type, sort amounts exactly,
and page through the results. CSV export includes live/demo mode, immutable book
ID, display label, period, selected commit sequence and native unit. Amounts remain
strings with units; formula-leading cells are escaped for spreadsheet import.

**Fiscal periods.** View calendar boundaries and current states, then choose a
period. The dashboard cannot open, close, lock, reopen or redate anything.

**Evidence explorer.** Follow account -> contributing entry -> resolved legs,
source commitments, review metadata and supersession links, or paste an `E:`
entry handle. Graph nodes are keyboard- and pointer-selectable and move focus to
the full detail row/card. The graph shows up to six legs and four documents, with
full lists beneath it. It represents relationships, not inferred money flow.
Document content is not fetched. Entry-authored text is labeled and inserted as
text, never interpreted as HTML or instructions.

**Integrity checks.** Run the native triage and an explicit leg-projection check.
A native red result remains red, with its available detail. No automatic repair,
checkpoint publication, certificate creation, or background verification is
performed. A successful projection comparison is not a claim of source
immutability, evidence authenticity, professional judgment, or offline proof.

Use Cmd/Ctrl-K to jump to views and accounts; arrow keys and Enter select results.
Escape closes dialogs. The theme switch supports light/dark mode and remembers
only that preference. Focus indicators, semantic tables, dialog focus management,
a skip link, reduced-motion styling, and mobile layouts are included. Formal
accessibility conformance and a cross-browser matrix have not been established.

## Time and exactness

An overview first asks the native engine for stock at HEAD or an explicit commit
sequence. Its activity read is then pinned to the **same resolved sequence**. The
account drilldown retains that sequence. The adapter rejects mismatched native
coordinates rather than displaying a mixed-snapshot overview.

Stock includes opening history. `explain balance` is a selected-period movement
explanation, so its totals need not equal cumulative stock. Pending and released
contributions remain separately labeled. The table preserves the native `net`
field; category cards and signed bars explicitly compute debit-minus-credit or
credit-minus-debit from their displayed source columns.

`period list`, `explain entry`, `explain evidence`, and integrity diagnostics are
current-state APIs. Their observed sequences are shown separately. In particular,
a later review or supersession is never presented as if it were known at the
historical report snapshot. An entry/evidence pair can have two different current
observations. Use **Refresh to latest** to deliberately read a new overview; the
dashboard does not silently poll a moving book.

The gateway parses JSON integers exactly in Python and transports all integer
fields as decimal strings. The UI uses BigInt and decimal-scale alignment for
amount arithmetic, ordering and labels, including values above 2^53 and 18-place
units. Only final normalized chart geometry becomes a JavaScript Number; it is
not used to compute or export balances. Charts remain presentation, not proofs.

## Boundary and limits

This is an **owner-local read-only companion**, not a multi-user authorization
service or production web deployment. `--as` is the existing owner CLI's principal
claim, not authentication of a human. The session token gates browser access to
that launched companion; it is not an issued accounting capability.

The gateway validates exact loopback Host, Origin when supplied, Fetch-Site,
bearer token, parameters and method. It has no CORS permission, directory listing,
generic command/GQL endpoint, or native file-serving route. A restrictive CSP,
no-store headers and text-only rendering limit browser exposure. The token starts
in the URL fragment, moves to tab-scoped sessionStorage, and is removed from the
visible address. Book data is not stored in localStorage. Treat terminal output,
browser extensions, downloads, and the local OS account as trusted surroundings.
Never expose this service through a reverse proxy, port forwarding, or a tunnel.

Native reads are serialized and run without a shell. Each subprocess is limited
to 16 MiB of stdout, 64 KiB of stderr and 1–120 seconds (30 by default). The server
bounds concurrent accepted connections and applies socket read timeouts. Larger
reports fail explicitly; there is no silent truncation. Native folds may scan the
book, and the adapter starts a CLI process for each read. This does not establish
bounded native work or low latency for very large books. Browser financial data
exists in memory for the lifetime of the tab, and explicit CSV exports remain
files the operator must protect.

## Tests

The gateway and numeric regressions use only the Python and Node standard
libraries. Node is a test tool, not a runtime dependency for the dashboard.

```sh
python3 -m unittest discover -s tools/dashboard/tests -v
node --test tools/dashboard/tests/amounts.test.mjs
```

An existing-book smoke test is opt-in; without this variable it is explicitly
skipped, not counted as a kernel integration pass:

```sh
FA_DASHBOARD_NATIVE_BOOK=./books/myco \
FA_DASHBOARD_FA=./target/release/fa \
python3 -m unittest discover -s tools/dashboard/tests -v
```

Use a trusted development book with at least one fiscal period. The smoke test
compares the native report coordinates; it is not a comprehensive accounting
oracle. Contract tests use labeled fixtures to test adapter refusal, integer
transport, same-snapshot selection and command arguments. HTTP tests exercise a
real local listener; subprocess tests exercise real bounded child processes.

For browser validation, start `--demo --open`, open an account and its first
entry, select a graph node by keyboard, search/filter accounts, export CSV, switch
theme, run the synthetic check, and inspect a 390px-wide layout. Print preview
must retain the demo warning. Repeat with a real development book before relying
on native integration. Missing executables, bad tokens, unknown periods,
unavailable snapshots, native refusals, and verification drift must never display
invented data or an empty green result.

## Integration posture

The user-requested visualization lives downstream of the plan's CLI contract in
`tools/dashboard`, with no new Rust dependency or unregistered core verb. It does
not alter bare `fa`, the daemon protocol, accounting laws or substrate APIs. A
native `fa dashboard` launcher, daemon-hosted typed HTTP reads, query pagination,
historical evidence API, and signed report/bundle visualization would be further
integration work, not capabilities claimed by this companion.
