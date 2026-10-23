# franken_accounting

<div align="center">

[![License: MIT + Rider](https://img.shields.io/badge/License-MIT_+_OpenAI/Anthropic_Rider-blue.svg)](./LICENSE)
[![Rust Edition](https://img.shields.io/badge/Rust-2024_Edition-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![toolchain: nightly](https://img.shields.io/badge/toolchain-nightly-purple.svg)](./rust-toolchain.toml)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![substrate: FrankenGraphDB](https://img.shields.io/badge/substrate-FrankenGraphDB-teal.svg)](https://github.com/Dicklesworthstone/frankengraphdb)
[![deps: closed universe](https://img.shields.io/badge/deps-closed_universe-black.svg)](./COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md)

**A universal, evidence-native, double-entry accounting system of record in memory-safe Rust, built on FrankenGraphDB. The journal is the database: every balance is a certified fold over an immutable, bitemporal entry stream; every entry carries its evidence; every correction is lineage, never an edit; every report replays byte-for-byte; every proof verifies offline. Built for CPAs, regulators, litigators, forensic investigators — and for AI agents as the operators.**

</div>

> **Status (2026-10-21): implementation in progress.** The Rust workspace includes the embedded library, persistent CLI, book writer-lease daemon and registered MCP tools, exact money and calendar primitives, G0 constitutional registries and `tools/registry-check`, chart installation (with embedded chart templates), period transitions, posting and reasoned reversal, register folds and their verify targets (`fa verify book` runs every one of them), and an independent arithmetic and state-machine oracle. Trial balances support stock balances, period activity, civil-date cutoffs, and historical commit-sequence or retained-instant snapshots. Trial balances, balance explanations, statements and open-items reports retain certificates that replay their exact results; statements are issued as journaled StatementIssuances, and reads select AS ORIGINALLY REPORTED, AS ISSUED TO an audience or AS REPORTED IN a certificate. `fa explain` covers `balance`, `entry`, `evidence`, `refusal`, `period`, `register` and `lineage`. `fa query` runs GQL over the book's graph in the FrankenAccounting profile (`AS KNOWN AT`, `FOR PERIOD`, `EFFECTIVE BETWEEN`, `CALL fa.trial_balance`), with the amount law checked before anything runs, and `--certify` retains a certificate that `fa replay` reproduces byte for byte; profile procedures inside a pipeline and scoped-token queries are still open (`fa-5c1`). Every published checkpoint is signed by the book's key; `fa proof` exports signed checkpoints and portable inclusion, consistency, prefix and balance proofs, and `fa bundle produce` writes `.fab` evidence bundles with signed production receipts, all checked offline by the standalone, std-only `fa-verify`. Lantern forensic procedures run as `fa procedure`, and `fa doctor`, `fa triage` and `fa next` diagnose a book and name the next command. Drafts promote to trunk in one batch; scenarios fork, run and certify a trial-balance diff over a scratch replay; restatement cases are journaled from open through determination, rehearsal, dual-control approval, posting, disclosure and close, and PriorPeriodAdjustment and Revision cases post their entries (Restatement posting waits on its SoD rule's session lineage, `fa-651f`). Year-end close and closing routes run as `fa close`; the CloseRun task DAG (`fa-4o0`) is still a design target. Capabilities are issued, listed and revoked with `fa capability` and bind an MCP session (`fa-mcp --token`); every command a read-only Human bound session runs (read, produce and verify only, as auditor-style tokens are) is recorded as an AccessEvent before it reads the book, listed by `fa access log` (Agent and writing sessions and the owner are not recorded yet, `fa-7dw`); the ordinary CLI and daemon remain the embedded-owner posture, where the host operator asserts the principal. The full Genesis acceptance criteria and the broader target-state workflows below remain open.

> **A note on tense.** The sections above `## TL;DR` document **what runs today** (and [`crates/fa-cli/tests/readme.rs`](./crates/fa-cli/tests/readme.rs) executes `### Try it today` and validates every present-tense `fa` command above `## TL;DR`). Starting at `## TL;DR`, the README describes the **1.0 target state** from [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md`](./COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md), with target-only capabilities annotated with the bead (`fa-…`) that delivers them.

### Try it today

<!-- try-it-today: crates/fa-cli/tests/readme.rs runs this section against the real `fa` binary.
It writes each `file:` block below verbatim, runs every `fa` line of the commands block in order
in a fresh directory, fills `<document-oid>` from the `oid` the line before printed, and requires
exit 0 from every line; the replay must reproduce the trial balance's data. Edit a line and the
test fails. The same test checks every `fa` line above `## TL;DR` against the verb registry. -->

Write an invoice and the entry it supports next to the book:

<!-- file: invoice.txt -->
```text
Invoice 10442 to ACME-CUST-17: 10 widgets at 125.00 USD, total 1,250.00 USD.
```

<!-- file: sale.json -->
```json
{"effective_date":"2026-03-14","idempotency_key":"inv-10442","legs":[{"side":"debit","account":"1200","amount":"1250.00 USD"},{"side":"credit","account":"4000","amount":"1250.00 USD"}]}
```

Then create a book with a template chart, open March, and record the invoice. Rehearse the entry it supports as a sealed plan (replace `<document-oid>` with the `oid` that `fa document add` printed), commit exactly that plan, and get a certified trial balance that `fa replay` reproduces:

<!-- commands -->
```bash
fa book create --book acme --name "Acme Co" --base-unit USD
fa chart import --template us-gaap-smb --book acme
fa period create --fiscal-year 2026 --book acme
fa period open FY2026-P03 --book acme
fa document add invoice.txt --kind Invoice --grade HumanUpload --book acme --json
fa post --intent sale.json --evidence <document-oid> --dry-run --plan-out sale.plan --book acme --json
fa commit --plan sale.plan --book acme --json
fa tb --period FY2026-P03 --certificate-out march.cert --book acme --json
fa replay march.cert --book acme --json
fa certificate status march.cert --book acme --json
fa statement income-statement --for FY2026-P03 --book acme --json
fa statement balance-sheet --for FY2026-P03 --book acme --json
fa explain balance 1200 --period FY2026-P03 --book acme --json
fa registers materialize --period FY2026-P03 --book acme --json
fa verify registers --period FY2026-P03 --book acme --json
fa verify projections --book acme --json
fa checkpoint create --grant witness --book acme --json
fa verify accumulator --book acme --json
# Every book-level verify target (entities and registers over every period), then one verdict.
fa verify book --book acme --json
# The registered rounding, allocation, FX, conversion, lot and tracing laws, and the unit versions.
fa law list --json
fa unit list --json
```

`fa chart templates` lists the charts (`us-gaap-smb`, `ifrs-sme`, `us-bank-call-report`); they are starting points, not GAAP, IFRS or regulatory advice. `--grade HumanUpload` declares that a human supplied the document; an agent's own upload is `AgentUpload`. Bare `fa`, `fa --help` and `fa robot-docs guide` orient an agent. Bare `fa` also names the book it would use (`--book`, `FA_BOOK`, or the working directory when it is a book) and whether a `fad` serves it, without opening the book. `fa triage` reports periods, pending cells, register watermark lag, drafts awaiting promotion and open findings by severity. `fa next` ranks the next steps for the caller's capability, and an Agent token is never offered a step that writes the book.

### Reporting available now

For a book with posted entries, the current CLI supports:

```bash
# Includes opening history and all postings through the period's last day.
fa tb --book ./books/acme --period FY2026-P03 --json
# Movement in exactly this period; repeated period selectors count once.
fa tb --book ./books/acme --period FY2026-P03 --activity --json
# Effective dates through March 15, using the journal as it stood at sequence 42.
fa tb --book ./books/acme --as-of 2026-03-15 --as-known-at 42 --json
fa verify registers --book ./books/acme --period FY2026-P03 --json
# A multi-entity book: each legal entity's register refolds against the journal.
fa verify entities --book ./books/acme --period FY2026-P03 --json
# Find entries by their description or leg memos, documents by their (extracted) text, and recorded findings by their narrative: one index rebuilt from the journal per query.
fa search "office rent" --book ./books/acme --json
# What changed since sequence 40: March balances then and now, and every entry recorded since, whatever date it carries.
fa diff --from 40 --period FY2026-P03 --book ./books/acme --json
# GQL over the book's graph: March's legs summed per unit and side, as known at sequence 42.
# --certify retains the result's certificate; fa replay C:<oid> reproduces the rows byte for byte.
fa query "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) RETURN u.code, l.side, SUM(l.amount) AS total FOR PERIOD 'FY2026-P03' AS KNOWN AT 42" --certify --book ./books/acme --json
fa registers materialize --book ./books/acme --period FY2026-P03 --json
# General-ledger lines, lead schedules, open-item aging and cash flow at one recorded snapshot.
fa gl detail --account 1000 --from 2026-03-01 --to 2026-03-31 --book ./books/acme --json
fa gl roll-forward --account 1000,1200 --from 2026-03-01 --to 2026-03-31 --book ./books/acme --json
# The statement of changes in equity: opening + net income + issuances + distributions + other = closing.
fa statement equity-roll-forward --from 2026-01-01 --to 2026-12-31 --issuance 3100 --distribution 3200 --book ./books/acme --json
# Tie open items to the control balance: one leaf, a list, or every posting leaf.
fa gl aging --account 1200 --as-of 2026-03-31 --reconcile --book ./books/acme --json
fa gl aging --all-posting --as-of 2026-03-31 --reconcile --book ./books/acme --json
# Reconcile exactly the aging and as-of trial balance certificates already handed out.
fa gl aging --reconcile --account 1200 --as-of 2026-03-31 --as-known-at 42 \
  --aging-certificate C:<aging-oid> --control-certificate C:<tb-oid> --certify --book ./books/acme --json
# Cash flow under an explicit policy: per-leg assignments, or account_rules plus overrides.
fa gl cash-flow --account 1000 --from 2026-03-01 --to 2026-03-31 --policy cash-policy.json --book ./books/acme --json
```

Omitting `--as-known-at` selects the current head; the response records the resolved sequence. A later backdated entry appears at head but cannot change a report at an earlier sequence. `--as-known-at` also accepts an RFC 3339 instant when the book contains retained TimeEvidence ticks. It resolves the latest recorded sequence in the matching tick bucket, reports the original frontier and both brackets under `coordinate.time_evidence`, and refuses an instant before the first tick. Numeric UTC offsets and up to nine fractional digits are exact. `--as-of` remains a civil-date selector. These reports are exact payload folds; `tb` can retain a replay certificate as described below. The [persistent CLI tests](./crates/fa-cli/tests/cli.rs) exercise book creation, chart installation, posting, reporting, retained replay, refusals and recovery with the actual binary.

Reports show posted and pending amounts separately. A hold reserves its original period; a later partial posting releases the entire hold and posts only the explicitly selected sub-vector in the resolution's period. A void releases the hold without posting. Earlier recorded snapshots still show the unresolved reservation. Limited accounts reserve pending outflows; pending inflows cannot fund spending. `fa verify availability` compares each limited account's expected cell, including its account binding, with a journal fold. Timed holds expire through the configured daemon's committed, corroborated ticks, as described below.

Register verification compares both amount columns, counts, identity, period membership, watermark and fold checksum against the journal payloads. Rebuilding repairs derived rows and retires phantom cells without changing journal entries. Existing register caches from before the pending-column format must be rebuilt; their missing columns are reported as drift rather than assumed to be zero.

The embedded API's `Book::advance_registers(period)` consumes new committed entry payloads through `delta_since` for native posted/pending period cells. It publishes cells and the consumed cursor atomically; `Book::rebuild_registers(period)` replaces them from a fresh journal fold. Reopening rehydrates the delta window, and an actually retired cursor falls back to a full rebuild. Staged migration chunks stay invisible; finalizing a run triggers a full fold to include newly activated chunks older than the cursor. Pending-sum overflow also falls back to the final fold, so holds released later in the same suffix do not prevent advancement; a genuinely oversized final sum still fails. `verify_registers` also checks the maintenance state against its journal prefix. This slice still scans projection metadata and writes the period's cells; it makes no throughput claim. Reports retain their literal folds. Historical register checkpoints, cadence policies, other register families, supervised daemon maintenance and cached report reads remain unfinished.

### Timed holds and scheduled reversals

The CLI and MCP accept the kernel's timed accounting inputs. A Pending intent
may carry an unsigned integer `timeout_ns`, or the caller may supply
`--timeout-ns`. An Adjusting intent may carry a civil-date `reverse_on`, or
the caller may supply `--reverse-on`. Supplying a value twice, using a float
or a negative timeout, or attaching either field to the wrong entry class
refuses before opening the book. A timeout requires an existing committed
TimeEvidence anchor; it never reads the caller's wall clock.

Scheduled reversals require an explicit book civil-day policy. Set the
currently supported UTC policy when creating a book:

```bash
fa book create --name Acme --time-zone UTC --book ./books/acme --json
# After preparing the chart and fiscal periods, run this in its own terminal.
fad serve --book ./books/acme --bootstrap-system --json
```

The explicit `--bootstrap-system` option authorizes the local book-key holder
to run timed effects. Merely holding the writer lease does not enable them.
The daemon journals UTC clock observations and compares their progress with
its monotonic timer. Its first observation, each restart's first observation,
and observations inconsistent with the configured drift allowance do not
authorize automatic effects. Rejected jumps retain the original comparison
baseline; repeated bad samples cannot gradually establish trust in a jump.
Monotonic agreement is corroboration, not proof of UTC accuracy.

After the daemon has recorded an anchor, submit ordinary evidence-backed
intent files through the same CLI:

```bash
# A Pending intent: reserve for 60 seconds from the latest committed tick.
fa reserve --book ./books/acme --intent hold.json --timeout-ns 60000000000 --json
# An Adjusting intent: journal a reversal schedule for the declared civil day.
fa post --book ./books/acme --intent adjustment.json --reverse-on 2026-11-01 --json
fad status --book ./books/acme --json
fad stop --book ./books/acme --json
```

The registered defaults are one observation per second, a 250 ms clock-drift
allowance, and up to 64 expiries plus 64 reversals per cycle. A cycle must use
the latest committed, corroborated tick. The daemon keeps request reads alive
across timer wakes, so idle clients and partial frames do not stop timed work
or lose request bytes. Status reports whether timing is enabled, its authority,
cycle count, latest tick, corroboration and the last cycle error. Cancellation
and Stop end timed work through the server's structured lifetime.

These bounds limit published effects per cycle; candidate discovery still
scans the book. Journaled capability issuance, a sweep-now command, paged
backlog discovery and the full timing simulation campaign remain unfinished.
MCP exposes the same intent fields as `timeout_ns` and `reverse_on`, subject
to its fixed launch capability; it cannot grant itself System authority.

### Stored unit identity

New books retain a versioned canonical definition for every unit: its numeric
identifier, code, version, scale, kind, currency ISO number where applicable,
and default rounding-law identifier. The book also commits to the complete
unit table. Reopening reconstructs the runtime table from those stored
definitions and checks them against the executable's supported registry.
Changed definitions, missing members, corrupt payloads and unsupported unit
identifiers fail with exit 5 before amounts are interpreted. Extra units in a
newer executable are not silently installed into an older book.

Financial CLI output checks every amount's unit and returns exit 5 for an
unknown identity. Unit checks for trial balances, explanations and open-items
reports also run before retaining certificate metadata in the book or creating
a requested certificate file.
Library callers can use `Amount::try_render` to
propagate the same typed error; the compatibility `render` method labels an
unknown value as a raw mantissa without guessing its scale.

**Compatibility:** books created before canonical unit payloads and the table
commitment were recorded are refused. Keep the creating executable for those
books. An explicit, authorized backfill that journals the adopted definitions
and their provenance is still pending; reopening never fills missing facts from
the current binary. This does not implement unit evolution or redenomination.

### Native receivable and payable subledgers

Designate an existing Asset leaf as a receivables control or a Liability leaf as
a payables control. Registration retains an immutable definition and requires
every existing control-account leg to name a valid party, including staged
migration history. Subsequent control postings require that party dimension too.
Invoices, bills, receipts and payments use their existing party-qualified legs;
registration creates no additional posting or balance.

```bash
fa subledger add AR --control 1200 --kind receivables --name "Trade receivables" \
  --book ./books/acme --json
fa subledger add AP --control 2000 --kind payables --name "Trade payables" \
  --book ./books/acme --json
fa subledger list --book ./books/acme --json
fa subledger show AR --book ./books/acme --json
fa subledger verify AR --as-of 2026-03-31 --book ./books/acme --json
fa subledger verify AR --as-of 2026-03-31 --as-known-at 42 \
  --book ./books/acme --json
```

Verification folds party detail from the retained journal and compares it with
an independent control-account trial balance at the same recorded sequence and
effective date. Each currency keeps separate posted debit/credit and pending
debit/credit totals. A party's `net` is debit minus credit, so an ordinary payable
credit balance is negative. Partial settlements, reversals and reservation
releases retain their party attribution. A mismatch produces verification exit 8.

Creation requires whole-book read and schema-change authority; inspection and
verification require whole-book read authority. The same commands are registered
in the on-demand `fa.subledger` MCP cluster, with launch authority enforced.
This native reconciliation does not retain a report certificate or validate
external summary-feed detail digests; those remain open work under `fa-03s`.

### Bank CSV downloads

Bank downloads can use an explicit column, date and amount declaration:

```bash
fa bank import download.csv --bank-format csv --account 1000 \
  --layout layout.json --book ./books/acme --json
```

The import retains the original CSV bytes and the canonical layout, checks the
exact header and opening-to-closing balance, and uses that same mapping for
later matching and reconciliation. Layouts support signed amounts or separate
debit/credit columns, explicit date formats, and dot or comma decimals. See
[declared CSV layouts](docs/bank_csv_layouts.md) for a complete example and the
inline MCP form. Omitting `--layout` keeps the canonical twelve-column parser.

### Certified reports and replay

Retain the exact selector, known-at sequence, accounting journal prefix, registry
versions and native read closure behind a trial balance, leaf-account balance
explanation, or open-items report:

```bash
# Retains the certificate in the book and saves a new external copy.
fa tb --book ./books/acme --period FY2026-P03 --certificate-out march.cert --json
# Verifies the retained inputs and reproduces the original trial_balance line.
fa replay march.cert --book ./books/acme --json
# Reports Current or SupersededBy, with the later relevant entry identities.
fa certificate status march.cert --book ./books/acme --json

# Explain one leaf account, retaining its cells, contributions and history.
fa explain balance 1000 --period FY2026-P03 --as-known-at 42 \
  --certify --book ./books/acme --json
# Retain item balances, their applications and account metadata at that snapshot.
fa open-items --account 1000 --as-known-at 42 \
  --certificate-out cash-items.cert --book ./books/acme --json
fa replay cash-items.cert --book ./books/acme --json
```

Instant-selected certificates also retain their requested instant, observed frontier,
and tick identities. Replay uses those saved brackets even after later ticks or
postings arrive. An open upper bracket is explicit; this is a clock-observation
bucket, without a claim about the physical instant of each commit. The same
instant selector is available on `open-items` and `explain balance`. Ticks are
journaled through the library API and by `fad serve --bootstrap-system`.

The original call emits two robot lines: `trial_balance`, `balance_explained`,
or `open_items`, followed by `report_certificate`, with the certificate digest
in both envelopes. The certificate records the report's canonical output format
and digest. `--certificate-out` implies
certification. `--certify` retains an immutable, content-addressed certificate in
the book; repeated retention of the same certificate reuses its recorded sequence.
The second line's `bytes` field is its complete canonical encoding as hex.
`fa replay -` and `fa certificate status -` accept those hex bytes, or canonical
binary bytes, on stdin. Replay and status also accept the retained `oid`, either
as 64 hex digits or with a `C:` prefix, from the original book: `fa replay C:<oid>`
and `fa certificate status C:<oid>`. The optional file
or complete bytes remains useful as an external copy. MCP exposes the same flow through
`fa_read_trial_balance`, `fa_read_explain_balance`, or `fa_read_open_items` with
`certify: true`, followed by `fa_read_replay` or `fa_read_certificate_status` with
the returned `oid` or `bytes` as `certificate`.

Certification writes a metadata object and advances the book frontier; it posts
no accounting entry and does not change balances. Uncertified reports, replay and
status do not publish anything.
The certificate fixes the original `--as-known-at` sequence, including a resolved
HEAD, so later backdated entries can supersede its current status while its
historical report still replays exactly. Before returning `Current`, status also
compares the current report's content with the original. Changes without a later
contributing entry, such as newly created earlier fiscal periods in an as-of
report, refuse with `FA-REF-150`; the original historical report remains replayable.
Stock, `--as-of` and `--activity`
trial balances are supported. The declared scope is `fa-fold-over-prefix` with
`embedded-owner` authority: unsigned replay against retained native history.
Balance explanations bind historical account metadata, evidence references,
reversal lineage, cell history, and the whole-period fold. Open-items certificates
bind the optional account filter, historical account metadata, and application
and reversal lineage. An account absent at the selected snapshot refuses instead
of producing an empty result. All three report families support commit-sequence
and RFC3339 instant selectors; replay preserves the original coordinate even
after later postings or ticks arrive. Signed witness claims, independent offline
bundles, and certificates for additional report families remain unfinished.

### Typed posting plans

The library, CLI and MCP can rehearse an entry through the actual posting
kernel, export its bounded canonical bytes, and commit that same intent later.
The embedded API uses a typed `PostIntent`:

```rust
let intent = fa::PostIntent::new(request.proposal, request.approvals)?;
let plan = book.plan(intent, &request.capability)??;
let saved_bytes = plan.canonical_bytes()?;
let restored = fa::PostPlan::decode(&saved_bytes)?;
let posted = book.commit_plan(restored, &request.capability)??;
```

For an existing book and an entry intent file:

```bash
# Run the posting laws, review the exact result, and save a new binary plan.
fa post --book ./books/acme --intent entry.json \
  --dry-run --plan-out entry.plan --json
# Commit the reviewed artifact with the same caller and grants.
fa commit --book ./books/acme --plan entry.plan --json
```

`reverse`, `reserve` and `resolve` also accept `--dry-run` and optional
`--plan-out`. Rehearsing a hold acquires no reservation, and rehearsing a void
releases nothing. On the ordinary owner CLI, the explicit `commit --plan`
confirms the authenticated artifact; use the same `--as` and `--grant` values
on both calls.

The robot `plan` event includes the exact legs, effective date, lineage,
evidence references, snapshot, effects digest and complete canonical `bytes`
as hex. `--plan-out` creates a private binary file and refuses an existing
path. Without a file, forward `data.bytes` on stdin to `fa commit --plan -`.
Commit emits `plan_committed`; an exact retry sets `already_recorded: true`.

An MCP server launched with the bounded Preparer profile below can use
`dry_run: true` on its posting tools, then pass the returned `data.bytes`
as `plan` to `fa_post_commit_plan`. Both calls use the exact fixed launch
capability. Per-call identity or grant overrides remain forbidden; the
default Agent profile still refuses trunk posting and planning. A void can
be previewed, but its MCP commit remains refused with `FA-REF-007` until the
separate confirmation exchange exists. A plan cannot replace that exchange.
Plan output identifies the actual `embedded-owner` or `mcp-launch-config`
authority. CLI/MCP dry runs currently refuse `--balancing` and do not collect
new approvals.

Planning runs the same balance, period, evidence, capability, approval,
settlement, reservation and balance-limit checks as posting, then aborts the
prepared transaction. It publishes nothing and consumes no idempotency key.
The artifact preserves the original sealed proposal, supplied approvals and
resolved entry preview. Its authenticated certificate binds the book,
principal, capability commitment, proposal, native staged effects, snapshot,
security-policy epoch and capability expiry. No capability is created from
the artifact; the caller supplies current authority again at commit.

This first slice deliberately requires the exact same book sequence. A new
posting, period transition, policy change, approval or retained report
certificate requires a fresh plan. A mismatched plan refuses with
`FA-REF-034` (exit 6), and current authorization is checked before protected
book observations. Commit repeats the posting checks and compares the actual
staged effects before publishing. An exact retry of a successfully committed
plan returns the original entry and sequence without another write.

The committed transaction also retains the complete plan in an immutable
graph `Certificate` with a `CITES` edge from the entry. Its public digest is
a graph locator. The pinned substrate has no public generic application
object store, so this slice leaves the native `Entry.plan_certificate` field
absent instead of treating that digest as a substrate object ID. Planning
requires any needed approvals to exist already. Planning before approval
collection, rebasing through portable read witnesses, atomic multi-intent
batches, draft promotion and authenticated sessions remain unfinished
under `fa-we7` and its dependent beads.

### MCP launch authority

The stdio server uses MCP `2026-07-28`. Clients discover it with
`server/discover` and send `io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities` in each request's `params._meta`.
Legacy `initialize` negotiation is refused. Resource refusals retain their
structured `error.data`, including the launch authority.
Resource reads have private, zero-lifetime cache hints because their URIs
resolve the current book state.

Start the stdio server against a book the operator has already prepared:

```bash
# The default Agent session: read reports and verify the journal.
fa-mcp --book ./books/acme --principal accounting-agent
# A trusted operator can explicitly allow ordinary accounting posting.
fa-mcp --book ./books/acme --principal rent-preparer --profile preparer
# An explicit grant list is the entire selected set, not an addition to defaults.
fa-mcp --book ./books/acme --principal report-reader --profile agent --grant read
```

The default principal is `mcp-agent`; the default profile is `agent`.
Both profiles default to `read`, `post`, and `verify`. An explicit, nonempty
`--grant` list selects only the named operations within the profile's ceiling.
Agent permits `read`, `post`, `verify`, `reconcile`, `produce`, and `partial_view`;
Preparer also permits `post_softclosed`. A grant outside that ceiling refuses
startup. Preparer is a bounded Human template, not an unrestricted owner.

An Agent's accounting posts to trunk reach the kernel and refuse with
`FA-REF-013`. Instead it plans them into a draft (`fa draft new <name>`, then
the same post with `--draft <name>`; over MCP, launch with `--cluster fa.draft`).
A Human holding `approve` who is not the draft's owner runs `fa draft promote`:
every planned intent is admitted again against current trunk and posts in one
batch, with the Agent still the entries' principal. An explicitly
launched Preparer can make ordinary, evidence-backed posts under its own fixed
principal. Book creation, chart/period preparation, document intake and approvals
remain operator work. Both profiles can use the certified report and retained
replay tools above when they hold `read`; certification retains metadata without
posting an accounting entry. Register maintenance additionally requires `verify`.

The server resolves `--book` or `FA_BOOK`, optional `--keys`, principal, profile,
and operations once at launch. Tool calls cannot supply `as`, `grant`, `yes`,
`keys`, `book`, `principal`, `profile`, or `via`, including null or false values.
Resource reads use the same book. Successful responses and structured refusals
identify the actual launch authority; report data remains in the first content
block. A separate operator-controlled session is required to change identity
or authority. Dangerous commits refuse with `FA-REF-007`; a plan or approval
file cannot substitute for the separate confirmation exchange that remains
unfinished.

Each book operation takes the configured writer lease. If a running `fad` or
another writer holds it, the server refuses instead of forwarding authority
through the daemon's unauthenticated protocol. This is a trusted launch binding;
authenticated capability issuance and daemon sessions remain unfinished. Host
file arguments are not confined to a filesystem sandbox, so deployments must
still control the server process's filesystem access.

### Embedded execution

`AsyncBook<V>` accepts the caller's `PurposeContexts` for each operation and
uses the supplied filesystem for both the journal and external document bytes.
It owns no runtime. The `Book` convenience API creates a production runtime
for its synchronous operations and delegates to the same implementation. This lets a host application or the
lab runtime supply cancellation, budgets, scheduling and filesystem faults
without a second accounting implementation.

Tick recording, bounded expiry and reversal sweeps, and their backlog reads
also use this async core. The `Book` timing adapters accept the caller's
context. The kernel takes automatic effects only from a corroborated committed
tick; a failed description seal aborts the current batch without advancing
its cursor. These are committed-tick semantics, not a guarantee of clock accuracy.

The lab smoke tests cover a posted entry, exact expected register cells,
external evidence, virtual sync latency, crash/reopen, idempotency, caller
cancellation, tick-driven expiry and reversal, and an injected write failure.
Additional daemon lab tests exercise bounded expiry and reversal cycles,
clock uncertainty, stale ticks, cancellation and partial request frames
across virtual timer wakes. These test sources require the normal Rust gates;
source inspection alone does not establish a passing simulation campaign.
The full registered crash-point
matrix, concurrency exploration and 1,000-seed Genesis campaign remain open
under `fa-0fl`; these smoke tests do not establish that broader claim.

The posting and period kernels also expose owned prepared transactions.
Their ordinary entrypoints prepare and commit through the same code.
Preparation retains the substrate's original witnesses; commit rechecks the
acting capability's expiry at the current frontier and validates those
witnesses without refreshing them. This permits controlled interleavings
between preparation and publication while preserving the accounting laws.
Period opening also witnesses the population of reversal schedules, including
an empty population, so a newly due schedule invalidates a prepared opening.
The filesystem fault tests currently cover consistently anchored paths;
relative-path alias handling in the substrate simulator is tracked by `fa-n4m`.

### Leg projection verification

`fa verify projections` compares stored leg mirrors and graph edges with the
canonical entry payloads at one committed snapshot:

```bash
fa verify projections --book ./books/acme --json
```

The check derives leg identities from each entry, so a missing `HAS_LEG`
edge cannot conceal a missing projection. It checks exact scalar mirrors,
wide-amount fallback bytes, labels, and all `HAS_LEG`, `POSTS_TO`, `IN_UNIT`
and dimension `FOR` edges. Pending and staged migration entries are included.
The command returns deterministic counts on success or exit 8 with drift
details, and never writes. The same target is available through
`fa_book_verify` in MCP; `Book::verify_projections` and
`AsyncBook::verify_projections` also accept an explicit historical sequence.

Ordinary postings and scheduled reversals now publish unit and dimension
edges together with the entry. Prefixes created by older versions can report
those previously omitted edges as missing. Verification reports that
condition without repairing it. Recovery is explicit, never automatic on
open:

```bash
fa recover projections --dry-run --book ./books/acme --json
fa recover projections --yes --book ./books/acme --json
```

The dry run loads the complete native history, checks every source entry
against its creation, and previews the mirror and edge changes at that head
without writing. Publishing needs `--yes` and read, verify and schema_change
authority (never an Agent profile on trunk, and host-only over MCP). It
rechecks the exact head, publishes every change in one commit, and then runs
both the projection and the open-item checkers again. A clean book publishes
nothing. Orphan legs, occupied identities and deleted edges, whose spent
identities the substrate cannot re-create, are refused with nothing written.
Applied counters and settlement edges retain their separate
`fa verify open-items` check.

### Entry accumulator checkpoints

The CLI can publish an unsigned checkpoint over the book's entry prefix and
recompute the stored chain from the journal:

```bash
fa checkpoint create --grant witness --book ./books/acme --json
fa verify accumulator --book ./books/acme --json
```

Publication requires witness authority; an Agent profile cannot publish on
trunk. Verification reports `verified_through`, the newest checked prefix,
so later postings are covered only after another checkpoint. With no stored
checkpoints it returns `status: "no_checkpoints"` and a null
`verified_through`. A corrupt state or broken chain produces exit 8 and a
finding; checkpoint creation refuses a corrupt predecessor. Verification
and proof generation also reject later rewrites or retirements of checkpointed
entries, even when the original historical snapshot is still readable.
These states cover entries, including control entries, and every journaled
attestation, import receipt, custody transfer and supplemental-evidence record
after the state's recorded evidence boundary. A state from before this boundary
existed covers entries alone and stays valid; the next state extends it. A
rewrite of any covered record fails `fa verify accumulator`. The library also signs
each published checkpoint with the book's Ed25519 key
(`Book::checkpoint_public_key`) as a `TransparencyCheckpoint` and produces
evidence bundles with detached production receipts (`Book::produce_bundle`);
`fa-verify checkpoint|scope|bundle` check them. The CLI exports both (see
below); witnesses and key rotation remain
unfinished. The
[CLI tests](./crates/fa-cli/tests/notary.rs) exercise persistence, later
postings, authorization and real storage corruption.

### Portable proofs and the offline verifier

Export one of the existing recorded states without creating a new checkpoint
or changing the book. Omit `--state`, or use `latest`, to select the newest
recorded checkpoint. A full 64-hex state digest selects a historical one.
The exporter verifies the retained chain first and refuses damaged history.

```bash
# Publish a checkpoint separately, using witness authority.
fa checkpoint create --grant witness --book ./books/acme --json
# Save its raw 80-byte statement and a complete prefix proof.
fa proof checkpoint --state latest --out acme.checkpoint --book ./books/acme --json
fa proof prefix --state latest --out acme.prefix --book ./books/acme --json
# Export an exact account/unit recomputation through an inclusive civil date.
fa proof balance --account 1000 --unit USD --as-of 2026-09-30 \
  --state latest --out cash.balance --book ./books/acme --json
```

Select the same explicit state digest for separate exports if another writer
may publish checkpoints between commands. `proof inclusion --entry <vid>`
proves one entry's inclusion; `--with-record` also supplies its payload for
recomputation. `proof consistency --state <old-oid> --next-state <new-oid>`
proves extension between two recorded states.

After independently establishing trust in the checkpoint, an outsider can
check the raw files with no book, keys, accounting dependencies or network:

```bash
fa-verify prefix --proof acme.prefix --checkpoint acme.checkpoint --unsigned-checkpoint --json
fa-verify balance --proof cash.balance --checkpoint acme.checkpoint --unsigned-checkpoint --json
# A consistency check additionally names the producer's claimed new statement.
fa-verify consistency --proof extension.proof --checkpoint old.checkpoint \
  --next-checkpoint next.checkpoint --unsigned-checkpoint --json
```

These checkpoints are unsigned, and `--unsigned-checkpoint` says so: you trust
the 80-byte statement through some other channel. The signed alternative needs
no side channel beyond the book's public key, which every export names as
`checkpoint_public_key`:

```bash
fa proof signed-checkpoint --state latest --out acme.ckpt --book ./books/acme --json
fa-verify prefix --proof acme.prefix --checkpoint acme.ckpt --key <checkpoint_public_key> --json
# An evidence bundle: one account's month, a recomputed balance, a signed receipt.
fa bundle produce --account 1000 --from 2026-03-01 --to 2026-03-31 \
  --balance 1000:USD:2026-03-31 --out cash.fab --receipt-out cash.receipt --book ./books/acme --json
fa-verify bundle cash.fab --key <checkpoint_public_key> --receipt cash.receipt --json
```

`--key` (repeatable) is required for `scope` and `bundle`; run
`fa-verify --help` for the grammar. Receiving a proof and its checkpoint together
does not authenticate their origin. The verifier requires the trust anchor
as a separate input and reports the exact predicate it checked: inclusion,
tree extension, complete prefix envelopes, or posted debit/credit arithmetic
for one account/unit through the optional date. Exact amounts are integer
mantissa strings. It does not claim witness signatures, document receipts,
FX conversion, financial-statement validity or full evidence-bundle replay.

`--out` creates a private raw binary file and refuses to overwrite an existing
path. Without it, the `proof_exported` event includes complete hex bytes and
checkpoint metadata. Binary proofs are bounded to 64 MiB; inline JSON has the
smaller daemon frame bound. The standalone verifier returns exit 2 for usage,
5 for I/O failure, and 8 for failed verification.

The embedded entrypoints are `Book::export_proof` and
`AsyncBook::export_proof`, using `ProofRequest` and `ProofKind`. They check
the holder, book scope, current expiry and journaled revocation, and require
both Read and Produce before scanning protected history. MCP exposes
`fa_notary_export` with a `kind` selector and inline results in the on-demand
`fa.notary` cluster (launch `fa-mcp --cluster fa.notary`). Its fixed launch
capability must include `--grant read --grant produce`; per-call authority
and host output paths are refused. Complete-prefix and balance proofs disclose
every journal envelope, so they require whole-book read authority.

### Litigation productions

A matter's Bates numbering is journaled, so it never restarts and never
reuses a number. `fa production open` records the matter's profile once: its
Bates prefix, its first number and an optional protective order the book
holds. `fa produce` gives each document the matter has not produced the next
numbers, journaled by one `ProductionControl` record, and writes the volume
into a new directory: a Concordance `.dat`, an Opticon `.opt` and each
document's native. A document the matter already produced keeps its range.
The same document produced in another matter gets that matter's range, and
its `doc_commit` never changes.

```bash
fa production open SEC-v-Acme --bates-prefix ACME-SEC --protective-order <order_oid> --book ./books/acme --json
fa produce --matter SEC-v-Acme --document <oid>:12:confidential --document <oid> --out ./prod-001 --book ./books/acme --json
fa production show SEC-v-Acme --json       # every range, with the record that assigned it
fa production document <oid> --json        # the document's range in every matter
```

Both writes need `produce`, and an Agent-profile capability can prepare
neither. Every document's read is judged before any number is journaled.
A governed document (a bank statement) that the producer can see only through
its redacted view is listed as `REDACTED`, with its contract, and ships no
bytes. The default key is the request itself: running the identical command
again returns the recorded production, and it can write the same volume into
another new directory.

The volume's `PRIVILEGE_LOG.md` has two kinds of row. The first is each
produced document whose redacted view withholds bytes. The second is each
document withheld in full with `--withhold <oid>`; that document is never
produced and takes no Bates number. `--privilege <claims.json>` states each
claim's date, author, recipients, description and basis. A withheld document
must have a claim. A redacted row without a claim states no date. Claims are
checked before anything is journaled.

`fa produce --bundle` is the plan's `Produce`. It makes an evidence bundle
over a scope against a recorded checkpoint, exactly as `fa bundle produce`
does, and numbers the documents its in-scope entries cite, in journal order.
On top of the load files, privilege log and natives above, the volume then
adds three things. First, `<VOLUME>.fab` and its signed `<VOLUME>.receipt`,
which `fa-verify bundle` checks offline. Second, EDRM XML (`<VOLUME>.xml`)
when the matter was opened with `--load-file edrm|both`; it binds the
bundle's digest. Third, the FRE 902(13)/(14) declaration, verification
procedure and notice templates over the journaled ranges.

```bash
fa checkpoint create --grant witness --book ./books/acme --json
fa production open Doe-v-Acme --bates-prefix DOE --load-file both --book ./books/acme --json
fa produce --matter Doe-v-Acme --bundle --account 1000 --from 2026-03-01 --to 2026-03-31 --out ./prod-002 --book ./books/acme --json
```

The FRE 902 package states technical predicates; admissibility is counsel's
call. `fa exhibit mark` is not wired yet (`fa-6l9`).

### Audit engagements

An audit's mechanics are journaled; the judgments stay the auditor's.

- **Open.** `fa engagement open` records the engagement once, with its kind,
  scope periods and the materiality parameters the auditor states: overall,
  performance and clearly trivial, in the book's base unit.
- **Propose.** `fa adjustment propose` journals a draft correcting entry. It
  must balance in every unit, use posting leaves, and be dated inside a scope
  period. It never posts.
- **Book or pass, once.**
  - `fa adjustment book` names the committed entry that makes the correction.
    That entry must post exactly the proposal's legs, be recorded after the
    proposal, be effective in the proposal's period, and stand (not be
    reversed or replaced); one entry books one proposal. Booking reads the
    entry, so it needs `read` as well as `produce`.
  - `fa adjustment pass` records why the proposal was left uncorrected, from
    the registered `adjustment_pass` reasons.
- **Summarize.** `fa engagement sud` is the summary of uncorrected
  misstatements. For each passed proposal, and each booked one whose entry
  was later reversed or replaced, it gives the effect on income, assets,
  liabilities and equity had the correction been booked and stood. It
  totals them under rollover and iron curtain, and compares them with the
  stated parameters. Per statement line, it attributes the same items to an
  income statement's lines (rollover) and a balance sheet's (iron curtain):
  the registered definitions by default, or the classified presets with
  `--definition us_gaap_small_company_income_statement` and
  `--definition us_gaap_small_company_balance_sheet`.
- **Out-of-period corrections.** An immaterial prior-period error fixed in
  the current period without a case is an `Adjusting` entry posted with
  `"prior_period_error": "FY2025-P12"` (or `--prior-period-error`); the
  kernel refuses the marker on any other class or on a period that does not
  end before the entry's date. While it stands, the summary lists it under
  `out_of_period` and counts it under rollover: it misstates this period's
  income. The iron curtain does not count it, because the period-end
  balance sheet is already corrected (SAB 108).
- **Carry forward.** `fa engagement carry-forward <id> --from <prior>`
  brings an earlier engagement's uncorrected misstatements into this one.
  The auditor states which turned around through this period's income
  (`--turned-around N`) and which an out-of-period correction here
  corrected (`--corrected N`); the rest are still uncorrected at this
  period's end. The summary counts them under the iron curtain (still
  uncorrected) or the rollover (turned around), and reports
  `prior_period_carry_forward: true`. A later carry-forward governs.
- **File and complete.** `fa engagement file` puts a document the book holds
  in the engagement's workpaper index, once. `fa engagement complete`
  journals the documentation completion once, at most 45 days after the
  report release date (AS 1215.15). Nothing is withdrawn afterwards: every
  workpaper, proposal and decision journaled after it is marked
  `added_after_completion` in `fa engagement show`.
- **Confirm and represent.** `fa document attest confirmed` records what a
  party confirmed (a balance as of a date) over a Confirmation document,
  under `produce`. `fa document attest represented` records management's
  representations over a Representation letter, under `approve`, each claim
  sealed. In the workpaper index a confirmation is audit-grade only when the
  engagement's firm principal received the document (AS 2310).

```bash
fa engagement open FY26-audit --kind audit --period FY2026-P12 --overall "50000.00 USD" --performance "37500.00 USD" --clearly-trivial "2500.00 USD" --book ./books/acme --json
fa adjustment propose --engagement FY26-audit --intent accrual.json --book ./books/acme --json
fa adjustment book --engagement FY26-audit --proposal 1 --entry E:<vid> --json
fa adjustment pass --engagement FY26-audit --proposal 2 --reason ClearlyTrivial --json
fa engagement sud FY26-audit --json
fa engagement sud FY26-audit --definition us_gaap_small_company_balance_sheet --json
fa engagement file FY26-audit --document <oid> --json
fa engagement complete FY26-audit --report-release 2027-02-15 --completion-date 2027-03-20 --json
fa engagement carry-forward FY27-audit --from FY26-audit --turned-around 2 --corrected 3 --json
fa document attest confirmed <oid> --party C-1 --balance "1200.00 USD" --as-of 2026-12-31 --json
fa document attest represented <oid> --claim "All transactions are recorded" --as-of 2027-02-15 --json
```

Writes need `produce`, which the Auditor profile holds, and an
Agent-profile capability makes none of them. The summary's comparisons are
mechanical; whether a misstatement is material is the auditor's call.

What the summary does not do yet:

- **Carried items need closing routes for their lines.** Per statement
  line, a turned-around item is reversed on the income statement, and a
  still-uncorrected item is on the balance sheet with its income legs on
  the equity account the book's closing routes (`fa close map`) send them
  to. That income is in opening retained earnings by now. Without a route
  for such an account the lines are refused, naming it. A carry-forward is
  not chained: the prior engagement's own carry-forward does not come
  along.
- **No foreign-currency conversion.** Legs in other units are listed, never
  converted.

### Exact arithmetic available now

`fa-money` supports the full signed `i128` amount range, including parsing,
rendering, identity conversion and allocation of `i128::MIN`. Posting legs
remain nonnegative. Conversion uses exact arbitrary-precision intermediates;
allocation uses a bounded wide sum of weights. Rates have private, reduced
arbitrary-size integer coefficients supplied by FrankenSymPy. Parsing,
composition, conversion and canonical rate encoding take a caller-owned
`ArithmeticBudget`, which checks `Cx` cancellation and deterministic resource
limits before work. Only the final, law-rounded amount must fit `i128`.
Unit registration rejects unsupported scales and conflicting definitions of
an existing version; historical amounts retain their original scale.
Valuation checks native balance before absorbing a law-bounded rounding
residual. Tests compare conversions under all nine rounding laws against
`fgdb-bigint`; the reference engine retains its own arithmetic and imports
only registry data and calendar primitives. Every `LegalEntity` in a `Book`
must share `functional_unit == book.base_unit` (plan §0.4 decision 1, `fa-viui`);
genesis (`create_book` / `fa book create --entity`) and schema evolution
(`create_legal_entity`) refuse a mismatched entity functional currency with
`FA-REF-003` (exit 3) naming the Concordat fix (maintain a separate `Book`
in that entity's functional currency and consolidate via Concordat).

**FrankenSymPy assessment (2026-10-10, corrected after the owner's clarification).**
The owner's own Rust projects — Franken-named or not — are eligible dependencies,
including their recorded transitive dependencies. [`frankensympy`](https://github.com/Dicklesworthstone/frankensympy/tree/bd1ad68a3a06e0a0ed6ee4a9bc76d85dc9e67e2e)
supplies the arbitrary-precision exact rationals used by `Rate`.
Its [`fsym-rational`](https://github.com/Dicklesworthstone/frankensympy/blob/bd1ad68a3a06e0a0ed6ee4a9bc76d85dc9e67e2e/crates/fsym-rational/src/lib.rs)
and `fsym-bigint` APIs provide normalized rationals, cross-cancelled composition
and metered arithmetic. The integration (`fa-pri`) uses those APIs for large
rate coefficients and exact conversion intermediates, with registered rounding
back to fixed-scale `i128` amounts. It includes a `Cx`-backed budget meter,
bounded input decoding, exact dependency pins and recorded wrapper paths.
`fgdb-bigint` remains an independent test oracle; a production `fsym-rational`
calculation cannot also serve as its own independent oracle. The versioned
rate codec rejects nonminimal and unreduced encodings and admits coefficient
storage before allocation. Symbolic rule analysis has no current consumer.
No performance improvement is claimed; verification results and the exact
foundation revision are recorded with the implementation landing.

---

## TL;DR

**The problem.** Every system that holds books today fossilized around a decision made decades ago. ERP general ledgers (SAP's Universal Journal, Oracle, NetSuite) keep posted journals immutable but store balances in mutable summary tables, model periods as flags, re-key reversals, and keep the audit trail in a separate change-document table with no "as known at" selector; small-business tools edit entries in place; TigerBeetle got the primitive exactly right — immutable transfers, 128-bit integers, two-phase holds, deterministic simulation — and is, by design, a two-leg balance engine with no journal entry, no periods, no close, no restatements, no documents, no "the books as of", no relationships; fintech ledger APIs stop at balances and transactions and hold your system of record in their SaaS; plain-text accounting got immutability and reproducibility right and is single-user with filename-grade evidence; audit and forensic tooling begins with "export the GL to CSV". The field solved every hard subproblem in isolation — REA, bitemporal time, event sourcing, Fowler's reversal/replacement adjustments, the AICPA Audit Data Standards, AS 2401's journal-entry tests, Certificate Transparency — and **no shipping system ever composed them.**

**The solution.** `franken_accounting` composes them, on a substrate that already has the hard parts: FrankenGraphDB's immutable content-addressed commit stream (our system time), bitemporal property graph (our REA model and effective dates), git-style branches (our drafts and but-for scenarios), incremental views (our registers), capability security (our segregation of duties), and deterministic replay (our certificates). One codebase, three postures: an embedded library (`fa`), a CLI (`fa`) whose robot mode is the agent contract, and an MCP server (`fa-mcp`) hosted by the `fad` daemon.

| | `franken_accounting` |
|---|---|
| Truth | The journal. There are no balance rows; registers, trial balances, statements, agings, and findings are derived folds, never authoritative, always verifiable by recomputation (`fa verify registers` — available now). |
| Immutability | Append-only. Corrections are `Reverse` and one-step `Replace` (`fa reverse --replace-with`) entries with `SUPERSEDES` lineage (available now); `fa reclass` moves an amount between accounts as a Reclassification citing its target, and restatement cases run from open through determination, rehearsal, dual-control approval, posting and disclosure with `fa case` (available now; a Restatement-class case's posting waits on `fa-651f`). Period close, reopen, and lock are journaled, approved control entries — never a flag (available now). |
| Time | Bitemporal by construction: period-scoped entries have a validated **effective date**; all entries have a commit-assigned **recorded sequence**, never user-supplied (available now). Undated Book controls follow registered applicability rules. Instant selectors resolve through retained TimeEvidence (available now). GQL selectors `FOR PERIOD FY2024 AS KNOWN AT 2025-03-03` (`fa-5c1`), `AS ORIGINALLY REPORTED`, `AS ISSUED TO <audience>`, `AS REPORTED IN <certificate>` and `AS CURRENTLY STATED` (`fa-wrrw`) are target GQL selectors, not backups. On `fa tb`, `fa statement` and `fa explain balance` the first three are available now as flags reading one period: `--as-originally-reported` at the certificate its first journaled `StatementIssuance` (`fa statement issue`) issued, else at its first Lock; `--as-issued-to <audience>` at its first issuance to that audience; `--as-reported-in C:<oid>` at that retained statement certificate's known-at. |
| Exactness | `Amount { unit, mantissa: i128 }` at the unit's registered scale; every rounding, allocation, and FX conversion names a registered law and exact error bound (available now). Native residual postings are explicit where the law requires them; base-valuation residuals are recorded and absorbed under plan §5.2 (`fa-s3c`). No float ever touches an amount. No tolerance. No auto-balancing. |
| Evidence | Nothing posts without a why: documents, attestations, supplements, REA events (`fa event record`), and `fa explain evidence <entry-vid>` are available now; posting-rule versions (`fa-c34`) complete the target content-addressed provenance closure. |
| Proofs | A journal-level Merkle accumulator with signed `TransparencyCheckpoint`s, `.fab` evidence bundles with signed production receipts, and `fa-verify`, a dependency-free static verifier a regulator runs on an air-gapped laptop (available now; an external witness quorum is target, `fa-qtfd`). |
| Graph | Accounts, entities, parties, instruments, documents, periods, findings are vertices; legs, approvals, ownership, settlement, intercompany pairs, supersession are edges. Journal-entry tests, Benford, duplicates, sequence gaps, cutoff, aging, round-trips, structuring, circular flows, layering, communities, related-party exposure, shell signatures, concentration, identity resolution, LIBR/FIFO/LIFO/pro-rata tracing of tainted value (single-account and network), court-ordered restitution schedules, Ponzi net investment, balance-sheet and cash-flow solvency, preference and fraudulent-transfer lookback, rising-tide and pro-rata distribution, and but-for damages run via `fa procedure run` today; check kiting has no procedure yet (`fa-m35p`). |
| Determinism | Same closure ⇒ byte-identical output, with a certificate (`fa tb|statement|explain|open-items --certify`, `fa replay` — available now; cross-registry-version certificate survival `fa-vdc`). |
| Agents | Dry-run plans (`fa post --dry-run --plan-out` / `fa commit --plan`), refusals that name the law and the exact fix (each catalog refusal also carries the Appendix D refusal object: an instance id, `where`, `why`, a `fix.argv` that parses against the verb registry, and the values the offending field admits, the same on CLI and MCP), `fa triage` in one call, robot-mode NDJSON, `fa-mcp` with the same verbs, drafts with authorized promotion (`fa draft new|plan|promote`), and every typed posting verb of plan §15.3, `fa invoice|bill|receipt|payment|accrue|defer|reclass|reverse|replace|allocate|reserve|post-reserve|void-reserve` and `fa batch`, with `fa revalue` for `fa fx revalue` (available now); plan certificates (`fa-we7`) and the rest of the draft life cycle (`fa-s7x`) are target. |
| Safety | `unsafe_code = "forbid"` everywhere, zero unsafe islands. Dependencies are `std`, the pinned nightly and suitable Franken-suite foundations with exact pins and recorded transitive paths. Unrelated third-party crates are not imported directly by accounting code. FrankenGraphDB is the sole book storage engine. |

---

## Quick example

> Note: see [`### Try it today`](#try-it-today) above for the runnable walkthrough executed in CI today. The snippet below shows the 1.0 target surface; commands not yet live carry their delivering bead (`fa-…`).

```bash
# Available today (`--name` required; `--gaap` is target fa-9ae):
fa book create --book acme.fabook --name "Acme" --keys fa.keys --base-unit USD --calendar monthly
fa chart import --template us-gaap-smb --book acme.fabook

# Bare `fa` is triage, never a TUI. Agents start here (available today).
fa triage --book acme.fabook --json

# A typed invoice, rehearsed: the plan shows the legs its lines derive (available today, as are `fa bill` and `--draft`; the caller names the accounts: no Canon rule or tax yet, fa-i7e / fa-c34).
fa invoice --party ACME-CUST-17 --number 10442 --date 2026-03-14 --receivable 1200 --revenue 4000 \
   --line 'qty=10 unit_price="125.00 USD" item=SKU-9 product=Widgets' \
   --evidence <document-oid> --dry-run --plan-out inv-10442.plan --book acme.fabook --json
#  → plan: legs (1200-AR 1,250.00 D for ACME-CUST-17 / 4000-Revenue 1,250.00 C), period FY2026-P03 Open → Admit,
#     evidence heads, certificate digest
fa commit --plan inv-10442.plan --book acme.fabook --json   # commits the reviewed plan; returns the entry vid
# The customer pays: the receipt applies itself to the invoice's open item; its number becomes the cash leg's memo, which fa bank match compares with the statement line's reference (available today; also fa payment).
fa receipt --party ACME-CUST-17 --number WIRE-IN-1 --date 2026-03-20 --cash 1010 --receivable 1200 --amount "1250.00 USD" --applies <invoice-vid> --book acme.fabook --json

# Why is this balance what it is? The register, its fold proof, and every contributing entry with evidence (available today with `--period`).
fa explain balance 1200 --period FY2026-P03 --as-known-at '2026-04-02T00:00:00Z' --book acme.fabook --json

# The books as they stood on a date, for a period — a selector, not a restore (available today with `--period` / `--fiscal-year`).
fa tb --fiscal-year 2025 --as-known-at '2026-02-01T00:00:00Z' --book acme.fabook --json
# As originally reported: one period at the certificate its first StatementIssuance issued, else at its first Lock, on tb, statements and balance explanations (available today).
fa tb --period FY2025-P12 --as-originally-reported --book acme.fabook --json
fa statement balance-sheet --for FY2025-P12 --compare FY2024-P12 --as-originally-reported --certify --book acme.fabook --json

# Corrections are lineage. The original stays (`fa reverse <vid> --reason <name|code>` available today).
fa reverse <vid> --reason WrongAccount --book acme.fabook --json
# Accruals and deferrals: an Adjusting entry with its scheduled reversal, from two legs or from an intent; fa batch
# commits several entries atomically (available today).
fa accrue --date 2026-03-31 --debit 6100 --credit 2100 --amount "1500.00 USD" --reverse-on 2026-04-01 --evidence <oid> --book acme.fabook --json
# One-step correction: the reversal and the corrected entry commit together, both or neither (available today).
fa reverse <vid> --reason WrongAmount --replace-with corrected.json --book acme.fabook --json
# Restatement cases: open one over the periods a correction affects, journal its determination, then
# rehearse, approve (dual control), post and disclose it with fa case rehearse|approve|post|disclose (available
# today; a Restatement-class case's posting waits on fa-651f).
fa case open --kind Restatement --periods FY2024-P12 --narrative <memo-oid> --book acme.fabook --json
fa case determine 1 --on 2025-03-03 --authority <minutes-oid> --book acme.fabook --json

# Rehearse the close on a draft, diff it, let a human promote it (available today: close dry-run posts the draft's
# plans as one scratch batch and shows the stock trial-balance change; --branch draft:<name> reads that rehearsal in
# tb, statement, explain and gl; fa diff compares two recorded frontiers of trunk today, and comparing a branch is
# target fa-s7x).
fa draft new close-2026-03 --book acme.fabook --json
fa close dry-run --period FY2026-P03 --draft close-2026-03 --json
# Target (fa-s7x):
fa diff --from draft:close-2026-03 --to trunk --json

# Forensics, in the database, certified (available today; `fa procedure list` names every registered procedure and its parameters).
fa procedure run jet.weekend --book acme.fabook --json
fa procedure run trace.libr --effective-through 2025-12-31 --account 1010 --source <deposit entry vid> --book acme.fabook --json
fa procedure run graph.related_party_exposure --param max_depth=4 --book acme.fabook --json
# A procedure runs under a work meter with no clock, entropy, network or filesystem: --budget refuses it mid-run (exit 3, no finding) at the first unit past the cap.
fa procedure run graph.layering --budget 5000000 --book acme.fabook --json
# Every procedure that selects accounts (suspense and inventory aging, intercompany, lapping, capitalization, confirmation coverage, payroll, cash-flow solvency, preferences, Ponzi and distribution) tests the accounts holding a journaled role, never accounts guessed from their codes or names (a chart's accounts may carry "roles" too, and the three templates' do). While no account holds its role a procedure refuses with this fix (exit 3), rather than report an empty population as nothing found.
fa chart role 1950 suspense --book acme.fabook --json
fa chart roles --book acme.fabook --json
fa procedure run jet.suspense_aging --effective-through 2025-12-31 --book acme.fabook --json

# Audit samples reproducible from a declared seed, over an account's open items at one recorded coordinate, and the Stringer bound over the audited values (available today).
fa sample mus --account 1200 --seed 20260115 --interval "5000.00 USD" --as-of 2025-12-31 --book acme.fabook --json
# Stratified over book-value bands the auditor declares; allocation is proportional (the decision card's pinned fallback) until a sampling policy is activated.
fa sample stratified --account 1200 --seed 20260115 --size 40 --band "1000.00 USD" --band "10000.00 USD" --book acme.fabook --json
fa sample evaluate --account 1200 --seed 20260115 --interval "5000.00 USD" --as-of 2025-12-31 --as-known-at <seq> --audited audited.json --confidence 95 --book acme.fabook --json

# Proofs an outsider can check without the book (`fa bundle produce` and `fa-verify bundle` available today).
fa bundle produce --account 1000 --from 2025-01-01 --to 2025-12-31 --inline-documents --out fy2025-cash.fab --receipt-out fy2025-cash.receipt --book acme.fabook --json
fa-verify bundle fy2025-cash.fab --key <checkpoint_public_key> --receipt fy2025-cash.receipt --json

# Witnesses (the CPA's year-end signature, plan §13.5): each witness cosigns a recorded checkpoint with its own key, only after the book proves its history extends what that witness signed last; a second witness adds its signature --onto the first's file, and fa-verify checks a quorum. Detection, not prevention: a rewritten history is refused a cosignature, and cosigned checkpoints that disagree expose it (available today; witness policies and key rotation journaled in the book are not yet, fa-qtfd).
fa checkpoint witness-key --out cpa-witness.key --json
fa checkpoint witness --key cpa-witness.key --previous fy2024-cpa.cp --out fy2025-cpa.cp --grant witness --book acme.fabook --json
fa-verify checkpoint fy2025-cpa.cp --key <checkpoint_public_key> --witness <cpa witness public key> --json

# A certified GL detail for the file; `fa replay C:<oid>` reproduces it after later postings (available today; also roll-forward and aging).
fa gl detail --account 1000 --from 2025-01-01 --to 2025-12-31 --certify --book acme.fabook --json

# The auditor's extract: the AICPA ADS GL package (also saft, csv-gl, beancount, hledger), what the trial balance folds, with its export coordinate certificate (available today).
fa export ads --period FY2025-P12 --out ads-fy2025-12 --book acme.fabook --json
# With proofs: the extract at exactly a recorded state's sequence, beside that state's complete-prefix bundle and receipt; fa-verify ads proves offline that GL_Detail holds exactly the proven entries the export selects, no more, no fewer, and that Trial_Balance is exactly their refold (available today; the chart file's names are not proven, nor is an account-month scope yet, fa-2q91).
fa export ads --period FY2025-P12 --out ads-fy2025-12 --with-proofs --book acme.fabook --json
fa-verify ads ads-fy2025-12 --key <checkpoint_public_key> --json

# Reconcile the bank: retain the statement (camt.053/052, a bank's standard BAI2 file, OFX, SWIFT MT940, CSV) for its cash account, propose matches against cash-leg memos, confirm them one line at a time with `fa bank confirm`, and attest the statement close with `fa bank reconcile`; matching replays the complete statement, so the owner opts in with --grant privileged (available today).
fa bank import stmt-2026-03.camt053.xml --bank-format camt053 --account 1010 --book acme.fabook --json
fa bank match --import <manifest_oid> --grant privileged --book acme.fabook --json

# But for the breach: fork a scenario at the current trunk, run the receipts the contract would have produced in it (never on trunk), and diff it against trunk per account (available today; the scenario is a scratch replay of the trunk prefix plus its intents; reads take --branch scenario:<name>). --certify retains the diff as a certificate: trunk certified natively at the fork, the scenario bound to exactly the intents it held, so fa replay reproduces the damages schedule byte for byte later, and fa certificate status names the intents run since.
fa scenario fork but-for-breach --from 2025-07-01 --evidence <contract_oid> --book acme.fabook --json
fa scenario run but-for-breach --intent but-for-receipts.json --book acme.fabook --json
fa scenario diff but-for-breach --period FY2025-P12 --certify --book acme.fabook --json
fa replay C:<oid> --book acme.fabook --json
fa certificate status C:<oid> --book acme.fabook --json
fa statement income-statement --for FY2025-P12 --branch scenario:but-for-breach --book acme.fabook --json

# The receiver takes over: on the appointing order, a book-scope legal hold pins everything the book recorded through the appointment, and the estate's branch forks there (available today; the branch is the `receivership` scenario until substrate branches land, so the estate posts with --scenario receivership and reads take --branch scenario:receivership). fa document hold place --through <seq> places a book-scope hold on its own.
fa book fork receivership --authority <order_oid> --at <appointment_seq> --book acme.fabook --json
fa post --intent estate-rent.json --scenario receivership --book acme.fabook --json

# Who and what the events name: parties, a relationship, an instrument mirrored by a GL leaf, and a new account (available today).
fa party add vendor.json --book acme.fabook --json
fa party relate O-1 ACME --kind owns --basis equity_voting --valid-from 2025-01-01 --pct 51/100 --book acme.fabook --json
fa instrument add operating-account.json --book acme.fabook --json
fa entity add acme-de.json --book acme.fabook --json
fa party bind V-17 --external-id qbo:55 --book acme.fabook --json
fa party identifiers V-17 --identifier bank_routing=<routing> --identifier bank_account=<account> --key chg-2026-03-17 --book acme.fabook --json
fa chart open office-supplies.json --opened 2026-03-01 --book acme.fabook --json

# Dimensions beside the legal entity and the party: a cost center (also department, project, product, region, fund, grant, segment) with a parent and valid time, which a leg tags with "dimensions": {"cost_center": "CC10"}; the kernel refuses a value the book does not hold, or one outside its window (FA-REF-194) (available today; per-account required dimensions and reports by dimension are not yet, fa-ficc).
fa dimension add cost_center CC --name "All operations" --book acme.fabook --json
fa dimension add cost_center CC10 --name Warehouse --parent CC --from 2026-01-01 --book acme.fabook --json
fa dimension list cost_center --book acme.fabook --json
```

An account-subtree extract needs authenticated hierarchy and complete account/range coverage, or the complete-prefix fallback. Membership alone does not prove scope completeness. A stock balance also needs its contributing opening history or an explicitly labeled baseline plus complete delta; the verifier reports these predicates separately.

```gql
-- fa query runs the profile's native reads today (example above); this query also needs a CALL inside its MATCH
-- pipeline (fa.open_amount), which this build refuses with the admissible form: target, later fa-5c1 slices.
MATCH (l:Leg)-[:POSTS_TO]->(a:Account {code:'1200'}), (l)-[:FOR]->(:DimensionValue)<-[:IS]-(p:Party)
WHERE EXISTS { MATCH (p)-[:RELATED_TO|OWNS|CONTROLS*1..3]-(:LegalEntity {code:'ACME'}) EFFECTIVE AT l.effective_date }
FOR PERIOD 'FY2025' AS KNOWN AT '2026-02-01T00:00:00Z'
CALL fa.open_amount(l) YIELD open, age_days WHERE age_days > 90
RETURN p.name, sum(open) AS exposure ORDER BY exposure DESC;
```

---

## Financial statements

The first statement definitions are `balance-sheet` and `income-statement`.
They calculate exact amounts from the journal and check that their mappings
cover every relevant leaf account exactly once. Each native unit has its own
rows. Computed totals use checked integer arithmetic; no exchange rate or
rounding adjustment is inferred.

```bash
fa statement balance-sheet --for FY2026-P03 --compare FY2026-P02 \
  --book ./books/myco --json
fa statement income-statement --for FY2026-P03 --compare FY2026-P02 \
  --known-at HEAD --certify --book ./books/myco --json
fa replay C:<oid-from-report_certificate> --book ./books/myco --json
fa statement diff --before-certificate C:<oid-as-reported> \
  --after-certificate C:<oid-as-restated> --for FY2026-P03 --book ./books/myco --json
```

Balance sheets include opening history through the selected period and show
unclosed earnings explicitly, so the statement can balance before a fiscal
close. Income statements show selected-period activity. Comparatives use the
same known-at snapshot as the current column; `--known-at` also accepts a
commit sequence or a retained TimeEvidence instant, and `--as-known-at` is an
alias. The statement event includes the definition version and digest, the
column coordinates, exact amounts, and the account-to-line mapping.

An ordinary statement read writes nothing. `--certify` retains its immutable
certificate and returns the complete bytes inline; `--certificate-out <new-file>`
also writes a binary copy without replacing an existing file. Replay uses the
same checked presentation and preserves both columns after subsequent postings.
MCP exposes this as `fa_read_statement`, under the fixed launch authority, with
inline certification and no caller-selected output paths.

Two retained certificates of the same statement compare directly. The
`--before-certificate` and `--after-certificate` form replays both and bridges
them, so the statement as reported (the certificate that was handed out) and as
restated (a later certificate) are compared without selecting anything from
HEAD. A stated `--for`, `--compare` or `--definition` is checked against the
certificates. With `--certify` the comparison keeps those exact source
certificates, and `fa statement trace --from-diff C:<oid> --certify` attributes
it to each intermediate publication.

### Rendered documents

`fa tb` and `fa statement <definition>` also render the report as a document
with `--render md|html|svg|pdf|pdfa`:

```bash
fa tb --period FY2026-P03 --render md --book ./books/myco --json
fa statement balance-sheet --for FY2026-P03 --render pdfa \
  --out balance-sheet-2026-03.pdf --book ./books/myco --json
```

Markdown travels inline in the `rendered` event unless `--out <new-file>`
names a file. HTML, SVG, PDF and PDF/A-2b are written to a new `--out` file,
never over an existing one. Every format is built from one deterministic
Markdown IR, whose digest the `rendered` event reports with the file's own
digest. Amounts come from exact integers at the unit's scale; no float is
involved.

A document's date is the latest corroborated TimeEvidence tick known at the
report's own frontier, never the machine's clock. The same report at the
same `--as-known-at` therefore renders to the same bytes whenever it is
rendered, and a historical read is never dated by a later tick. A book whose
frontier has no such tick (one that never ran `fad` with timed work) renders
Markdown only; the other formats are refused with exit 4. PDF/A output must
pass the built-in PDF/A-2b validator before it is written. The document is
written before a `--certify` certificate is retained, so a refused render
leaves nothing behind. Summary trial balances, functional-currency views,
scenario branches, statement diffs and traces are not rendered yet. Over MCP,
`render: md` returns the Markdown inline; file formats are host-only.

This slice covers one book and native units. Custom company layouts, cash-flow
and equity-roll-forward statements, consolidation, FX translation, and
presentation rounding remain separate work. A certificate establishes replay
and arithmetic over the journal; it does not establish GAAP conformity.

### Statement issuance

When certified statements leave the entity, `fa statement issue` journals a
`StatementIssuance` (plan §12.5): the retained statement certificate, the
period it reports, its known-at coordinate, the audience (`board`, `auditor`,
`lender`, `regulator`, `sec`, `tax-authority` or `other`) and an optional
transmittal document. It takes two people. The preparer, holding `close`,
plans the issuance; an approver who is not the preparer approves the plan's
digest; the preparer commits exactly that plan.

```bash
fa statement income-statement --for FY2026-P03 --certify --book ./books/myco --json
fa statement issue --certificate C:<oid> --issued-to auditor --dry-run --book ./books/myco --json
fa approve --proposal <proposal_digest> --as reviewer --book ./books/myco --json
fa statement issue --plan <plan-bytes-file> --approval <approval_vid> --book ./books/myco --json
fa statement issuances --for FY2026-P03 --book ./books/myco --json
```

A period's issuances are numbered in commit order, and the approved plan
names its number. The first issuance is what `--as-originally-reported` reads
from then on: the known-at of the certificate it issued, ahead of the period's
Lock. A later issuance of restated statements is recorded beside it and never
moves that coordinate. An issuance is never withdrawn.

Two more restatement views read a period at a reported coordinate. On `fa tb`,
`fa statement` and `fa explain balance`:

- `--as-issued-to <audience>` reads the period as issued to that audience: at
  the certificate of its first issuance to it (FA-REF-173 when it never was);
- `--as-reported-in C:<oid>` reads it as reported in that retained trunk
  statement certificate, which must report the period in a current or
  comparative column (FA-REF-174 otherwise).

Only one restatement view applies at a time, and none combines with a known-at
selector. `AS CURRENTLY STATED` with supersession netting remains a target
(`fa-wrrw`, after `fa-oz3`).

## The six bets

| Bet | One-line statement |
|---|---|
| **A1 · One Posting Universe** | The journal is the database. Balances are deterministic, certified folds at a `(book, branch, known-at, effective)` coordinate, materialized incrementally, verified by recomputation. |
| **A2 · Bitemporal by Construction, Period Law Mechanized** | Effective × recorded time are orthogonal selectors; close, reopen, and restate are journaled, authorized events enforced at commit; restatements have first-class lineage and diff certificates. |
| **A3 · Evidence-Native and Outsider-Verifiable** | Every entry carries a content-addressed provenance closure; bundles with inclusion proofs; a dependency-free verifier. |
| **A4 · The Ledger Is a Graph (REA)** | Relationships are first-class; forensic questions are graph procedures over the time-travelable graph with determinism witnesses. |
| **A5 · Exact and Deterministic** | Exact fixed-scale integers, named rounding/allocation/FX laws, certified replayable reports. |
| **A6 · Agent-Native with Counterfactual Branches** | Typed intents, dry-run plans, teaching refusals, branch-per-task, what-if/but-for scenarios with ledger diffs, one verb registry across CLI/daemon/MCP. |

---

## How it works

```
┌──────────────────────────────────────────────────────────────────────────┐
│  TELLER     fa (CLI, robot mode) · fad (daemon, writer lease, local RPC) │
│             fa-mcp (MCP tool clusters, resources, macros) · fa (library) │
│             one verb registry; GQL + the FrankenAccounting profile       │
└──────────────────────────────────────────────────────────────────────────┘
                                     ▼
┌──────────────────────────────┐  ┌───────────────────────────────────────┐
│  CANON   typed intents ·     │  │  STEWARD   capability caveats · SoD   │
│  deterministic posting rules │  │  profiles (Agent/Auditor/Regulator/…) │
│  dry-run plans · backtests   │  │  access audit · holds · erasure law   │
└──────────────────────────────┘  └───────────────────────────────────────┘
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  FOLIO     admit → resolve → canon → abacus → laws → plan → commit → ack │
│            balance law · leaf-only · dimensions · idempotency · batches  │
│            two-phase holds · escrow balance limits · subledger control   │
│  ABACUS    Amount{unit,i128} · rounding/allocation/FX laws · exact wide  │
│  ALMANAC   calendars · periods · state machine · selectors · close DAG   │
│  PALIMPSEST supersession lineage · restatement cases · diff certificates │
└──────────────────────────────────────────────────────────────────────────┘
                  ▼                                       ▼
┌──────────────────────────────────┐    ┌──────────────────────────────────┐
│  DOCKET   documents · custody ·  │    │  LANTERN   JET · Benford · dupes │
│  attestations · bank lines       │    │  graph tracing · kiting · Ponzi  │
│  NOTARY   accumulator · bundles  │    │  solvency · sampling · findings  │
│  checkpoints · fa-verify         │    │  STATEMENTS/CONCORDAT  reports · │
│                                  │    │  multi-book · FX · consolidation │
└──────────────────────────────────┘    └──────────────────────────────────┘
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  FRANKENGRAPHDB   Chronicle (immutable commit stream = system time) ·    │
│  optimistic WriteTxn + point-read witnesses (SSI planned) · certificates │
│  Prism/fnx · lab runtime (asupersync) · valid time / branches / Ripple / │
│  Beacon / Warden as they land (plan Appendix H interim postures)         │
└──────────────────────────────────────────────────────────────────────────┘
```

- **Folio** is the only writer. Every proposal passes admit → resolve → canon → abacus → laws → plan → commit → ack; a dry run is the same pipeline without the commit, and its certificate names the snapshot, so the plan an agent reviewed is the plan that commits — or a typed `PlanInvalidated` with a fresh one. A post racing a close is an SSI conflict, not a nightly finding.
- **Registers are folds.** The posting transaction never touches a register; a supervised maintainer folds the committed delta stream in commit order and publishes a watermark; reads are O(1) at the watermark plus an exact tail fold. `fa verify registers` recomputes every cell from the journal and compares digests.
- **Palimpsest** keeps "as originally posted" and "as currently stated" both first-class. A `RestatementCase` is rehearsed on a branch, approved under dual control, posted as one batch, and disclosed with a certified as-reported-vs-as-restated diff.
- **Notary** maintains a journal-level Merkle accumulator in commit order (never on the write path), signs transparency checkpoints — the auditor's signature on the year-end root is the modern successor of initials on the ledger page — and produces deterministic evidence bundles that `fa-verify` checks with its own BLAKE3 and nothing else.
- **Lantern** registers every procedure as a deterministic, certified computation with a typed evidence row: a Benford statistic is `statistical` evidence, never an invariant, and a finding is a reproducible observation with cited entries, never an accusation.
- **Teller** is built under one rule: the first command an agent instinctively tries must work or be redirected with a copy-pasteable fix, and nothing an agent can type by accident may damage the books.

The full design — every subsystem, the normative object schemas, the intent catalog, the admissibility matrix, the CLI/MCP contract, the sixteen invariants, the operation-cost registry, and the foundation dependency ledger — is in [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md`](./COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md).

---

## Who it is for

| Reader | What they get |
|---|---|
| **CPA auditor** | A GL extract in the AICPA Audit Data Standards layout whose completeness is *proven*; journal-entry tests, Benford, duplicates, seeded reproducible sampling; evidence pulls to the document; a snapshot pinned at engagement start; a witness signature on the year-end checkpoint. |
| **Regulator / examiner** | Point-in-time positions (`--as-known-at`) and schedules (call report lines, FR Y-9C) derived from the ledger with certificates; a scoped, time-boxed, fully logged read-only capability. |
| **Litigation consultant / expert** | But-for scenarios on a branch with a certified damages schedule; hash-certified productions with chain of custody; a methodology that replays years later. |
| **Forensic accountant / investigator** | Follow-the-money across accounts, entities, and banks; related-party closure; layering, kiting, structuring, Ponzi detectors; legal tracing rules as code; legal holds; workpapers with verifiable references. |
| **AI agent** | `fa triage`; typed intents with plans; refusals that teach; stable self-verifying handles; `fa explain`; drafts and scenarios; a sandbox (`fa demo init`); an MCP server with the same verbs. |

What it is **not**: an ERP, a payments processor, a UI, a tax engine or GAAP interpreter, a blockchain, or a SaaS. Judgment — materiality, treatment, recognition — belongs to professionals and the agent skills that act on this system; the system makes every mechanical fact exact and every judgment attributable and reversible with lineage.

---

## Design philosophy

1. **Reuse the Franken suite.** `std`, the pinned nightly and suitable owner-maintained Franken projects are eligible dependencies. Pin and record their transitive paths; own the accounting laws and contracts here.
2. **Memory safety is structural**, with zero unsafe islands.
3. **`Cx` everywhere.** Rules and procedures run under a context with no clock, entropy, network, or filesystem.
4. **Exactness is constitutional.** No float in any amount path; every rounding is a named law.
5. **The journal is the source of truth, and it is append-only.** Derived structures are never authoritative.
6. **Recorded time is never user-supplied.**
7. **Period law and segregation of duties are enforced at commit.**
8. **Authorization precedes observation.**
9. **Deterministic by default**, with certificates and replay.
10. **Claims have types; costs are registered.**
11. **FrankenGraphDB is consumed, never forked.** Capabilities it has not shipped yet have registered interim postures (plan Appendix H).

---

## How it compares

| | `franken_accounting` | TigerBeetle | ERP GL (SAP/Oracle/NetSuite) | Fintech ledger APIs | Plain-text accounting |
|---|---|---|---|---|---|
| Primitive | N-leg immutable entry, balanced per unit | 2-leg immutable transfer | Immutable posted journal; mutable balance tables | 2-leg or N-leg postings | Text transactions |
| Balances | Certified folds, never authoritative | Four balance fields per account | Mutable balance tables | Balances per account | Recomputed from text |
| Journal entry as object | ✓ | ✗ (encode in `user_data`) | ✓ | partial | ✓ |
| Periods / close / lock | ✓ journaled, enforced at commit | ✗ | flags | ✗ | ✗ |
| Restatements with lineage | ✓ cases + diff certificates | ✗ | manual | ✗ | git history |
| Bitemporal ("as known at") | ✓ by construction | ✗ | ✗ | ✗ | git history |
| Evidence model | content-addressed closure | ✗ | attachments | ✗ | filenames |
| Outsider-verifiable proofs | ✓ accumulator + `fa-verify` | ✗ | ✗ | ✗ | ✗ |
| Forensic graph analytics in-DB | ✓ | ✗ | ✗ | ✗ | ✗ |
| Branches / what-if | ✓ | ✗ | ✗ | ✗ | git branches |
| Exact arithmetic | i128 + laws | u128 | decimal columns | decimal/int | decimal |
| Deterministic simulation testing | ✓ (lab runtime) | ✓ (VOPR) | ✗ | ✗ | ✗ |
| Agent-native surface | CLI robot mode + MCP | client libraries | ✗ | REST/GraphQL | ✗ |
| System of record custody | yours (a directory) | yours | vendor/on-prem | SaaS | yours |

> **Target state.** The `franken_accounting` column is the complete design target, beyond the implemented subset described above. Several substrate capabilities it relies on (valid-time contracts, branch fork/merge, Ripple views, escrow, the MMR, the UDF VM) are planned in FrankenGraphDB and have registered interim postures in the plan's Appendix H.

---

## Installation

There are no releases or installers yet. When Gate G1 lands, the quick start will be:

```bash
git clone https://github.com/Dicklesworthstone/franken_accounting
cd franken_accounting
cargo run -p fa-cli -- demo init --scenario retail --seed 7
```

Releases will ship through the suite's self-releaser (`dsr`), never GitHub Actions.

---

## Repository layout (target)

```
COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md   the single source of truth
AGENTS.md                                                   operating rules for agents
registries/        constitution, invariants, evidence, slo, units, laws, entry classes,
                   admissibility, intents, procedures, caveats, SoD, verbs, exit codes,
                   refusal catalog, formats, robot schemas, operation costs, foundation deps
crates/            fa-types fa-money fa-time fa-registry fa-claim fa-sim-harness fa-model
                   fa-canon fa-policy fa-intents fa-journal fa-registers fa-escrow fa-palimpsest
                   fa-docket fa-notary fa-statements fa-concordat fa-lantern fa-query fa-steward
                   fa-formats fa-verbs fa fa-demo fa-cli fad fa-mcp fa-reference fa-sim
                   fa-oracles fa-gen fa-bench fa-conformance fa-fuzz fa-verify
tools/registry-check   std-only validator of the registries (G0)
scripts/check.sh       the one gate (verdict contract: exit code is the verdict)
docs/                  negative evidence, ADRs, threat & trust model
templates/             chart-of-accounts and statement-definition templates (data)
```

---

## License

MIT License with the OpenAI/Anthropic rider — see [`LICENSE`](./LICENSE). The rider is a condition of the license and must accompany every copy and derivative work.
