# Launch-selected daemon register maintenance

The daemon can own maintenance of native posted/pending period register
cells in the same serving region and on the same held book writer as its
requests and timed effects. No worker is detached and no second writer opens
the book. The default launch remains unchanged: maintenance is disabled.

```sh
fad serve --book ./books/acme --bootstrap-system \
  --register-period FY2026-P03 --register-period FY2026-P04 --json
```

Repeat `--register-period` for 1 to 64 distinct exact period codes. The
operator's order determines the initial rotation. A code is not a fiscal-year
selector or a date expression; it is neither trimmed nor silently corrected.
The scheduler bounds a code to 128 bytes and rejects whitespace/control
characters and missing option values. Selection is fixed at local launch;
wire requests cannot configure maintenance. An unknown code is reported as a
per-period error; it does not create a period or stop valid periods advancing.

The local launcher must explicitly opt into the existing `--bootstrap-system`
posture. This is the book-key owner's trusted local authority, not a newly
issued capability, and the writer lease does not grant it. Status/stop reject
maintenance launch arguments before observing a book or socket.

## One period per cycle, using the native maintainer

After the existing clock observation and eligible expiry/reversal work, the
daemon attempts exactly one configured period and rotates to the next, even
when the attempt fails. There is no catch-up drain. The next timer deadline
is computed after maintenance finishes, so a fold lasting longer than one
interval does not keep the timer continuously due ahead of foreground I/O.
The retained partial-frame and stop behavior uses the existing serving loop.
Cancellation before admission performs no maintenance operation.

Each attempt calls the existing `Book::advance_registers` / equivalent
`AsyncBook` method. Atomic cell/cursor publication, posted/pending semantics,
migration visibility, overflow handling and retired-delta fallback remain
owned by the native maintainer. This scheduler never invokes an explicit
rebuild to erase a drift finding. An operator must independently verify and
explicitly authorize repair. Restart loses only transient scheduling/status
counters; the native persistent cursor remains authoritative for resumption.

Clock corroboration still gates automatic expiry and reversal effects. It
is not needed to maintain disposable caches of already committed facts.
A failed or uncorroborated clock sample therefore need not prevent register
maintenance; timing and maintenance errors are reported separately.

## Status and scope

`fad_serving` and `fad_status` include `register_maintenance`, null when
unconfigured or not serving. When enabled it contains the scope, one-period
cycle bound, total attempts, next period, `certified: false`, and per-period
attempt counts, most recent successful consumed frontier, publication
sequence, incremental decode count, rebuild/no-write flags and current error.
`published_at` is null when the last successful attempt did not write.

A failed attempt retains the period's earlier successful metadata as history;
it never advances that successful frontier. Another period's success cannot
clear its error. The error clears only after that same period succeeds.
Error strings have a bounded UTF-8-safe diagnostic length. No amounts, entry
payloads, keys or documents are added to maintenance status.

These are operational cursors, not certified RegisterCheckpoints or a claim
that all configured periods share a single current snapshot. Reports continue
to use their existing independent literal folds. The bound is one publication
attempt, not a CPU, memory, read-amplification or latency bound on the native
fold. Automatic discovery of periods, adaptive cadence, entity/open-item
families and cached certified report reads remain separate work.

## Validation for this change

Added tests cover bounded exact configuration, absent progress, fair rotation,
per-period failures, native posted/pending updates, late-recorded entries,
cursor resumption, unknown periods, bad clock samples, cancellation, bounded
Unicode diagnostics, real fragmented frames and stop, and launch argument
admission. Run the project's remote Rust gates before relying on the change:

```sh
rch exec -- cargo test --locked -p fad
rch exec -- cargo clippy --locked -p fad --all-targets -- -D warnings
cargo fmt --all -- --check
```

The authoring environment lacked `rch`, `cargo` and `rustc`. These Rust tests
and compilation were not executed there; source/patch checks are not a green
build or gate completion.
