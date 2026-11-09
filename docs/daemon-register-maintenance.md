# Launch-selected daemon register maintenance

The daemon can maintain native and functional posted/pending period register
cells in the same serving region and on the same held book writer as its
requests and timed effects. No worker is detached and no second writer opens
the book. Maintenance is disabled until periods are selected.

```sh
fad serve --book ./books/acme \
  --register-period FY2026-P03 --register-period FY2026-P04 \
  --register-measure both --json
```

Repeat `--register-period` for 1 to 64 distinct exact period codes. The
operator's order determines the initial rotation. A code is not a fiscal-year
selector or date expression; it is neither trimmed nor silently corrected.
The scheduler bounds a code to 128 bytes and rejects whitespace, control
characters and missing option values. Selection is fixed at local launch;
wire requests cannot configure maintenance. An unknown code produces a task
error without creating a period or stopping valid tasks.

Alternatively, `--register-fiscal-year 2026` selects the complete year from
the book's calendar, including Opening, Adjustment and Closing periods. This
fixed cohort covers periods created after startup. It cannot be combined with
exact period selections.

`--register-measure native|functional|both` chooses the projections. Omitting
it preserves native-only maintenance. The option requires a period selector
and may appear only once. Functional maintenance folds committed base
valuations. Foreign postings without those valuations produce a visible
functional-task error; maintenance does not invent a rate or change a posting.

Maintenance uses the local book-key owner's narrow, book-bound Read, Verify
and Maintain service authority. It requires no `--bootstrap-system` option.
That separate option enables the existing clock, expiry and reversal work;
the writer lease and maintenance selection do not grant those timed effects.
Status and stop reject maintenance launch options before observing a book
or socket.

## One period and measure per cycle

Each maintenance cycle attempts one configured period and measure and rotates
to the next, even when an attempt fails. With `both`, the example rotates
March native, March functional, April native, April functional. When separately
enabled, clock observation and eligible expiry/reversal work run before the
timer's maintenance attempt. There is no catch-up drain. The next timer
deadline is computed after maintenance finishes, so a long fold does not keep
the timer continuously due ahead of foreground I/O.

Cancellation before admission performs no maintenance operation. A served
write also queues one coalesced maintenance wake using the same fair rotation.
It does not run timed accounting effects or postpone the regular timer.

Each attempt calls `Book::advance_registers_with` or
`Book::advance_functional_registers_with` under the serving context, or the
equivalent `AsyncBook` method. Atomic cell/cursor publication, posted/pending
semantics, migration visibility, overflow handling and retained-tail handling
remain owned by the selected maintainer. The scheduler never invokes an
explicit rebuild to erase a drift finding. An operator must independently
verify and authorize repair. Restart loses transient scheduling/status
counters; each projection's persistent cursor remains authoritative.

Clock corroboration still gates automatic expiry and reversal effects. It is
not needed to maintain disposable caches of committed facts. A failed or
uncorroborated clock sample therefore need not prevent register maintenance;
timing and maintenance errors are reported separately.

## Status and scope

`fad_serving` and `fad_status` include `register_maintenance`, null when
unconfigured or not serving. Enabled status includes the scope, selected
`measure`, one-attempt cycle bound, total attempts, `next_period`,
`next_measure`, `certified: false` and a `periods` row for each
period/measure task. Each row identifies its measure and retains attempts,
the most recent successful consumed frontier, publication sequence,
incremental decode count, rebuild/no-write flags and current error.
`published_at` is null when the last successful attempt did not write.

A failed attempt retains that task's earlier successful metadata as history;
it does not advance that frontier. Another period's success cannot clear its
error, nor can the other measure's success in the same period. The error
clears only after the same period/measure task succeeds. Error strings have a
bounded UTF-8-safe diagnostic length. No amounts, entry payloads, keys or
documents are added to maintenance status.

These are operational cursors, not certified RegisterCheckpoints or a claim
that all tasks share a current snapshot. Ordinary reports may use checked
caches and exact tails under their existing selection rules; certification
retains independent full verification. One publication attempt is not a CPU,
memory, read-amplification or latency bound on a fold. Adaptive cadence,
entity/open-item register families and cached certified reads remain separate
work.

## Focused validation

Regressions exercise launch selection, fair period/measure rotation, retained
foreign-currency valuations, missing-valuation error isolation, native
posted/pending updates, late-recorded entries, persisted cursor resumption,
unknown periods, bad clock samples and cancellation. Existing tests also
exercise bounded Unicode diagnostics, real fragmented frames and stop.

Use the pinned toolchain, in addition to the repository's required gates:

```sh
cargo test --locked -Z bindeps -Z git=shallow-deps -p fad --lib timed::
cargo test --locked -Z bindeps -Z git=shallow-deps -p fad --test register_launch
```
