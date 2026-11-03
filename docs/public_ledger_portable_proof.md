# Independently verifying a complete public-ledger report

The [public-ledger replay](public_ledger.md) imports each selected Oklahoma OMES
agency's complete published monthly activity, compares the native journal and
reports with an independent source fold, and checks exported CSV and ADS legs.
The portable-proof companion additionally produces a retained departmental
report bundle and asks the separate `fa-verify` executable to authenticate it
against its expected certificate, signed checkpoint, fixture public key and
detached receipt.

The university fixture is especially useful: its full dimension vectors
produce a 157-leg accounting Entry larger than the substrate's 16 KiB row limit.
The portable report therefore exercises the actual immutable Entry fragments
and migration-run fragments from a complete public dataset. This is an execution
path through the native producer and independent verifier; Python's framing
inspection describes the resulting profile and does not replace verification.

## Reproduce from a fresh book

Build the real binaries with the repository's pinned compiler and dependency
settings:

```bash
cargo +nightly-2026-08-31 build --locked -Z bindeps -Z git=shallow-deps \
  -p fa-cli --bin fa -p fa-verify --bin fa-verify --jobs 1
```

First run the complete ordinary migration and its portable report:

```bash
python3 -B scripts/public_ledger.py run --agency 66000 \
  --out /tmp/fa-university-stock \
  --fa "$PWD/target/debug/fa" --fa-verify "$PWD/target/debug/fa-verify"

python3 -B scripts/public_ledger_portable_proof.py \
  --run /tmp/fa-university-stock --out /tmp/fa-university-stock-proof \
  --fa target/debug/fa --fa-verify target/debug/fa-verify \
  --require-entry-fragments
```

Then exercise the stronger native source-population binding in a separate fresh
book. The companion adds `--bind-source` to native preparation and its exact
retry while retaining all of the ordinary driver's source and accounting
assertions:

```bash
python3 -B scripts/public_ledger_source_bound_replay.py --repo "$PWD" run \
  --agency 66000 --out /tmp/fa-university-source-bound \
  --fa "$PWD/target/debug/fa" --fa-verify "$PWD/target/debug/fa-verify"

python3 -B scripts/public_ledger_portable_proof.py \
  --run /tmp/fa-university-source-bound \
  --out /tmp/fa-university-source-bound-proof \
  --fa target/debug/fa --fa-verify target/debug/fa-verify \
  --source-bound --require-entry-fragments
```

Choose new output paths for each attempt. Existing replay and proof directories
are preserved; the proof output must be separate from the replay directory.
The proof helper requires the completed replay's actual `PASS` report,
checksummed recovery pins, matching original driver and normalizer bytes, and
the exact same executable hashes. It checks these inputs again before declaring
success.

## What the proof checks

The helper selects the first retained departmental certificate from the
completed report. It obtains a signed checkpoint for an explicitly returned
state identity, then produces the bundle against that exact state. It calls
the real verifier with all four external expectations:

```bash
fa-verify report report.fab \
  --key <trusted-fixture-public-key> \
  --checkpoint checkpoint.bin \
  --receipt report.receipt \
  --expect <retained-certificate-digest> --json
```

Successful process exit and an actual `verified` verdict are both required.
The additional framing checks bind the observed book, selected department,
retained certificate digest and every migration-run body to the completed
replay. Source-bound mode also requires one source witness per migration run.

With `--require-entry-fragments`, an ordinary university report must have the
ten-input native closure, including `MigrationRunFragment` and `EntryFragment`.
The source-bound form must have twelve native inputs, adding
`MigrationSource` and `MigrationSourceFragment` in the registered order.
Missing, extra, reordered or wrong-profile inputs fail the helper. The native
verifier remains responsible for authentication and accounting proof acceptance.

A fixture's public key establishes the caller-selected trust anchor for this
exercise. It does not establish an externally authenticated agency identity.
The source-bound migration profile proves the prepared normalized population
represented by its source witnesses; the replay's separate original-row checks
establish how that population relates to the published selection. The source
contains monthly activity aggregates, not original transaction-level journals
or opening balances.

## Retained outputs and a small public example

Each proof directory contains:

| File | Purpose |
|---|---|
| `report.fab` | The native portable departmental report bundle |
| `checkpoint.bin` | The separately exported signed checkpoint |
| `report.receipt` | The detached receipt from the native bundle producer |
| `trusted-public-key.txt` | The fixture key passed to the verifier |
| `commands.jsonl` | Exact actual native commands, output and exit status |
| `validation.json` | Result, observed closure, hashes and before/after input pins |

The optional `--emit-public-example` flag emits deterministic gzip/base64 and
hash metadata for exactly `report.fab`, `checkpoint.bin` and `report.receipt`.
Emission occurs only after independent verification and final input-pin checks
have passed. The three compressed files must total at most 2 MiB; larger
examples are explicitly omitted while their ordinary proof outputs remain.
No native book or private key is in this allowlist.

The GitHub workflow executes the stock and source-bound university replays and
their independent portable proofs as separate fail-fast steps, retains the
fixed public files and transcripts, and records the exact source revision and
native executable hashes. It also exercises the four `entry_storage_tests::`
genesis regressions, atomic fragment-object tests and automatic expiry/reversal.
The fragment witness-conflict regression stages its candidate write before a
concurrent publication; it then requires the stale commit to fail without
publishing that candidate.

## Validation boundary

The preceding hosted run at `f3f1d66b25f9b01535efa9de74e38cb600b08a59`
completed the full stock university replay: 1,055 source rows, 1,051 monetary
legs, 223 accounts, 27 Entries and 521 native commands. Its 512-leg retained
certificate/portable-proof regression and all 878 independent-verifier tests
passed. Its separate fragment-object group failed because the test staged a
write only after a concurrent publication had advanced its snapshot. The
genesis filter also selected zero tests. Those results are preserved as an
overall failed job, rather than relabeled as complete acceptance.

The helper and source-bound university workflow introduced here have received
source review. Their Python/native execution is not claimed until the hosted
steps execute successfully on the published revision. Use the actual
`validation.json`, command transcript and workflow results for that distinction.
