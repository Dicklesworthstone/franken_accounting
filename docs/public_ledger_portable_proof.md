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

## Observed acceptance (2026-11-03)

Both complete university replays and both independent portable proofs passed
with the actual executables built from
`f3f1d66b25f9b01535efa9de74e38cb600b08a59`. Each fresh replay preserved all
1,055 source rows, posted 1,051 monetary legs across 27 Entries and nine
migration runs, registered 223 accounts, and executed 521 native commands.
The source, driver, normalizer and executable hashes remained unchanged.

| Actual portable result | Ordinary university | Source-bound university |
|---|---:|---:|
| Independent verifier verdict | verified | verified |
| Native inputs | 10 | 12 |
| Bundle minor version | 0 | 1 |
| Canonical migration-run bodies | 9 | 9 |
| Migration-source witnesses | 0 | 9 |
| Migration-run and Entry fragments | Both present | Both present |
| Bundle bytes | 263,355 | 273,822 |
| Native helper commands | 4 | 4 |

The helper is the exact version introduced in `a0c79c5`, SHA256
`61b3ddd43e78147ac61a81c8508f2d71c95371b2336c8d6f5db2efc202d765b0`.
The [execution record](../evidence/public_ledger/validation-2026-11-03-entry-fragments.json)
retains the complete original failure, subsequent measured results, actual
commands, verifier receipts and artifact hashes.

The [public offline example](../examples/public_ledger/university_source_bound/README.md)
contains the actual source-bound bundle, checkpoint and receipt from this
successful run, compressed to 85,694 bytes in total. Its manifest records both
compressed and original hashes, the expected certificate and the fixture trust
anchor. Its reproduction command verifies those public files without opening
or possessing the generated native book.

These workload passes are distinct from the complete Rust regression gate.
The earlier hosted run at `f3f1d66` passed the 512-leg retained-certificate and
portable-proof regression and all 878 independent-verifier tests. Its separate
fragment-object group failed because the test staged a write only after a
concurrent publication had advanced its snapshot. The genesis filter selected
zero tests, and the subsequent lifecycle command was not reached. That job
remains recorded as failed. The later operation-order and filter corrections
must establish their own runtime acceptance; the positive real-data results
do not stand in for those tests or the complete workspace gate.

The same path also passed for the complete Health Care Authority selection
under the explicit `agency-period` boundary. Its source-bound replay preserved
1,440 source rows and 1,405 monetary legs across three monthly Entries; the
independently verified departmental report contained 12 native inputs, one
migration-run body and one source witness, including both run and Entry
fragments. The replay passed 39 driver checks over 666 native commands, and
the portable report passed 30 independent verifier checks. The
[separate execution record](../evidence/public_ledger/health-authority-agency-period-validation-2026-11-03.json)
retains the newer helper pins and the strict fund/class profile's unchanged
refusal. That distinction is necessary because the report uses a declared
monthly activity grouping while preserving the two offsetting source class
balances.

The source-bound companion rejects `--resume` and every abbreviation that the
stock parser could treat as that option before resolving the repository or
observing an existing output. Its six argument-admission tests and the expanded
public-ledger/source suite passed together: 99 tests with exit 0. This preserves
the companion's fresh-book contract; ordinary recovery remains a separate
stock-driver operation with its original source and boundary pins.
