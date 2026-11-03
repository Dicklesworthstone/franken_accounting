# Independently verifying a complete public-ledger report

The [public-ledger replay](public_ledger.md) imports each selected Oklahoma OMES
agency's complete published monthly activity, compares the native journal and
reports with an independent source fold, and checks exported CSV and ADS legs.
The portable-proof companion additionally produces a retained dimension
report bundle and asks the separate `fa-verify` executable to authenticate it
against its expected certificate, signed checkpoint, fixture public key and
detached receipt. It then compares the verified output's exact net and gross
account cells with the original source controls pinned when the import began.

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

Then exercise native source-population binding in a separate fresh book. The
canonical driver retains `--bind-source` in the recovery contract, applies it
to native preparation and retries, and preserves all source and accounting
assertions:

```bash
python3 -B scripts/public_ledger.py run --bind-source \
  --agency 66000 --out /tmp/fa-university-source-bound \
  --fa "$PWD/target/debug/fa" --fa-verify "$PWD/target/debug/fa-verify"

python3 -B scripts/public_ledger_portable_proof.py \
  --run /tmp/fa-university-source-bound \
  --out /tmp/fa-university-source-bound-proof \
  --fa target/debug/fa --fa-verify target/debug/fa-verify \
  --dimension department --value 1000001 --require-entry-fragments
```

Choose new output paths for each attempt. Existing replay and proof directories
are preserved; the proof output must be separate from the replay directory.
The proof helper requires the completed replay's actual `PASS` report,
checksummed recovery pins and original book identity, the original pinned
source manifest, matching driver and normalizer bytes, and the exact same
executable hashes. It checks these inputs again before declaring success.

For canonical replays, the helper inherits bound or unbound mode from the
original recovery contract. An explicit `--source-bound` or `--unbound` must
agree with that contract. Older fresh-companion runs that never recorded a
binding-mode pin still require `--source-bound` when verifying their bound
profile; the helper does not retrospectively add a recovery guarantee.

An interrupted canonical import resumes with its original mode and source
selection, without repeating or changing those options:

```bash
python3 -B scripts/public_ledger.py run --resume \
  --out /tmp/fa-university-source-bound
```

### Select an exact source dimension

`--dimension` supports `department`, `fund`, `product`, and `project`.
`--value` names the exact original code: leading zeroes and case are significant.
When omitted, the helper selects the first available code in lexical order.
Every selection must identify a distinct retained certificate in the completed
replay; a missing project population or unknown code refuses before native
commands or proof-directory creation.

For the complete Health Care Authority selection, first run the source-bound
import with its documented `agency-period` accounting boundary:

```bash
python3 -B scripts/public_ledger.py run --bind-source --agency 80700 \
  --balance-boundary agency-period --out /tmp/fa-health-bound \
  --fa "$PWD/target/debug/fa" --fa-verify "$PWD/target/debug/fa-verify"

python3 -B scripts/public_ledger_portable_proof.py \
  --run /tmp/fa-health-bound --out /tmp/fa-health-fund-proof \
  --fa target/debug/fa --fa-verify target/debug/fa-verify \
  --dimension fund --value 1000 --require-entry-fragments

python3 -B scripts/public_ledger_portable_proof.py \
  --run /tmp/fa-health-bound --out /tmp/fa-health-product-proof \
  --fa target/debug/fa --fa-verify target/debug/fa-verify \
  --dimension product --value 00 --require-entry-fragments
```

These commands are reproducible selections, not a claim that every dimension
has completed a measured native run. This agency has no published project
values. The original source's fund/class balances remain separately visible;
the monthly grouping does not invent balancing entries or discard rows.

## What the proof checks

The helper selects the requested retained dimension certificate from the
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
The bundle, checkpoint and detached receipt are hashed before verification;
their bytes must remain unchanged through inspection, optional public-example
emission and the final acceptance record. A successful verifier invocation
cannot authorize publication of subsequently replaced proof files.
The additional checks bind the observed book to its original checksummed
identity, and the selected dimension, retained certificate digest and every
migration-run body to the completed replay. Source-bound mode also requires
one source witness per migration run.

After native verification, the helper decodes the actual canonical report
output and compares its account nets **and** gross debit/credit amounts with
the independently folded original-source controls. These controls come from
the immutable `manifest.json` whose hash is in the original recovery pins;
editing only a completion report cannot replace the source oracle. The helper
accumulates the original monthly cells through the selected fiscal period and
checks the exact dimension value, stock selection, fiscal period, snapshot,
and inclusive period-end date. Increasing debit and credit by equal amounts
therefore fails even though the net balance is unchanged. Unsupported units,
pending amounts, duplicate account identities, truncated output and trailing
bytes refuse rather than lose accounting meaning.

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
| `report.fab` | The native portable dimension report bundle |
| `checkpoint.bin` | The separately exported signed checkpoint |
| `report.receipt` | The detached receipt from the native bundle producer |
| `trusted-public-key.txt` | The fixture key passed to the verifier |
| `commands.jsonl` | Exact actual native commands, output and exit status |
| `validation.json` | Result, verified output cells, original-source comparison, hashes and before/after input pins |

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

The historical source-bound companion test record above predates canonical
source-bound recovery. The companion remains a fresh-book convenience entry
point; use `public_ledger.py run --resume` for the new recoverable path.

The current portable-helper regression suite uses the committed university
bundle and original 66000 CSV, verifies their manifest hashes, and independently
folds the original department `1000001` rows using `Decimal`. Its exact net and
gross results must match the real decoded canonical output. Negative cases
cover altered report controls, wrong scope or snapshot, missing fiscal periods,
mode contradictions and malformed framing. These arithmetic and admission
tests do not create a new native cryptographic acceptance claim for the newer
helper or the Rust assertion-drift implementation.
