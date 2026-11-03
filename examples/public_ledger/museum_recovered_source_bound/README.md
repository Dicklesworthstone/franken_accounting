# Verify a recovered source-bound museum report

These three compressed public files contain a successfully verified report
from the **original recovered museum book**. The canonical replay imported
all **125 published FY2024 Q4 rows** for Oklahoma agency **20400**,
`J. M. DAVIS ARMS & HIST. MUSEUM`, producing **121 monetary legs, 15 Entries
and five source-bound migration runs**. Recovery continued the same book,
`51dbcd4ca627a6f6d81065b96af53252`, with its original packages and proposals.

The retained report selects **department 1000001, FY2024-P12**, at native
sequence **147**, with the exact stock cutoff **2024-06-30**. Its portable
bundle has ten native inputs, five canonical migration bodies and five source
witnesses. The additive storage inputs are `MigrationSource` and
`MigrationSourceFragment`; this small fixture does not require Entry fragments.

The separate portable-proof invocation completed four native commands with
exit 0. The independent `fa-verify` process returned **`verified`, with 37
passing checks**. The helper also compared **32 nonzero net cells and 32
nonzero gross cells** with the pinned original-source controls. All three proof
files remained byte-identical before verification, after verification and at
the final acceptance check. These gzip files expand to those exact accepted
bytes; their preparation also checked decompression byte-for-byte.

The bundle verifies the selected department report. The manifest also records
the complete agency replay, its recovery history, exact source and binary
identities, and the public files' hashes: [manifest.json](manifest.json).
The three compressed proof files total **29,470 bytes**.

## Verify offline

Run from the repository root with its pinned Rust toolchain. Only `fa-verify`
is needed. The following command creates a fresh directory, checks the
compressed and decompressed identities, and verifies the exact expected
certificate against the fixture's public key, signed checkpoint and receipt.

```bash
set -eu
cargo +nightly-2026-08-31 build --locked -Z bindeps -Z git=shallow-deps -p fa-verify
fa_example=examples/public_ledger/museum_recovered_source_bound
fa_example_out="$(mktemp -d)"
python3 - "$fa_example" "$fa_example_out" <<'PY'
import gzip
import hashlib
import json
import pathlib
import sys

source, target = map(pathlib.Path, sys.argv[1:])
manifest = json.loads((source / "manifest.json").read_text())
expected_names = {"report.fab", "checkpoint.bin", "report.receipt"}
assert {item["name"] for item in manifest["files"]} == expected_names
assert len(manifest["files"]) == len(expected_names)
for item in manifest["files"]:
    packed = (source / item["gzip_name"]).read_bytes()
    assert len(packed) == item["gzip_bytes"]
    assert hashlib.sha256(packed).hexdigest() == item["gzip_sha256"]
    raw = gzip.decompress(packed)
    assert len(raw) == item["bytes"]
    assert hashlib.sha256(raw).hexdigest() == item["sha256"]
    with (target / item["name"]).open("xb") as handle:
        handle.write(raw)
PY
target/debug/fa-verify report "$fa_example_out/report.fab" \
  --key 004225a884f0386b7b9b65ac897417a924d5be5dceaa97530612e5aa1c9a2a30 \
  --checkpoint "$fa_example_out/checkpoint.bin" \
  --receipt "$fa_example_out/report.receipt" \
  --expect 5a87b96013a6766ea92709bfeff1efa985cd12e5a43e96820ab7fc6484820b06 \
  --json
```

The recorded execution used the producer and verifier built from
`f3f1d66b25f9b01535efa9de74e38cb600b08a59`, the canonical replay helper from
`afe795be1903672e9e82bd89d2d7a3e9f76b6b3f`, and the portable helper from
`46e952fd6e938fa5dbe05a7b365fcb3cfce9e187`.
Exact executable and helper hashes are in the manifest. The command above is
a reproduction recipe; the recorded acceptance does not establish execution
of later Rust changes or a whole-tree test pass. The original hosted artifact
build's separate failed regression remains disclosed in the manifest.

## Recovery history, including the failures

1. The controlled first attempt stopped after native package preparation and
   before source binding. It returned the expected driver exit 1. The actual
   package was Open, with zero staged chunks and no binding, while the original
   recovery pins already required binding.
2. An initial resume was incomplete. Its wrapper recorded exit 120 and a
   missing-file error. The retained transcript contains 125 complete records
   followed by a 312-byte truncated record; that failed attempt remains part
   of the evidence.
3. The subsequent native continuation completed on the same original book:
   **exit 0, 42 checks, all five source bindings complete**, with 121 bound
   monetary rows and all 15 Entries. Its report counted 221 calls. The final
   attempt retained 204 complete command records; the other 17 are read-only
   preflight calls made while attempt logging was disabled. That distinction
   comes from the frozen driver and counter difference, without invented
   receipts for those reads.
4. After that native success, the continuation wrapper failed while parsing
   the prior attempt's truncated tail. Its `FAIL` status is retained separately
   from the successful native report.
5. A separate follow-up independently verified this portable report on the
   same recovered book. Its four native commands exited 0, its proof bytes and
   input pins remained unchanged, and its outer execution returned `PASS`.

The native recovery used the original source/package identities and approval
history. The successful continuation first persisted its preactivation fact
at sequence **129**, before finalization; the earlier incomplete attempt had
not yet written that fact. The public proof's later retained report uses
sequence **147**. Exact record hashes and timing scopes are preserved in the
manifest.

## Source and trust scope

The data is attributed to the **State of Oklahoma, Office of Management and
Enterprise Services** ([catalog](https://catalog.data.gov/dataset/general-ledger),
[published CSV](https://data.ok.gov/dataset/dd1ecf41-4abc-4886-ab0f-b84d7662d8d4/resource/0c2a7e42-610e-4f1d-826f-f6b267fba68a/download/ledger_fy24_qtr4.csv),
[catalogued CC BY license](http://www.opendefinition.org/licenses/cc-by)). The
complete agency selection is retained in the repository's
[source fixture](../../../crates/fa-oracles/fixtures/public_ledger/omes-fy2024-q4-20400.csv).

The original records are monthly chartfield aggregates. Dates are declared
period ends, and this activity-only book has no agency opening balances.
The four zero-valued source records remain in the retained CSV and coverage
controls. The five native source witnesses bind the normalized monetary-row
packages and their ordered proposals. These scope limits remain explicit;
the result is not an audited financial statement or recovered transaction-level
journal history.

The verification command explicitly trusts the original fixture book's public
key. It authenticates the retained report against that key, checkpoint,
receipt and expected certificate, without asserting that OMES signed it or
that the local test principals were independent human reviewers.

This example contains exactly the public report bundle, signed checkpoint and
detached receipt, plus this README and the manifest. It includes no native
book or private signing key. See the
[portable proof workflow](../../../docs/public_ledger_portable_proof.md)
for the complete import, recovery and proof procedure.
