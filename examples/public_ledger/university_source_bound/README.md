# Verify a real public-ledger report without its book

These three compressed public files reproduce a successful independent
verification of an Oklahoma OMES university activity report. The source-bound
book imported all 1,055 published FY2024 Q4 rows for agency 66000
(`S. E. OKLA. ST. UNIV.`), producing 1,051 monetary legs, 27 Entries and nine
migration runs. This retained report selects **FY2024-P12, department 1000001**
at native sequence **270**.

The bundle contains 12 native inputs, including `MigrationRunFragment`,
`MigrationSource`, `MigrationSourceFragment` and `EntryFragment`, with nine
source witnesses. The source-bound replay and portable export both passed;
fresh decompression of these exact gzip files also returned `verified` with
**91 passing checks** on 2026-11-03. Sizes, hashes, source provenance, exact
engine/helper commits and the measured verification are in
[manifest.json](manifest.json).

## Reproduce the independent verification

Run from the repository root with its pinned Rust toolchain. Only `fa-verify`
is needed; no book or producer process is needed. The command creates a fresh
directory and checks both compressed and decompressed identities before use.

```bash
set -eu
cargo +nightly-2026-08-31 build --locked -Z bindeps -Z git=shallow-deps -p fa-verify
fa_example=examples/public_ledger/university_source_bound
fa_example_out="$(mktemp -d)"
python3 - "$fa_example" "$fa_example_out" <<'PY'
import gzip
import hashlib
import json
import pathlib
import sys

source, target = map(pathlib.Path, sys.argv[1:])
manifest = json.loads((source / "manifest.json").read_text())
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
  --key c1b4180137fe89d5539e0eb40dd620ffb38a35b6c6bbfa0af2e924d17823c13c \
  --checkpoint "$fa_example_out/checkpoint.bin" \
  --receipt "$fa_example_out/report.receipt" \
  --expect 538f44d7cf22fe3f0b39ffd88db708ec22de4036c40f044abfe90f5e56567044 \
  --json
```

The recorded execution used the engine and verifier built from
`f3f1d66b25f9b01535efa9de74e38cb600b08a59`, with the portable helper from
`a0c79c57cfc07f48635584fa1b97a7f4e1379c40`. Their exact binary hashes are in the
manifest. That hosted build's separate object-storage regression failed; the
manifest preserves the failed job conclusion separately from these successful
real-data executions. This example makes no runtime claim about later FWC or
CAMT changes.

## Source and trust scope

The data is attributed to the **State of Oklahoma, Office of Management and
Enterprise Services** ([catalog](https://catalog.data.gov/dataset/general-ledger),
[published CSV](https://data.ok.gov/dataset/dd1ecf41-4abc-4886-ab0f-b84d7662d8d4/resource/0c2a7e42-610e-4f1d-826f-f6b267fba68a/download/ledger_fy24_qtr4.csv),
[catalogued CC BY license](http://www.opendefinition.org/licenses/cc-by)). Its
rows are monthly chartfield aggregates. The imported book contains quarter
activity without opening balances; this is not original transaction-level
history or an audited financial statement.

The command explicitly trusts the public key of a freshly created **test
book**. Verification authenticates the retained report against that key,
checkpoint, receipt and expected certificate. It does not authenticate OMES
as the signer or establish independent human review. The nine source witnesses
bind the admitted canonical migration packages; the original published CSV
and the normalization provenance are identified separately.

The package contains only the report bundle, public signed checkpoint and
detached receipt, plus documentation and a manifest. There is no book or
private signing key. See [the portable proof workflow](../../../docs/public_ledger_portable_proof.md)
to reproduce the complete import and export.
