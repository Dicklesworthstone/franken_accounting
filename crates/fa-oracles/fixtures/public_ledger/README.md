# Oklahoma OMES published general-ledger activity

Source: State of Oklahoma, Office of Management and Enterprise Services (OMES),
General Ledger, FY2024 Q4. Catalog: https://catalog.data.gov/dataset/general-ledger

Original distribution:
https://data.ok.gov/dataset/dd1ecf41-4abc-4886-ab0f-b84d7662d8d4/resource/0c2a7e42-610e-4f1d-826f-f6b267fba68a/download/ledger_fy24_qtr4.csv

The catalog declares the dataset Creative Commons Attribution (CC BY):
http://www.opendefinition.org/licenses/cc-by

The CSV fixtures preserve the original header and original bytes of every row
for business units 20400, 31500, and 66000, including zero amounts, Windows-1252
text, and CRLF line endings. This is a selection from the distribution; rows are
not fabricated, rounded, balanced with new entries, or reduced to net amounts.
Each adjacent JSON manifest records the full distribution's pinned SHA-256,
the selection's SHA-256, original logical data-record ordinals, and exact controls.

These records are monthly posted activity aggregated by published ChartFields.
They are not original transaction-level journal entries, audited trial balances,
or opening balances. The fixture amounts and source dimensions are real; generated
journal IDs and month-end effective dates belong to the documented replay model.

| Business unit | Selection | Source rows |
| --- | --- | ---: |
| 20400 | J. M. Davis museum | 125 |
| 31500 | Firefighters Pension & Retirement System | 137 |
| 66000 | Southeastern Oklahoma State University | 1,055 |

The full distribution contains 373,357 rows and is not vendored. Reacquire it with
the checksum-pinned helper. Its complete profile, including unbalanced groups and
subcent amounts, is in
[evidence/public_ledger/omes-fy2024-q4-profile.json](../../../../evidence/public_ledger/omes-fy2024-q4-profile.json).

See [the workflow and limitations](../../../../docs/public_ledger.md) for source
attribution, acquisition, normalization, native replay, and the validation status.
