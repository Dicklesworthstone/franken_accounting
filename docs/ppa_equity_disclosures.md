# Prior-period-adjustment equity comparisons

A posted `PriorPeriodAdjustment` case can now carry a supplemental equity
comparison in its disclosure. The comparison isolates the case's actual effect
in a current posting period and retains the existing independently verifiable
equity comparison certificate.

## Inspect the actual posting impact

For a case that corrects March by posting an adjustment in April:

```sh
fa case diff 7 --equity --period FY2026-P04 --unit USD \
  --label ppa-7-april --json
```

The period must be one of the actual posting periods found in the case's
immutable Post members. Both recorded-time frontiers are fixed: immediately
before the atomic Post, and at that Post. Later postings, certificate retention,
issuances and period transitions cannot move either endpoint.

The `case_equity_diff` event reports all fifteen exact before/after/delta rows
per selected native unit, both sets of classified movement citations, and the
canonical verification request. Its basis is `before-post-impact`; this is a
comparison of the case's posting impact, without an originally-issued-equity
claim. Amounts remain in their native units.

Select every monetary unit used by that period's posted adjustment members.
Owner-account roles are explicit: repeat `--issuance ACCOUNT` and
`--distribution ACCOUNT`, or omit them to select empty role sets. The account
roles must be valid for the historical chart and cannot overlap. `--branch` and
`--as-known-at` cannot replace the fixed trunk Post coordinates.

This command needs whole-book Read authority. It does not publish journal
records or retain a certificate. MCP exposes this pure comparison through
`fa.case/read` with `--equity` and the same selection flags.

## Certify and retain the independent question

```sh
fa case diff 7 --equity --period FY2026-P04 --unit USD \
  --label ppa-7-april --certify \
  --request-out ppa-7-april.request --json
```

Certification also requires Produce authority. It retains both original equity
sources inside the existing equity comparison artifact and emits a
`report_certificate` event after `case_equity_diff`. The comparison event's
outer `certificate` field identifies the retained artifact.

`--request-out` writes a new file and refuses to replace an existing one. It is
also available on the pure comparison, so the question can be saved before
certification. `verification_request_hex` contains the same canonical bytes.
Keep that question separately from the delivered certificate. Its full units, label,
dates, owner roles and recorded frontiers are the recipient's expectation;
deriving those choices from an untrusted certificate would not independently
select the question.

The artifact uses the existing replay, status and bundle interfaces with a
complete `equity-roll-forward-diff` expectation. The saved binary request also
works with the standalone verifier's `--equity-diff-request` option. Portable
verification still requires the expected outer certificate digest and trusted
checkpoint and registry evidence.

## Attach the comparison to the disclosure

First certify all mandatory comparisons with `case diff 7 --statements
--certify`. Keep every returned statement comparison, including the required
current posting impact and opening comparisons. Then supply the supplemental
equity artifact and its separately selected request alongside that set:

```text
fa case disclose CASE --document DISCLOSURE_OID \
  --certificate REQUIRED_STATEMENT_DIGEST ... \
  --equity-certificate EQUITY_DIFF_DIGEST \
  --equity-request ppa-7-april.request --json
```

Repeat the two equity options in matching order for distinct actual posting
periods. Each request file contains canonical binary bytes or their full hex;
one request may instead read standard input using `-`. At most one equity
comparison per posting period is accepted.

Disclosure checks current Restate, whole-book Read and CaseControl authority
before reading request files. Input and output paths use the same launch-bound
`--files` and daemon `--files-root` checks as other file arguments. Native
publication repeats its authority checks and fully replays each retained equity
comparison against the independently supplied question.

All required statement comparisons remain mandatory. A missing, duplicated,
wrong-period, wrong-frontier, altered-role or otherwise mismatched equity
attachment is refused. Once a disclosure is recorded, an exact retry must keep
the complete original comparison digest set; it cannot add, remove or substitute
supplemental evidence.

The embedded API exposes the same workflow through
`CaseEquityComparisonSelection`, `case_equity_diff_request`, `case_equity_diff`
and `disclose_case_with_equity`. Existing `disclose_case` callers continue to
supply only the mandatory statement comparisons.
